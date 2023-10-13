use crate::acme::{Account, ACME_TLS_ALPN_NAME};
use crate::rework::certificate::CertificateHandle;
use crate::{AcmeAcceptor, CertParseError, CertificateShouldUpdate, MultiCertCache, OrderError, ResolverError};
use async_io::Timer;
use async_notify::Notify;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::select;
use multi_key_map::MultiKeyMap;
use pin_project::pin_project;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ClientConfig;
use std::borrow::Borrow;

use log::error;
use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use stream_throttle::{ThrottlePool, ThrottleRate};
use vec_collections::{AbstractVecSet, VecSet2};

#[derive(Default)]
pub struct InnerResolver {
    map: MultiKeyMap<String, Arc<CertificateHandle>>,
    keys: VecSet2<String>,
}

pub struct StreamlinedResolver<C> {
    inner: Mutex<InnerResolver>,
    notifier: Arc<Notify>,
    updater_handles: Arc<()>,
    cache: C,
}

#[pin_project]
pub struct Updater<F> {
    #[pin]
    future: F,
    handle: Handle,
}

impl<F: Future> Future for Updater<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().future.poll(cx)
    }
}

struct Handle(Arc<()>);
impl Drop for Handle {
    fn drop(&mut self) {
        if Arc::strong_count(&self.0) <= 2 {
            log::warn!("rustls-acme resolver no longer has updater")
        }
    }
}

impl<C> StreamlinedResolver<C> {
    pub async fn new_with_updater(
        account: impl Borrow<Account>,
        client_config: impl Borrow<Arc<ClientConfig>>,
        cache: C,
    ) -> Result<(Arc<Self>, Updater<impl Future + Sized>), ResolverError<C::EC>>
    where
        C: MultiCertCache,
    {
        let certs = cache.load_all_certs().await.map_err(ResolverError::Cache)?;
        let this = Arc::new(Self {
            inner: Mutex::new(Default::default()),
            notifier: Arc::new(Default::default()),
            updater_handles: Arc::new(()),
            cache,
        });
        for cert in certs {
            this.create_pem_handle(cert.pem, cert.automatic)?;
        }
        let updater = this.clone().updater(account, client_config);
        Ok((this, updater))
    }

    pub(crate) fn updater(self: Arc<Self>, account: impl Borrow<Account>, client_config: impl Borrow<Arc<ClientConfig>>) -> Updater<impl Future>
    where
        C: MultiCertCache,
    {
        debug_assert_eq!(
            Arc::strong_count(&self.updater_handles),
            1,
            "cannot create multiple updaters for resolver"
        );
        Updater {
            handle: Handle(self.updater_handles.clone()),
            future: async move {
                let pool = ThrottlePool::new(ThrottleRate::new(300, core::time::Duration::from_secs(3600 * 3)));
                let errors = ThrottlePool::new(ThrottleRate::new(1, core::time::Duration::from_secs(3600 / 4)));
                loop {
                    let time = match self.renew(account.borrow(), client_config.borrow(), Some(&pool)).await {
                        Ok(time) => time,
                        Err(err) => {
                            log::error!("An error occurred during certificate renewal: {:?}", err);
                            errors.queue().await;
                            continue;
                        }
                    };
                    let notified = self.notifier.notified();
                    if let Some(time) = time {
                        select(pin!(notified), pin!(Timer::after((time - Utc::now()).to_std().unwrap_or_default()))).await;
                    } else {
                        notified.await;
                    }
                }
            },
        }
    }

    pub fn get(&self, domain: &str) -> Option<Arc<CertificateHandle>> {
        self.inner.lock().unwrap().map.get(domain).cloned()
    }

    pub fn create_domain_handle<S: Into<String>>(
        &self,
        domains: impl IntoIterator<Item = S>,
        automatic: bool,
    ) -> Result<Arc<CertificateHandle>, CertParseError> {
        self.create_handle(CertificateHandle::from_domains(domains, automatic))
    }
    pub async fn get_or_create_domain_handle<S: Into<String>>(
        &self,
        domains: impl Borrow<[String]> + IntoIterator<Item = S>,
        automatic: bool,
    ) -> Result<Arc<CertificateHandle>, ResolverError<C::EC>>
    where
        C: MultiCertCache,
    {
        Ok(
            if let Some(existing) = self.cache.load_cert(domains.borrow()).await.map_err(ResolverError::Cache)? {
                self.create_pem_handle(existing.pem, existing.automatic)?
            } else {
                self.create_handle(CertificateHandle::from_domains(domains, automatic))?
            },
        )
    }

    pub fn create_pem_handle(&self, pem: impl Into<Bytes>, automatic: bool) -> Result<Arc<CertificateHandle>, CertParseError> {
        self.create_handle(CertificateHandle::from_pem(pem, automatic)?)
    }
    fn create_handle(&self, handle: CertificateHandle) -> Result<Arc<CertificateHandle>, CertParseError> {
        let handle = Arc::new(handle);
        {
            let domains = handle.domains();
            let mut lock = self.inner.lock().unwrap();
            if !lock.keys.is_disjoint(domains) {
                return Err(CertParseError::InvalidDns);
            }
            lock.keys.extend(domains.iter().cloned());
            lock.map.insert_many(domains.iter().cloned().collect(), handle.clone());
        }
        self.notifier.notify();
        Ok(handle)
    }

    pub fn get_all_handles(&self) -> Vec<Arc<CertificateHandle>> {
        self.inner.lock().unwrap().map.values().cloned().collect()
    }

    async fn renew(
        &self,
        account: &Account,
        client_config: &Arc<ClientConfig>,
        limit: Option<&ThrottlePool>,
    ) -> Result<Option<DateTime<Utc>>, OrderError>
    where
        C: MultiCertCache,
    {
        let mut renew_time: Option<DateTime<Utc>> = None;
        for handle in self.get_all_handles() {
            let date = match handle.get_should_update() {
                CertificateShouldUpdate::Renew => {
                    if let Some(limit) = limit {
                        limit.queue().await
                    }
                    let info = handle.order(account, client_config).await?;
                    if let Err(err) = self.cache.store_cert(&info).await {
                        error!("Unable to store generated certificate in cache: {:?}", err);
                    }
                    info.validity[1]
                }
                CertificateShouldUpdate::RenewLater(date) => date,
                _ => continue,
            };
            renew_time = Some(renew_time.take().map_or_else(|| date, |other| other.min(date)));
        }
        Ok(renew_time)
    }

    pub fn acceptor(self: &Arc<Self>) -> AcmeAcceptor
    where
        C: Send + Sync + 'static,
    {
        AcmeAcceptor::new(self.clone())
    }

    #[cfg(feature = "axum")]
    pub fn axum_acceptor(&self, rustls_config: Arc<rustls::ServerConfig>) -> crate::axum::AxumAcceptor {
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
}

impl<C: Send + Sync> ResolvesServerCert for StreamlinedResolver<C> {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name().map(|it| {
            log::warn!("client did not supply SNI");
            it
        })?;
        let inner = self.get(domain).map(|it| {
            log::warn!("domain {domain} has no associated tls certificate");
            it
        })?;
        if client_hello.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME]) {
            inner.get_challenge_certificate(domain)
        } else {
            inner.get_certificate()
        }
    }
}
