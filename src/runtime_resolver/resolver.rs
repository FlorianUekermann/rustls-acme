use crate::acme::Account;
use crate::runtime_resolver::certificate::CertificateHandle;
use crate::{is_tls_alpn_challenge, AcmeAcceptor, CertParseError, CertificateShouldUpdate, MultiCertCache, OrderError, ResolverError};
use async_io::Timer;
use async_notify::Notify;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::select;
use futures_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use futures_rustls::rustls::sign::CertifiedKey;
use futures_rustls::rustls::ClientConfig;
use log::error;
use multi_key_map::MultiKeyMap;
use pin_project::pin_project;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt::Debug;
use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use stream_throttle::{ThrottlePool, ThrottleRate};

#[derive(Debug, Default)]
pub struct InnerRuntimeResolver {
    map: MultiKeyMap<String, Arc<CertificateHandle>>,
    keys: HashSet<String>,
}

/// An ACME resolver for dynamic multi-certificate resolution and auto update.
///
/// It works in tandem with the `Updater` future which must be spawned in the background
/// to handle certificate renewals and ACME challenges.
#[derive(Debug)]
pub struct RuntimeResolver<C> {
    inner: Mutex<InnerRuntimeResolver>,
    directory_url: String,
    notifier: Arc<Notify>,
    updater_handles: Arc<()>,
    cache: C,
}

/// A future responsible for managing certificate lifecycle events.
///
/// This struct is created via `RuntimeResolver::new_with_updater` and represents
/// the background task that periodically checks for expired certificates and
/// processes ACME challenges.
///
/// If this future is dropped, the `RuntimeResolver` will log a warning as it
/// will no longer be able to renew certificates.
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

impl<C> RuntimeResolver<C> {

    /// Creates a new resolver and its associated background updater.
    ///
    /// This function loads any existing certificates from the provided `cache`.
    /// It returns a tuple containing:
    /// 1. The `Arc<RuntimeResolver>` to be used in your TLS acceptor.
    /// 2. An `Updater` future that **must** be spawned or awaited to keep certificates valid.
    ///
    /// # Arguments
    ///
    /// * `account` - The ACME account to use for orders.
    /// * `client_config` - TLS client config used for upstream ACME requests.
    /// * `directory_url` - The ACME directory URL (e.g., Let's Encrypt).
    /// * `cache` - A storage backend implementing `MultiCertCache`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rustls_acme::{RuntimeResolver, acme::Account};
    /// # use rustls_acme::caches::DirCache; // Assuming a cache impl exists
    /// # async fn example() {
    /// // 1. Load your account (usually from storage/cache)
    /// // In a real app, this might come from serde_json::from_str(...)
    /// let account: Account = panic!("Load account from storage");
    ///
    /// // 2. Configure the upstream ACME client
    /// let client_config = Arc::new(futures_rustls::rustls::ClientConfig::builder()
    ///     .with_root_certificates(futures_rustls::rustls::RootCertStore::empty())
    ///     .with_no_client_auth());
    ///
    /// let cache = DirCache::new("./cached_certs");
    ///
    /// let (resolver, updater) = RuntimeResolver::new_with_updater(
    ///     account,
    ///     client_config,
    ///     "[https://acme-staging-v02.api.letsencrypt.org/directory](https://acme-staging-v02.api.letsencrypt.org/directory)".to_string(),
    ///     cache
    /// ).await.expect("Failed to create resolver");
    ///
    /// // 3. Spawn the updater in the background
    /// tokio::spawn(updater);
    /// # }
    /// ```
    pub async fn new_with_updater(
        account: impl Borrow<Account> + Send + Sync,
        client_config: impl Borrow<Arc<ClientConfig>> + Send + Sync,
        directory_url: String,
        cache: C,
    ) -> Result<(Arc<Self>, Updater<impl Future<Output = ()> + Send>), ResolverError<C::EC>>
    where
        C: MultiCertCache,
    {
        let certs = cache.load_all_certs().await.map_err(ResolverError::Cache)?;
        let this = Arc::new(Self {
            inner: Mutex::new(Default::default()),
            notifier: Arc::new(Default::default()),
            updater_handles: Arc::new(()),
            directory_url,
            cache,
        });
        for cert in certs {
            this.create_pem_handle(cert.pem, cert.automatic)?;
        }
        let updater = this.clone().updater(account, client_config);
        Ok((this, updater))
    }

    pub(crate) fn updater(
        self: Arc<Self>,
        account: impl Borrow<Account> + Send + Sync,
        client_config: impl Borrow<Arc<ClientConfig>> + Send + Sync,
    ) -> Updater<impl Future<Output = ()> + Send>
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

    /// Retrieves a certificate handle for a specific domain, if it exists in memory.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustls_acme::RuntimeResolver;
    /// # fn run<C>(resolver: &RuntimeResolver<C>) {
    /// if let Some(handle) = resolver.get("example.com") {
    ///     println!("Found handle for example.com");
    /// }
    /// # }
    /// ```
    pub fn get(&self, domain: &str) -> Option<Arc<CertificateHandle>> {
        self.inner.lock().unwrap().map.get(domain).cloned()
    }

    /// Creates a new certificate handle for the specified domains in memory.
    ///
    /// It can be called anytime and anywhere to add certificates dynamically during runtime.
    ///
    /// If `automatic` is true, the handle will be eligible for ACME renewal.
    /// This does not check the cache; it forces the creation of a new handle.
    ///
    /// # Recommendations
    ///
    /// Prefer using [Self::get_or_create_domain_handle] as it checks the cache
    /// before creating a new handle, preventing unnecessary re-issuance.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustls_acme::RuntimeResolver;
    /// # fn run<C>(resolver: &RuntimeResolver<C>) {
    /// // Start managing a certificate for these domains
    /// resolver.create_domain_handle(vec!["example.com", "www.example.com"], true);
    /// # }
    /// ```
    pub fn create_domain_handle<S: Into<String>>(&self, domains: impl IntoIterator<Item = S>, automatic: bool) -> Arc<CertificateHandle> {
        self.create_handle(CertificateHandle::from_domains(domains, automatic))
    }

    /// Retrieves an existing handle from the cache or creates a new one if missing.
    ///
    /// It can be called anytime and anywhere to add certificates dynamically during runtime.
    ///
    /// This is the preferred method for requesting certificates dynamically. It ensures
    /// that if a certificate was previously obtained and cached, it is loaded instead
    /// of triggering a new order.
    ///
    /// It can be called anytime and anywhere to add certificates dynamically during runtime.
    ///
    /// # Arguments
    ///
    /// * `domains` - List of domains (SANs) for the certificate.
    /// * `automatic` - Whether the resolver should auto-renew this certificate.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rustls_acme::{RuntimeResolver, MultiCertCache};
    /// # async fn run<C: MultiCertCache>(resolver: &RuntimeResolver<C>) {
    /// match resolver.get_or_create_domain_handle(vec!["example.com"], true).await {
    ///     Ok(handle) => println!("Handle obtained ready for TLS"),
    ///     Err(e) => eprintln!("Cache error: {:?}", e),
    /// }
    /// # }
    /// ```
    pub async fn get_or_create_domain_handle<S: Into<String>>(
        &self,
        domains: impl IntoIterator<Item = S>,
        automatic: bool,
    ) -> Result<Arc<CertificateHandle>, ResolverError<C::EC>>
    where
        C: MultiCertCache,
    {
        let mut domains: Vec<_> = domains.into_iter().map(Into::into).collect();
        domains.sort();
        domains.dedup();
        Ok(
            if let Some(existing) = self
                .cache
                .load_cert(domains.borrow(), &self.directory_url)
                .await
                .map_err(ResolverError::Cache)?
            {
                self.create_pem_handle(existing.pem, existing.automatic)?
            } else {
                self.create_handle(CertificateHandle::from_domains(domains, automatic))
            },
        )
    }

    /// Creates a certificate handle from raw PEM bytes.
    ///
    /// Useful for loading manual certificates (not managed by ACME) into the resolver.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rustls_acme::RuntimeResolver;
    /// # fn run<C>(resolver: &RuntimeResolver<C>) {
    /// let pem_bytes = b"-----BEGIN CERTIFICATE-----...";
    /// resolver.create_pem_handle(pem_bytes.as_slice(), false).expect("Invalid PEM");
    /// # }
    /// ```
    pub fn create_pem_handle(&self, pem: impl Into<Bytes>, automatic: bool) -> Result<Arc<CertificateHandle>, CertParseError> {
        Ok(self.create_handle(CertificateHandle::from_pem(pem, automatic)?))
    }

    /// Manually inserts a pre-configured `CertificateHandle` into the resolver.
    ///
    /// The resolver will index the handle by the domains it contains. If a handle
    /// already exists for a domain, the one with the longer validity period is kept.
    pub fn create_handle(&self, handle: CertificateHandle) -> Arc<CertificateHandle> {
        let handle = Arc::new(handle);
        let domains = handle.domains();
        let mut lock = self.inner.lock().unwrap();
        lock.keys.extend(domains.iter().cloned());
        let handle_exp = handle.get_validity().map(|it| it[1]);
        for domain in domains {
            if let Some(existing) = lock.map.get(domain) {
                if let (Some(this), existing) = (handle_exp, existing.get_validity().map(|it| it[1])) {
                    if existing.map(|existing| this > existing).unwrap_or(true) {
                        lock.map.insert(domain.clone(), handle.clone());
                    }
                }
            } else {
                lock.map.insert(domain.clone(), handle.clone());
            }
        }
        self.notifier.notify();
        handle
    }

    /// Returns a list of all certificate handles currently managed by the resolver.
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
                    if let Err(err) = self.cache.store_cert(&info, &self.directory_url).await {
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

    /// Creates a generic `AcmeAcceptor` using this resolver.
    ///
    /// The `AcmeAcceptor` wraps an incoming stream and performs the TLS handshake
    /// using certificates resolved by this `RuntimeResolver`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rustls_acme::RuntimeResolver;
    /// # use futures::StreamExt;
    /// # use tokio_util::compat::TokioAsyncReadCompatExt;
    /// # async fn run<C: std::fmt::Debug + Send + Sync + 'static>(resolver: std::sync::Arc<RuntimeResolver<C>>, tcp_listener: tokio::net::TcpListener) {
    /// let acceptor = resolver.acceptor();
    ///
    /// while let Ok((stream, _addr)) = tcp_listener.accept().await {
    ///     let acceptor = acceptor.clone();
    ///     tokio::spawn(async move {
    ///         let stream = stream.compat();
    ///         if let Ok(tls_stream) = acceptor.accept(stream).await {
    ///             // handle tls_stream
    ///         }
    ///     });
    /// }
    /// # }
    /// ```
    pub fn acceptor(self: &Arc<Self>) -> AcmeAcceptor
    where
        C: Debug + Send + Sync + 'static,
    {
        #[allow(deprecated)]
        AcmeAcceptor::new(self.clone())
    }

    /// Creates an `AxumAcceptor` for easy integration with `axum-server`.
    ///
    /// This method bridges the `RuntimeResolver` with the `axum-server` crate, allowing
    /// you to run an Axum application with automatic HTTPS.
    ///
    /// # Arguments
    ///
    /// * `rustls_config` - A `rustls::ServerConfig` configured with this resolver.
    ///   You typically create this via `with_cert_resolver(resolver.clone())`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rustls_acme::RuntimeResolver;
    /// # use rustls_acme::caches::DirCache;
    /// # use axum::{Router, routing::get};
    /// # use std::net::SocketAddr;
    /// # use std::path::PathBuf;
    ///
    /// async fn run(resolver: Arc<RuntimeResolver<DirCache<PathBuf>>>) {
    /// // 1. Create a Rustls ServerConfig that uses this resolver
    /// let rustls_config = rustls::ServerConfig::builder()
    ///     .with_no_client_auth()
    ///     .with_cert_resolver(resolver.clone());
    ///
    /// // 2. Create the AxumAcceptor
    /// let acceptor = resolver.axum_acceptor(Arc::new(rustls_config));
    ///
    /// // 3. Define your Axum app
    /// let app = Router::new().route("/", get(|| async { "Hello HTTPS!" }));
    ///
    /// // 4. Launch the server using axum-server
    /// let addr = SocketAddr::from(([0, 0, 0, 0], 443));
    /// axum_server::bind(addr)
    ///     .acceptor(acceptor)
    ///     .serve(app.into_make_service())
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    ///
    /// # Feature Requirement
    ///
    /// This method is only available when the `axum` feature is enabled in `rustls-acme`.
    #[cfg(feature = "axum")]
    pub fn axum_acceptor(self: &Arc<Self>, rustls_config: Arc<crate::futures_rustls::rustls::ServerConfig>) -> crate::axum::AxumAcceptor
    where
        C: Debug + Send + Sync + 'static,
    {
        #[allow(deprecated)]
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
}

impl<C: Debug + Send + Sync> ResolvesServerCert for RuntimeResolver<C> {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let Some(domain) = client_hello.server_name() else {
            log::warn!("client did not supply SNI");
            return None;
        };
        let Some(inner) = self.get(domain) else {
            log::warn!("domain {domain} has no associated tls certificate");
            return None;
        };
        if is_tls_alpn_challenge(&client_hello) {
            inner.get_challenge_certificate(domain)
        } else {
            inner.get_certificate()
        }
    }
}
