use crate::acceptor::AcmeAcceptor;
use crate::acme::{Account, AcmeError, Auth, AuthStatus, Directory, Identifier, Order, OrderStatus, ACME_TLS_ALPN_NAME};
use crate::{any_ecdsa_type, crypto_provider, AcmeConfig, Incoming, ResolvesServerCertAcme};
use async_io::Timer;
use chrono::{DateTime, TimeZone, Utc};
use core::fmt;
use futures::future::try_join_all;
use futures::prelude::*;
use futures::ready;
use futures_rustls::pki_types::{CertificateDer as RustlsCertificate, PrivateKeyDer, PrivatePkcs8KeyDer};
use futures_rustls::rustls::crypto::CryptoProvider;
use futures_rustls::rustls::sign::CertifiedKey;
use futures_rustls::rustls::ServerConfig;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use x509_parser::parse_x509_certificate;

#[allow(clippy::type_complexity)]
pub struct AcmeState<EC: Debug = Infallible, EA: Debug = EC> {
    config: Arc<AcmeConfig<EC, EA>>,
    resolver: Arc<ResolvesServerCertAcme>,
    account_key: Option<Vec<u8>>,

    early_action: Option<Pin<Box<dyn Future<Output = Event<EC, EA>> + Send>>>,
    load_cert: Option<Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, EC>> + Send>>>,
    load_account: Option<Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, EA>> + Send>>>,
    order: Option<Pin<Box<dyn Future<Output = Result<Vec<u8>, OrderError>> + Send>>>,
    backoff_cnt: usize,
    wait: Option<Timer>,
}

impl<EC: 'static + Debug, EA: 'static + Debug> fmt::Debug for AcmeState<EC, EA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeState").field("config", &self.config).finish_non_exhaustive()
    }
}

pub type Event<EC, EA> = Result<EventOk, EventError<EC, EA>>;

#[derive(Debug)]
pub enum EventOk {
    DeployedCachedCert,
    DeployedNewCert,
    CertCacheStore,
    AccountCacheStore,
}

#[derive(Error, Debug)]
pub enum EventError<EC: Debug, EA: Debug> {
    #[error("cert cache load: {0}")]
    CertCacheLoad(EC),
    #[error("account cache load: {0}")]
    AccountCacheLoad(EA),
    #[error("cert cache store: {0}")]
    CertCacheStore(EC),
    #[error("account cache store: {0}")]
    AccountCacheStore(EA),
    #[error("cached cert parse: {0}")]
    CachedCertParse(CertParseError),
    #[error("order: {0}")]
    Order(OrderError),
    #[error("new cert parse: {0}")]
    NewCertParse(CertParseError),
}

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
    #[error("order status stayed on processing too long")]
    ProcessingTimeout(Order),
}

#[derive(Error, Debug)]
pub enum CertParseError {
    #[error("X509 parsing error: {0}")]
    X509(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("expected 2 or more pem, got: {0}")]
    Pem(#[from] pem::PemError),
    #[error("expected 2 or more pem, got: {0}")]
    TooFewPem(usize),
    #[error("unsupported private key type")]
    InvalidPrivateKey,
}

impl<EC: 'static + Debug, EA: 'static + Debug> AcmeState<EC, EA> {
    pub fn incoming<TCP: AsyncRead + AsyncWrite + Unpin, ETCP, ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin>(
        self,
        tcp_incoming: ITCP,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        #[allow(deprecated)]
        let acceptor = self.acceptor();
        Incoming::new(tcp_incoming, self, acceptor, alpn_protocols)
    }
    #[deprecated(note = "please use high-level API via `AcmeState::incoming()` instead or refer to updated low-level API examples")]
    #[allow(deprecated)]
    pub fn acceptor(&self) -> AcmeAcceptor {
        AcmeAcceptor::new(self.resolver())
    }
    #[cfg(feature = "tokio")]
    pub fn tokio_incoming<
        TokioTCP: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        ETCP,
        TokioITCP: Stream<Item = Result<TokioTCP, ETCP>> + Unpin,
    >(
        self,
        tcp_incoming: TokioITCP,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> crate::tokio::TokioIncoming<
        tokio_util::compat::Compat<TokioTCP>,
        ETCP,
        crate::tokio::TokioIncomingTcpWrapper<TokioTCP, ETCP, TokioITCP>,
        EC,
        EA,
    > {
        let tcp_incoming = crate::tokio::TokioIncomingTcpWrapper::from(tcp_incoming);
        crate::tokio::TokioIncoming::from(self.incoming(tcp_incoming, alpn_protocols))
    }
    #[cfg(feature = "axum")]
    pub fn axum_acceptor(&self, rustls_config: Arc<ServerConfig>) -> crate::axum::AxumAcceptor {
        #[allow(deprecated)]
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
    pub fn resolver(&self) -> Arc<ResolvesServerCertAcme> {
        self.resolver.clone()
    }
    /// Creates a [rustls::ServerConfig] for tls-alpn-01 challenge connections. Use this if [crate::is_tls_alpn_challenge] returns `true`.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn challenge_rustls_config(&self) -> Arc<ServerConfig> {
        self.challenge_rustls_config_with_provider(crypto_provider().into())
    }
    /// Same as [AcmeState::challenge_rustls_config], with a specific [CryptoProvider].
    pub fn challenge_rustls_config_with_provider(&self, provider: Arc<CryptoProvider>) -> Arc<ServerConfig> {
        let mut rustls_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver());
        rustls_config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Arc::new(rustls_config)
    }
    /// Creates a default [rustls::ServerConfig] for accepting regular tls connections. Use this if [crate::is_tls_alpn_challenge] returns `false`.
    /// If you need a [rustls::ServerConfig], which uses the certificates acquired by this [AcmeState],
    /// you may build your own using the output of [AcmeState::resolver].
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn default_rustls_config(&self) -> Arc<ServerConfig> {
        self.default_rustls_config_with_provider(crypto_provider().into())
    }
    /// Same as [AcmeState::default_rustls_config], with a specific [CryptoProvider].
    pub fn default_rustls_config_with_provider(&self, provider: Arc<CryptoProvider>) -> Arc<ServerConfig> {
        let rustls_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver());
        Arc::new(rustls_config)
    }
    pub fn new(config: AcmeConfig<EC, EA>) -> Self {
        let config = Arc::new(config);
        Self {
            config: config.clone(),
            resolver: ResolvesServerCertAcme::new(),
            account_key: None,
            early_action: None,
            load_cert: Some(Box::pin({
                let config = config.clone();
                async move { config.cache.load_cert(&config.domains, &config.directory_url).await }
            })),
            load_account: Some(Box::pin({
                let config = config.clone();
                async move { config.cache.load_account(&config.contact, &config.directory_url).await }
            })),
            order: None,
            backoff_cnt: 0,
            wait: None,
        }
    }
    fn parse_cert(pem: &[u8]) -> Result<(CertifiedKey, [DateTime<Utc>; 2]), CertParseError> {
        let mut pems = pem::parse_many(pem)?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pems.remove(0).contents()))) {
            Ok(pk) => pk,
            Err(_) => return Err(CertParseError::InvalidPrivateKey),
        };
        let cert_chain: Vec<RustlsCertificate> = pems.into_iter().map(|p| RustlsCertificate::from(p.into_contents())).collect();
        let validity = match parse_x509_certificate(&cert_chain[0]) {
            Ok((_, cert)) => {
                let validity = cert.validity();
                [validity.not_before, validity.not_after].map(|t| Utc.timestamp_opt(t.timestamp(), 0).earliest().unwrap())
            }
            Err(err) => return Err(CertParseError::X509(err)),
        };
        let cert = CertifiedKey::new(cert_chain, pk);
        Ok((cert, validity))
    }

    #[allow(clippy::result_large_err)]
    fn process_cert(&mut self, pem: Vec<u8>, cached: bool) -> Event<EC, EA> {
        let (cert, validity) = match (Self::parse_cert(&pem), cached) {
            (Ok(r), _) => r,
            (Err(err), cached) => {
                return match cached {
                    true => Err(EventError::CachedCertParse(err)),
                    false => Err(EventError::NewCertParse(err)),
                }
            }
        };
        self.resolver.set_cert(Arc::new(cert));
        let wait_duration = (validity[1] - (validity[1] - validity[0]) / 3 - Utc::now())
            .max(chrono::Duration::zero())
            .to_std()
            .unwrap_or_default();
        self.wait = Some(Timer::after(wait_duration));
        if cached {
            return Ok(EventOk::DeployedCachedCert);
        }
        let config = self.config.clone();
        self.early_action = Some(Box::pin(async move {
            match config.cache.store_cert(&config.domains, &config.directory_url, &pem).await {
                Ok(()) => Ok(EventOk::CertCacheStore),
                Err(err) => Err(EventError::CertCacheStore(err)),
            }
        }));
        Event::Ok(EventOk::DeployedNewCert)
    }
    async fn order(config: Arc<AcmeConfig<EC, EA>>, resolver: Arc<ResolvesServerCertAcme>, key_pair: Vec<u8>) -> Result<Vec<u8>, OrderError> {
        let directory = Directory::discover(&config.client_config, &config.directory_url).await?;
        let account = Account::create_with_keypair(&config.client_config, directory, &config.contact, &key_pair).await?;

        let mut params = CertificateParams::new(config.domains.clone())?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let csr = params.serialize_request(&key_pair)?;

        let (order_url, mut order) = account.new_order(&config.client_config, config.domains.clone()).await?;
        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order.authorizations.iter().map(|url| Self::authorize(&config, &resolver, &account, url));
                    try_join_all(auth_futures).await?;
                    log::info!("completed all authorizations");
                    order = account.order(&config.client_config, &order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        log::info!("order processing");
                        Timer::after(Duration::from_secs(1u64 << i)).await;
                        order = account.order(&config.client_config, &order_url).await?;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(OrderError::ProcessingTimeout(order));
                    }
                }
                OrderStatus::Ready => {
                    log::info!("sending csr");
                    order = account.finalize(&config.client_config, order.finalize, csr.der()).await?
                }
                OrderStatus::Valid { certificate } => {
                    log::info!("download certificate");
                    let pem = [
                        &key_pair.serialize_pem(),
                        "\n",
                        &account.certificate(&config.client_config, certificate).await?,
                    ]
                    .concat();
                    return Ok(pem.into_bytes());
                }
                OrderStatus::Invalid => return Err(OrderError::BadOrder(order)),
            }
        }
    }
    async fn authorize(config: &AcmeConfig<EC, EA>, resolver: &ResolvesServerCertAcme, account: &Account, url: &String) -> Result<(), OrderError> {
        let auth = account.auth(&config.client_config, url).await?;
        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;
                log::info!("trigger challenge for {}", &domain);
                let (challenge, auth_key) = account.tls_alpn_01(&auth.challenges, domain.clone())?;
                resolver.set_auth_key(domain.clone(), Arc::new(auth_key));
                account.challenge(&config.client_config, &challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            Timer::after(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(&config.client_config, url).await?;
            match auth.status {
                AuthStatus::Pending => {
                    log::info!("authorization for {} still pending", &domain);
                    account.challenge(&config.client_config, &challenge_url).await?
                }
                AuthStatus::Valid => return Ok(()),
                _ => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(domain))
    }
    fn poll_next_infinite(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event<EC, EA>> {
        loop {
            // queued early action
            if let Some(early_action) = &mut self.early_action {
                let result = ready!(early_action.poll_unpin(cx));
                self.early_action.take();
                return Poll::Ready(result);
            }

            // sleep
            if let Some(timer) = &mut self.wait {
                ready!(timer.poll_unpin(cx));
                self.wait.take();
            }

            // load from cert cache
            if let Some(load_cert) = &mut self.load_cert {
                let result = ready!(load_cert.poll_unpin(cx));
                self.load_cert.take();
                match result {
                    Ok(Some(pem)) => {
                        return Poll::Ready(Self::process_cert(self.get_mut(), pem, true));
                    }
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::CertCacheLoad(err))),
                }
            }

            // load from account cache
            if let Some(load_account) = &mut self.load_account {
                let result = ready!(load_account.poll_unpin(cx));
                self.load_account.take();
                match result {
                    Ok(Some(key_pair)) => self.account_key = Some(key_pair),
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::AccountCacheLoad(err))),
                }
            }

            // execute order
            if let Some(order) = &mut self.order {
                let result = ready!(order.poll_unpin(cx));
                self.order.take();
                match result {
                    Ok(pem) => {
                        self.backoff_cnt = 0;
                        return Poll::Ready(Self::process_cert(self.get_mut(), pem, false));
                    }
                    Err(err) => {
                        // TODO: replace key on some errors or high backoff_cnt?
                        self.wait = Some(Timer::after(Duration::from_secs(1 << self.backoff_cnt)));
                        self.backoff_cnt = (self.backoff_cnt + 1).min(16);
                        return Poll::Ready(Err(EventError::Order(err)));
                    }
                }
            }

            // schedule order
            let account_key = match &self.account_key {
                None => {
                    let account_key = Account::generate_key_pair();
                    self.account_key = Some(account_key.clone());
                    let config = self.config.clone();
                    let account_key_clone = account_key.clone();
                    self.early_action = Some(Box::pin(async move {
                        match config
                            .cache
                            .store_account(&config.contact, &config.directory_url, &account_key_clone)
                            .await
                        {
                            Ok(()) => Ok(EventOk::AccountCacheStore),
                            Err(err) => Err(EventError::AccountCacheStore(err)),
                        }
                    }));
                    account_key
                }
                Some(account_key) => account_key.clone(),
            };
            let config = self.config.clone();
            let resolver = self.resolver.clone();
            self.order = Some(Box::pin(Self::order(config.clone(), resolver.clone(), account_key)));
        }
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> Stream for AcmeState<EC, EA> {
    type Item = Event<EC, EA>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(Some(ready!(self.poll_next_infinite(cx))))
    }
}
