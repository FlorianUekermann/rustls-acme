use crate::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use crate::caches::{BoxedErrCache, CompositeCache, NoCache};
use crate::UseChallenge::TlsAlpn01;
use crate::{crypto_provider, AccountCache, Cache, CertCache};
use crate::{AcmeState, Incoming};
use core::fmt;
use futures::{AsyncRead, AsyncWrite, Stream};
use futures_rustls::pki_types::TrustAnchor;
use futures_rustls::rustls::crypto::CryptoProvider;
use futures_rustls::rustls::{ClientConfig, RootCertStore};
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;

/// Configuration for an ACME resolver.
///
/// The type parameters represent the error types for the certificate cache and account cache.
pub struct AcmeConfig<EC: Debug, EA: Debug = EC> {
    pub(crate) client_config: Arc<ClientConfig>,
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache: Box<dyn Cache<EC = EC, EA = EA>>,
    pub(crate) challenge_type: UseChallenge,
}

pub enum UseChallenge {
    Http01,
    TlsAlpn01,
}

impl AcmeConfig<Infallible, Infallible> {
    /// Creates a new [AcmeConfig] instance with Web PKI root certificates.
    ///
    /// The new [AcmeConfig] instance will initially have no cache, and its type parameters for
    /// error types will be `Infallible` since the cache cannot return an error. The methods to set
    /// a cache will change the error types to match those returned by the supplied cache.
    ///
    /// ```rust
    /// # use rustls_acme::AcmeConfig;
    /// use rustls_acme::caches::DirCache;
    /// let config = AcmeConfig::new(["example.com"]).cache(DirCache::new("./rustls_acme_cache"));
    /// ```
    ///
    /// Due to limited support for type parameter inference in Rust (see
    /// [RFC213](https://github.com/rust-lang/rfcs/blob/master/text/0213-defaulted-type-params.md)),
    /// [AcmeConfig::new] is not (yet) generic over the [AcmeConfig]'s type parameters.
    /// An uncached instance of [AcmeConfig] with particular type parameters can be created using
    /// [NoCache].
    ///
    /// ```rust
    /// # use rustls_acme::AcmeConfig;
    /// use rustls_acme::caches::NoCache;
    /// # type EC = std::io::Error;
    /// # type EA = EC;
    /// let config: AcmeConfig<EC, EA> = AcmeConfig::new(["example.com"]).cache(NoCache::default());
    /// ```
    #[cfg(all(feature = "webpki-roots", any(feature = "ring", feature = "aws-lc-rs")))]
    pub fn new(domains: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self::new_with_provider(domains, crypto_provider().into())
    }

    /// Same as [AcmeConfig::new], with a specific [CryptoProvider].
    #[cfg(feature = "webpki-roots")]
    pub fn new_with_provider(domains: impl IntoIterator<Item = impl AsRef<str>>, provider: Arc<CryptoProvider>) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            let ta = ta.to_owned();
            TrustAnchor {
                subject: ta.subject,
                subject_public_key_info: ta.subject_public_key_info,
                name_constraints: ta.name_constraints,
            }
        }));
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        AcmeConfig {
            client_config,
            directory_url: LETS_ENCRYPT_STAGING_DIRECTORY.into(),
            domains: domains.into_iter().map(|s| s.as_ref().into()).collect(),
            contact: vec![],
            cache: Box::new(NoCache::default()),
            challenge_type: TlsAlpn01,
        }
    }

    /// Creates a new [AcmeConfig] instance with the provided TLS configuration client.
    ///
    /// The new [AcmeConfig] instance will initially have no cache, and its type parameters for
    /// error types will be `Infallible` since the cache cannot return an error. The methods to set
    /// a cache will change the error types to match those returned by the supplied cache.
    ///
    /// ```rust
    /// # use rustls_acme::AcmeConfig;
    /// use std::sync::Arc;
    /// use futures_rustls::rustls::ClientConfig;
    /// use rustls_acme::caches::DirCache;
    /// # use futures_rustls::rustls::{crypto::CryptoProvider, RootCertStore};
    /// # fn call(provider: Arc<CryptoProvider>, root_store: RootCertStore) {
    /// let client_config = Arc::new(
    ///     ClientConfig::builder_with_provider(provider)
    ///         .with_safe_default_protocol_versions()
    ///         .unwrap()
    ///         .with_root_certificates(root_store)
    ///         .with_no_client_auth(),
    /// );
    /// let config = AcmeConfig::new_with_client_config(["example.com"], client_config)
    ///     .cache(DirCache::new("./rustls_acme_cache"));
    /// # }
    /// ```
    ///
    /// Due to limited support for type parameter inference in Rust (see
    /// [RFC213](https://github.com/rust-lang/rfcs/blob/master/text/0213-defaulted-type-params.md)),
    /// [AcmeConfig::new_with_client_config] is not (yet) generic over the [AcmeConfig]'s type parameters.
    /// An uncached instance of [AcmeConfig] with particular type parameters can be created using
    /// [NoCache].
    ///
    /// ```rust
    /// # use rustls_acme::AcmeConfig;
    /// # use std::sync::Arc;
    /// # use futures_rustls::rustls::ClientConfig;
    /// use rustls_acme::caches::NoCache;
    /// # type EC = std::io::Error;
    /// # type EA = EC;
    /// # fn call(client_config: Arc<ClientConfig>) {
    /// let config: AcmeConfig<EC, EA> = AcmeConfig::new_with_client_config(["example.com"], client_config)
    ///     .cache(NoCache::default());
    /// # }
    /// ```
    pub fn new_with_client_config(domains: impl IntoIterator<Item = impl AsRef<str>>, client_config: Arc<ClientConfig>) -> Self {
        AcmeConfig {
            client_config,
            directory_url: LETS_ENCRYPT_STAGING_DIRECTORY.into(),
            domains: domains.into_iter().map(|s| s.as_ref().into()).collect(),
            contact: vec![],
            cache: Box::new(NoCache::default()),
            challenge_type: TlsAlpn01,
        }
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> AcmeConfig<EC, EA> {
    /// Set custom `rustls::ClientConfig` for ACME API calls.
    pub fn client_tls_config(mut self, client_config: Arc<ClientConfig>) -> Self {
        self.client_config = client_config;
        self
    }
    pub fn directory(mut self, directory_url: impl AsRef<str>) -> Self {
        self.directory_url = directory_url.as_ref().into();
        self
    }
    pub fn directory_lets_encrypt(mut self, production: bool) -> Self {
        self.directory_url = match production {
            true => LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            false => LETS_ENCRYPT_STAGING_DIRECTORY,
        }
        .into();
        self
    }
    pub fn domains(mut self, contact: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.domains = contact.into_iter().map(|s| s.as_ref().into()).collect();
        self
    }
    pub fn domains_push(mut self, contact: impl AsRef<str>) -> Self {
        self.domains.push(contact.as_ref().into());
        self
    }

    /// Provide a list of contacts for the account.
    ///
    /// Note that email addresses must include a `mailto:` prefix.
    pub fn contact(mut self, contact: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.contact = contact.into_iter().map(|s| s.as_ref().into()).collect();
        self
    }

    /// Provide a contact for the account.
    ///
    /// Note that an email address must include a `mailto:` prefix.
    pub fn contact_push(mut self, contact: impl AsRef<str>) -> Self {
        self.contact.push(contact.as_ref().into());
        self
    }

    pub fn cache<C: 'static + Cache>(self, cache: C) -> AcmeConfig<C::EC, C::EA> {
        AcmeConfig {
            client_config: self.client_config,
            directory_url: self.directory_url,
            domains: self.domains,
            contact: self.contact,
            cache: Box::new(cache),
            challenge_type: self.challenge_type,
        }
    }
    pub fn cache_compose<CC: 'static + CertCache, CA: 'static + AccountCache>(self, cert_cache: CC, account_cache: CA) -> AcmeConfig<CC::EC, CA::EA> {
        self.cache(CompositeCache::new(cert_cache, account_cache))
    }
    pub fn cache_with_boxed_err<C: 'static + Cache>(self, cache: C) -> AcmeConfig<Box<dyn Debug>> {
        self.cache(BoxedErrCache::new(cache))
    }
    pub fn cache_option<C: 'static + Cache>(self, cache: Option<C>) -> AcmeConfig<C::EC, C::EA> {
        match cache {
            Some(cache) => self.cache(cache),
            None => self.cache(NoCache::<C::EC, C::EA>::default()),
        }
    }
    pub fn challenge_type(mut self, challenge_type: UseChallenge) -> Self {
        self.challenge_type = challenge_type;
        self
    }
    pub fn state(self) -> AcmeState<EC, EA> {
        AcmeState::new(self)
    }
    /// Turn a stream of TCP connections into a stream of TLS connections.
    ///
    /// Specify supported protocol names in `alpn_protocols`, most preferred first. If empty (`Vec::new()`), we don't do ALPN.
    pub fn incoming<TCP: AsyncRead + AsyncWrite + Unpin, ETCP, ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin>(
        self,
        tcp_incoming: ITCP,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        self.state().incoming(tcp_incoming, alpn_protocols)
    }
    #[cfg(feature = "tokio")]
    /// Tokio compatible wrapper for [Self::incoming].
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
        self.state().tokio_incoming(tcp_incoming, alpn_protocols)
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> fmt::Debug for AcmeConfig<EC, EA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeConfig")
            .field("directory", &self.directory_url)
            .field("domains", &self.domains)
            .field("contact", &self.contact)
            .finish_non_exhaustive()
    }
}
