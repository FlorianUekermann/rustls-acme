use crate::acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use crate::caches::{BoxedErrCache, CompositeCache, NoCache};
use crate::{AccountCache, Cache, CertCache};
use crate::{AcmeState, Incoming};
use futures::{AsyncRead, AsyncWrite, Stream};
use std::convert::Infallible;
use std::fmt::Debug;

pub struct AcmeConfig<EC: Debug = Infallible, EA: Debug = EC> {
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache: Box<dyn Cache<EC = EC, EA = EA>>,
}

impl<EC: 'static + Debug, EA: 'static + Debug> AcmeConfig<EC, EA> {
    pub fn new(domains: Vec<String>) -> AcmeConfig<EC, EA> {
        AcmeConfig {
            directory_url: LETS_ENCRYPT_STAGING_DIRECTORY.to_string(),
            domains,
            contact: vec![],
            cache: Box::new(NoCache::<EC, EA>::default()),
        }
    }
    pub fn directory(mut self, directory_url: impl ToString) -> Self {
        self.directory_url = directory_url.to_string();
        self
    }
    pub fn directory_lets_encrypt(mut self, production: bool) -> Self {
        self.directory_url = match production {
            true => LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            false => LETS_ENCRYPT_STAGING_DIRECTORY,
        }
        .to_string();
        self
    }
    pub fn domains(mut self, contact: Vec<String>) -> Self {
        self.domains = contact;
        self
    }
    pub fn domains_push(mut self, contact: String) -> Self {
        self.domains.push(contact);
        self
    }

    /// Provide a list of contacts for the account.
    ///
    /// Note that email addresses must include a `mailto:` prefix.
    pub fn contact(mut self, contact: Vec<String>) -> Self {
        self.contact = contact;
        self
    }

    /// Provide a contact for the account.
    ///
    /// Note that an email address must include a `mailto:` prefix.
    pub fn contact_push(mut self, contact: String) -> Self {
        self.contact.push(contact);
        self
    }

    pub fn cache<C: 'static + Cache>(self, cache: C) -> AcmeConfig<C::EC, C::EA> {
        AcmeConfig {
            directory_url: self.directory_url,
            domains: self.domains,
            contact: self.contact,
            cache: Box::new(cache),
        }
    }
    pub fn cache_compose<CC: 'static + CertCache, CA: 'static + AccountCache>(
        self,
        cert_cache: CC,
        account_cache: CA,
    ) -> AcmeConfig<CC::EC, CA::EA> {
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
    pub fn state(self) -> AcmeState<EC, EA> {
        AcmeState::new(self)
    }
    pub fn incoming<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>>,
    >(
        self,
        tcp_incoming: ITCP,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        self.state().incoming(tcp_incoming)
    }
}
