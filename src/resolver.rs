use fastcache::Cache;
use futures_rustls::rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use crate::is_tls_alpn_challenge;

#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
    key_auths: Cache<String, Arc<Vec<u8>>>,
}

impl Debug for Inner {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> ::core::fmt::Result {
        f.debug_struct("Inner")
            .field("cert", &self.cert)
            .field("auth_keys", &self.auth_keys)
            //ignore non printable fashcache
            .finish()
    }
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
                // Reasonably high key auth cache defaults. Avoid Infinite accumulation
                key_auths: Cache::new(500, Duration::from_secs(3600)),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().cert = Some(cert);
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().auth_keys.insert(domain, cert);
    }
    pub(crate) fn set_key_auth(&self, token: String, key_auth: Arc<Vec<u8>>) {
        self.inner.lock().unwrap().key_auths.insert(token, key_auth);
    }
    pub fn get_key_auth(&self, token: &String) -> Option<Arc<Vec<u8>>> {
        match self.inner.lock().unwrap().key_auths.get(token) {
            None => None,
            Some(key_auth) => {
                Some(key_auth.get().clone())
            }
        }
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let is_acme_challenge = is_tls_alpn_challenge(&client_hello);
        if is_acme_challenge {
            match client_hello.server_name() {
                None => {
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).into();
                    self.inner.lock().unwrap().auth_keys.get(&domain).cloned()
                }
            }
        } else {
            self.inner.lock().unwrap().cert.clone()
        }
    }
}
