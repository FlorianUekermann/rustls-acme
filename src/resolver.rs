use futures_rustls::rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use crate::is_tls_alpn_challenge;

#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
    key_auths: BTreeMap<String, Arc<Vec<u8>>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
                // Reasonably high key auth cache defaults. Avoid Infinite accumulation
                key_auths: Default::default(),
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
    pub (crate) fn clear_key_auth(&self, token: &String) {
        self.inner.lock().unwrap().key_auths.remove(token);
    }
    pub fn get_key_auth(&self, token: &String) -> Option<Arc<Vec<u8>>> {
        self.inner.lock().unwrap().key_auths.get(token).cloned()
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
