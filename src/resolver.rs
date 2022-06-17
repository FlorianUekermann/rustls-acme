use crate::acme::ACME_TLS_ALPN_NAME;
use async_rustls::rustls::sign::CertifiedKey;
use async_rustls::rustls::{ClientHello, ResolvesServerCert};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

struct Inner {
    cert: Option<CertifiedKey>,
    auth_keys: BTreeMap<String, CertifiedKey>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: CertifiedKey) {
        self.inner.lock().unwrap().cert = Some(cert);
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: CertifiedKey) {
        self.inner.lock().unwrap().auth_keys.insert(domain, cert);
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
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
