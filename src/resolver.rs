use crate::is_tls_alpn_challenge;
use futures_rustls::rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    challenge_data: Option<ChallengeData>,
}

#[derive(Debug)]
enum ChallengeData {
    TlsAlpn01 { sni: String, cert: Arc<CertifiedKey> },
    Http01 { token: String, key_auth: String },
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                challenge_data: None,
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().cert = Some(cert);
    }
    pub(crate) fn set_tls_alpn_01_challenge_data(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner.lock().unwrap().challenge_data = Some(ChallengeData::TlsAlpn01 { sni: domain, cert });
    }
    pub(crate) fn set_http_01_challenge_data(&self, token: String, key_auth: String) {
        self.inner.lock().unwrap().challenge_data = Some(ChallengeData::Http01 { token, key_auth })
    }
    pub(crate) fn clear_challenge_data(&self) {
        self.inner.lock().unwrap().challenge_data = None;
    }
    pub fn get_http_01_key_auth(&self, challenge_token: &str) -> Option<String> {
        match &self.inner.lock().unwrap().challenge_data {
            Some(ChallengeData::Http01 { token, key_auth }) => {
                if token == challenge_token {
                    Some(key_auth.clone())
                } else {
                    None
                }
            }
            _ => None,
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
                Some(domain) => match &self.inner.lock().unwrap().challenge_data {
                    Some(ChallengeData::TlsAlpn01 { sni, cert }) => {
                        if sni == domain {
                            Some(cert.clone())
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
            }
        } else {
            self.inner.lock().unwrap().cert.clone()
        }
    }
}
