use crate::acme::{Account, AcmeError, Auth, Directory, Identifier, Order, ACME_TLS_ALPN_NAME};
use crate::persist::{read_if_exist, write};
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::Certificate as RustlsCertificate;
use async_rustls::rustls::{ClientHello, PrivateKey, ResolvesServerCert};
use async_std::path::Path;
use async_std::task::sleep;
use chrono::Utc;
use futures::future::try_join_all;
use pem::PemError;
use rcgen::{CertificateParams, DistinguishedName, RcgenError, PKCS_ECDSA_P256_SHA256};
use ring::digest::{Context, SHA256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use x509_parser::parse_x509_certificate;

pub struct ResolvesServerCertUsingAcme {
    cert_key: Mutex<Option<CertifiedKey>>,
    auth_keys: Mutex<BTreeMap<String, CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new() -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            cert_key: Mutex::new(None),
            auth_keys: Mutex::new(BTreeMap::new()),
        })
    }
    pub async fn run<P: AsRef<Path>>(
        &self,
        directory_url: impl AsRef<str>,
        mut domains: Vec<String>,
        cache_dir: Option<P>,
    ) {
        domains.sort();
        let file_name = Self::cached_cert_file_name(&domains);
        self.load_certified_key(&cache_dir, &file_name).await;

        let mut err_cnt = 0usize;
        loop {
            let d = self.duration_until_renewal_attempt(err_cnt);
            if d.as_secs() != 0 {
                log::info!("next renewal attemt in {}s", d.as_secs());
                sleep(d).await;
            }
            match self
                .order(&directory_url, &domains, &cache_dir, &file_name)
                .await
            {
                Ok(_) => {
                    log::info!("successfully ordered certificate");
                    err_cnt = 0;
                }
                Err(err) => {
                    log::error!("ordering certificate failed: {}", err);
                    err_cnt += 1;
                }
            };
        }
    }
    async fn order<P: AsRef<Path>>(
        &self,
        directory_url: impl AsRef<str>,
        domains: &Vec<String>,
        cache_dir: &Option<P>,
        file_name: &str,
    ) -> Result<(), OrderError> {
        let mut params = CertificateParams::new(domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params)?;
        let pk = any_ecdsa_type(&PrivateKey(cert.serialize_private_key_der())).unwrap();
        let directory = Directory::discover(directory_url).await?;
        let account = Account::load_or_create(directory, Some("test-persist")).await?;
        let mut order = account.new_order(domains.clone()).await?;
        loop {
            order = match order {
                Order::Pending {
                    authorizations,
                    finalize,
                } => {
                    let auth_futures = authorizations
                        .iter()
                        .map(|url| self.authorize(&account, url));
                    try_join_all(auth_futures).await?;
                    log::info!("completed all authorizations");
                    Order::Ready { finalize }
                }
                Order::Ready { finalize } => {
                    log::info!("sending csr");
                    let csr = cert.serialize_request_der()?;
                    account.finalize(finalize, csr).await?
                }
                Order::Valid { certificate } => {
                    log::info!("download certificate");
                    let acme_cert_pem = account.certificate(certificate).await?;
                    let acme_cert = RustlsCertificate(pem::parse(&acme_cert_pem)?.contents);
                    let cert_key = CertifiedKey::new(vec![acme_cert], Arc::new(pk));
                    self.cert_key.lock().unwrap().replace(cert_key.clone());
                    let pk_pem = cert.serialize_private_key_pem();
                    Self::save_certified_key(cache_dir, file_name, pk_pem, acme_cert_pem).await;
                    return Ok(());
                }
                Order::Invalid => return Err(OrderError::BadOrder(order)),
            }
        }
    }
    fn duration_until_renewal_attempt(&self, err_cnt: usize) -> Duration {
        let valid_until = match self.cert_key.lock().unwrap().clone() {
            None => 0,
            Some(cert_key) => match cert_key.cert.first() {
                Some(cert) => match parse_x509_certificate(cert.0.as_slice()) {
                    Ok((_, cert)) => cert.validity().not_after.timestamp(),
                    Err(err) => {
                        log::error!("could not parse certificate: {}", err);
                        0
                    }
                },
                None => 0,
            },
        };
        let valid_secs = (valid_until - Utc::now().timestamp()).max(0);
        let wait_secs = Duration::from_secs(valid_secs as u64 / 2);
        match err_cnt {
            0 => wait_secs,
            err_cnt => wait_secs.max(Duration::from_secs(1 << err_cnt)),
        }
    }
    async fn load_certified_key<P: AsRef<Path>>(
        &self,
        cache_dir: &Option<P>,
        cert_cache_name: &str,
    ) {
        let mut pems = match cache_dir {
            Some(cache_dir) => match read_if_exist(cache_dir, &cert_cache_name).await {
                Ok(content) => match content {
                    Some(content) => pem::parse_many(content),
                    None => return,
                },
                Err(err) => {
                    log::error!("could not read certificate from cache directory: {}", err);
                    return;
                }
            },
            None => return,
        };
        if pems.len() < 2 {
            log::error!(
                "expected 2 or more pem in {}, got: {}",
                cert_cache_name,
                pems.len()
            );
            return;
        }
        let pk = match any_ecdsa_type(&PrivateKey(pems.remove(0).contents)) {
            Ok(pk) => pk,
            Err(_) => {
                log::error!("{} does not contain an ecdsa private key", cert_cache_name);
                return;
            }
        };
        let acme_cert = RustlsCertificate(pems.remove(0).contents);
        let cert_key = CertifiedKey::new(vec![acme_cert], Arc::new(pk));
        self.cert_key.lock().unwrap().replace(cert_key);
        log::info!("found certificate in cache directory")
    }
    async fn save_certified_key<P: AsRef<Path>>(
        cache_dir: &Option<P>,
        cert_cache_name: &str,
        pk_pem: String,
        acme_cert_pem: String,
    ) {
        match cache_dir {
            Some(cache_dir) => {
                let content = format!("{}\n{}", pk_pem, acme_cert_pem);
                match write(cache_dir, cert_cache_name, &content).await {
                    Ok(_) => log::info!("saved certificate in cache directory"),
                    Err(err) => log::error!("could not save certificate: {}", err),
                }
            }
            None => log::info!("could not save certificate, no cache directory specified"),
        }
    }
    fn cached_cert_file_name(domains: &Vec<String>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
        format!("cached_cert_{}", hash)
    }
    async fn authorize(&self, account: &Account, url: &String) -> Result<(), OrderError> {
        let (domain, challenge_url) = match account.auth(url).await? {
            Auth::Pending {
                identifier,
                challenges,
            } => {
                let Identifier::Dns(domain) = identifier;
                log::info!("trigger challenge for {}", &domain);
                let (challenge, auth_key) = account.tls_alpn_01(&challenges, domain.clone())?;
                self.auth_keys
                    .lock()
                    .unwrap()
                    .insert(domain.clone(), auth_key);
                account.challenge(&challenge.url).await?;
                (challenge.url.clone(), domain)
            }
            Auth::Valid => return Ok(()),
            auth => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            sleep(Duration::from_secs(1 << i)).await;
            match account.auth(url).await? {
                Auth::Pending { .. } => {
                    log::info!("authorization for {} still pending", &domain);
                    account.challenge(&challenge_url).await?
                }
                Auth::Valid => return Ok(()),
                auth => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(domain))
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            match client_hello.server_name() {
                None => {
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).to_string();
                    self.auth_keys.lock().unwrap().get(&domain).cloned()
                }
            }
        } else {
            self.cert_key.lock().unwrap().clone()
        }
    }
}

#[derive(Error, Debug)]
enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("could not parse pem: {0}")]
    Pem(#[from] PemError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}
