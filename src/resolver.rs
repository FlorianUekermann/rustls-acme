use crate::acme::{duration_until_renewal_attempt, order, ACME_TLS_ALPN_NAME};
use crate::persist::{read_if_exist, write};
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::Certificate as RustlsCertificate;
use async_rustls::rustls::{ClientHello, PrivateKey, ResolvesServerCert};
use async_std::path::Path;
use async_std::task::sleep;
use ring::digest::{Context, SHA256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

pub struct ResolvesServerCertUsingAcme {
    cert_key: Mutex<Option<CertifiedKey>>,
    auth_keys: Mutex<BTreeMap<String, CertifiedKey>>,
    contact: Vec<String>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new() -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            cert_key: Mutex::new(None),
            auth_keys: Mutex::new(BTreeMap::new()),
            contact: vec![],
        })
    }
    pub fn with_contact<'a, S, I>(contact: I) -> Arc<ResolvesServerCertUsingAcme>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        Arc::new(ResolvesServerCertUsingAcme {
            cert_key: Mutex::new(None),
            auth_keys: Mutex::new(BTreeMap::new()),
            contact: contact
                .into_iter()
                .map(AsRef::<str>::as_ref)
                .map(str::to_string)
                .collect(),
        })
    }
    pub async fn run<P: AsRef<Path>>(
        &self,
        directory_url: impl AsRef<str>,
        mut domains: Vec<String>,
        cache_dir: Option<P>,
    ) {
        domains.sort();
        let file_name = Self::cached_cert_file_name(&domains, &directory_url);
        self.load_certified_key(&cache_dir, &file_name).await;

        let mut err_cnt = 0usize;
        loop {
            let d = duration_until_renewal_attempt(
                self.cert_key.lock().unwrap().as_ref(),
                err_cnt
            );
            if d.as_secs() != 0 {
                log::info!("next renewal attempt in {}s", d.as_secs());
                sleep(d).await;
            }
            match order(
                |domain,auth_key|{
                    self.auth_keys
                    .lock()
                    .unwrap()
                    .insert(domain.clone(), auth_key);
                    Ok(())
                },
                &directory_url, &domains, cache_dir.as_ref(), &self.contact
            ).await
            {
                Ok((cert_key, pk_pem, acme_cert_pem)) => {
                    self.cert_key.lock().unwrap().replace(cert_key.clone());
                    Self::save_certified_key(
                        &cache_dir,
                        &file_name,
                        pk_pem,
                        acme_cert_pem
                    ).await;
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
        let cert_chain = pems
            .into_iter()
            .map(|p| RustlsCertificate(p.contents))
            .collect();
        let cert_key = CertifiedKey::new(cert_chain, Arc::new(pk));
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
    fn cached_cert_file_name(domains: &Vec<String>, directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        // cache is specific to a particular ACME API URL
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
        format!("cached_cert_{}", hash)
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