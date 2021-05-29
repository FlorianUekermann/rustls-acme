use crate::*;
use async_rustls::rustls::{
    PrivateKey,
    internal::pemfile,
    sign::{CertifiedKey, any_ecdsa_type}
};
use async_std::fs::create_dir_all;
use async_std::path::{Path, PathBuf};
use base64::URL_SAFE_NO_PAD;
use http_types::{Method, Response};
use rcgen::{Certificate, CustomExtension, RcgenError, PKCS_ECDSA_P256_SHA256, CertificateParams, DistinguishedName};
use ring::digest::{Context, SHA256};
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use thiserror::Error;

use futures::future::try_join_all;
use std::time::Duration;
use async_std::task::sleep;
use std::io;
use chrono::Utc;
use x509_parser::parse_x509_certificate;

pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub cache: Option<PathBuf>,
    pub kid: String,
}

impl Account {
    pub async fn load_or_create<'a, P, S, I>(
        directory: Directory,
        cache_dir: Option<P>,
        contact: I,
    ) -> Result<Self, AcmeError>
    where
        P: AsRef<Path>,
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        if let Some(cache_dir) = &cache_dir {
            create_dir_all(cache_dir).await?;
        }
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let file = Self::cached_key_file_name(&contact);
        let pkcs8 = match &cache_dir {
            Some(cache_dir) => read_if_exist(cache_dir, &file).await?,
            None => None,
        };
        let key_pair = match pkcs8 {
            Some(pkcs8) => {
                log::info!("found cached account key");
                EcdsaKeyPair::from_pkcs8(alg, &pkcs8)?
            }
            None => {
                log::info!("creating a new account key");
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)?;
                if let Some(cache_dir) = &cache_dir {
                    write(cache_dir, &file, pkcs8.as_ref()).await?;
                }
                EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref())?
            }
        };
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
        .to_string();
        let body = sign(
            &key_pair,
            None,
            directory.nonce().await?,
            &directory.new_account,
            &payload,
        )?;
        let mut response = https(&directory.new_account, Method::Post, Some(body)).await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
            cache: cache_dir.map(|p| p.as_ref().to_path_buf()),
        })
    }
    fn cached_key_file_name(contact: &Vec<&str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
        format!("cached_account_{}", hash)
    }
    async fn request(&self, url: impl AsRef<str>, payload: &str) -> Result<String, AcmeError> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce().await?,
            url.as_ref(),
            payload,
        )?;
        let mut response = https(url.as_ref(), Method::Post, Some(body)).await?;
        let body = response.body_string().await?;
        log::debug!("response: {:?}", body);
        Ok(body)
    }
    pub async fn new_order(&self, domains: Vec<String>) -> Result<Order, AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(|d| Identifier::Dns(d)).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let response = self.request(&self.directory.new_order, &payload).await;
        Ok(serde_json::from_str(&response?)?)
    }
    pub async fn auth(&self, url: impl AsRef<str>) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let response = self.request(url, &payload).await;
        Ok(serde_json::from_str(&response?)?)
    }
    pub async fn challenge(&self, url: impl AsRef<str>) -> Result<(), AcmeError> {
        self.request(&url, "{}").await?;
        Ok(())
    }
    pub async fn finalize(&self, url: impl AsRef<str>, csr: Vec<u8>) -> Result<Order, AcmeError> {
        let payload = format!(
            "{{\"csr\":\"{}\"}}",
            base64::encode_config(csr, URL_SAFE_NO_PAD)
        );
        let response = self.request(&url, &payload).await;
        Ok(serde_json::from_str(&response?)?)
    }
    pub async fn certificate(&self, url: impl AsRef<str>) -> Result<String, AcmeError> {
        self.request(&url, "").await
    }
    pub fn tls_alpn_01<'a>(
        &self,
        challenges: &'a Vec<Challenge>,
        domain: String,
    ) -> Result<(&'a Challenge, CertifiedKey), AcmeError> {
        let challenge = challenges
            .iter()
            .filter(|c| c.typ == ChallengeType::TlsAlpn01)
            .next();
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let mut params = rcgen::CertificateParams::new(vec![domain]);
        let key_auth = key_authorization_sha256(&self.key_pair, &*challenge.token)?;
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];
        let cert = Certificate::from_params(params)?;
        let pk = any_ecdsa_type(&PrivateKey(cert.serialize_private_key_der())).unwrap();
        let certified_key = CertifiedKey::new(
            vec![async_rustls::rustls::Certificate(cert.serialize_der()?)],
            Arc::new(pk),
        );
        Ok((challenge, certified_key))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl Directory {
    pub async fn discover(url: impl AsRef<str>) -> Result<Self, AcmeError> {
        let body = https(url, Method::Get, None).await?.body_bytes().await?;
        Ok(serde_json::from_slice(&body)?)
    }
    pub async fn nonce(&self) -> Result<String, AcmeError> {
        let response = &https(&self.new_nonce.as_str(), Method::Head, None).await?;
        get_header(response, "replay-nonce")
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Order {
    Pending {
        authorizations: Vec<String>,
        finalize: String,
    },
    Ready {
        finalize: String,
    },
    Valid {
        certificate: String,
    },
    Invalid,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Auth {
    Pending {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    Valid,
    Invalid,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub token: String,
}

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("JOSE error: {0}")]
    Jose(#[from] JoseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http request error: {0}")]
    HttpRequest(#[from] HttpsRequestError),
    #[error("invalid key pair: {0}")]
    KeyRejected(#[from] KeyRejected),
    #[error("crypto error: {0}")]
    Crypto(#[from] Unspecified),
    #[error("acme service response is missing {0} header")]
    MissingHeader(&'static str),
    #[error("no tls-alpn-01 challenge found")]
    NoTlsAlpn01Challenge,
}

impl From<http_types::Error> for AcmeError {
    fn from(e: http_types::Error) -> Self {
        Self::HttpRequest(HttpsRequestError::from(e))
    }
}

fn get_header(response: &Response, header: &'static str) -> Result<String, AcmeError> {
    match response.header(header) {
        None => Err(AcmeError::MissingHeader(header)),
        Some(values) => Ok(values.last().to_string()),
    }
}

/// obtain a new certificate for `domains` from `directory_url`
/// using the contact info `contact`.
/// authentication data will be cached in `cache_dir`.
/// the callback `set_auth_key` is called with the data needed for the ACME TLS challange
/// returns on success a tupel of:
/// - the new Certificate Key pair
/// - the key in PEM
/// - the Certificate in PEM
pub async fn order<P, F>(
    set_auth_key: F,
    directory_url: impl AsRef<str>,
    domains: &Vec<String>,
    cache_dir: Option<P>,
    contact: &Vec<String>,
    ) -> Result<(CertifiedKey, String, String), OrderError>
where
    P: AsRef<Path>,
    F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
{
    let mut params = CertificateParams::new(domains.clone());
    params.distinguished_name = DistinguishedName::new();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    let cert = rcgen::Certificate::from_params(params)?;
    let pk = any_ecdsa_type(&PrivateKey(cert.serialize_private_key_der())).unwrap();
    let directory = Directory::discover(directory_url).await?;
    let account = Account::load_or_create(directory, cache_dir, contact).await?;
    let mut order = account.new_order(domains.clone()).await?;
    loop {
        order = match order {
            Order::Pending {
                authorizations,
                finalize,
            } => {
                let auth_futures = authorizations
                    .iter()
                    .map(|url| authorize(&set_auth_key, &account, url));
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
                /*let pems = pem::parse_many(&acme_cert_pem);
                let cert_chain = pems
                    .into_iter()
                    .map(|p| RustlsCertificate(p.contents))
                    .collect();*/
                let mut rd = acme_cert_pem.as_bytes();
                let cert_chain = pemfile::certs(&mut rd)
                    .map_err(|_e| {
                        AcmeError::Io(io::Error::new(io::ErrorKind::InvalidInput, "Error reading Cert"))
                })?;
                let cert_key = CertifiedKey::new(cert_chain, Arc::new(pk));
                let pk_pem = cert.serialize_private_key_pem();
                return Ok((cert_key, pk_pem, acme_cert_pem));
            }
            Order::Invalid => return Err(OrderError::BadOrder(order)),
        }
    }
}
async fn authorize<F>(
    set_auth_key: &F,
    account: &Account,
    url: &String) -> Result<(), OrderError>
 where F: Fn(String, CertifiedKey) -> Result<(), AcmeError>
    {
    let (domain, challenge_url) = match account.auth(url).await? {
        Auth::Pending {
            identifier,
            challenges,
        } => {
            let Identifier::Dns(domain) = identifier;
            log::info!("trigger challenge for {}", &domain);
            let (challenge, auth_key) = account.tls_alpn_01(&challenges, domain.clone())?;
            set_auth_key(domain.clone(), auth_key)?;
            account.challenge(&challenge.url).await?;
            (domain, challenge.url.clone())
        }
        Auth::Valid => return Ok(()),
        auth => return Err(OrderError::BadAuth(auth)),
    };
    for i in 0u8..5 {
        sleep(Duration::from_secs(1u64 << i)).await;
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

pub fn duration_until_renewal_attempt(cert_key: Option<&CertifiedKey>, err_cnt: usize) -> Duration {
    let valid_until = match cert_key {
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

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}
