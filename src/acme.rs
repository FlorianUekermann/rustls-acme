use crate::*;
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::PrivateKey;
use async_std::fs::create_dir_all;
use async_std::path::{Path, PathBuf};
use base64::URL_SAFE_NO_PAD;
use http_types::{Method, Response};
use rcgen::{Certificate, CustomExtension, RcgenError, PKCS_ECDSA_P256_SHA256};
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

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
    pub async fn load_or_create<P: AsRef<Path>>(
        directory: Directory,
        cache_dir: Option<P>,
    ) -> Result<Self, AcmeError> {
        const FILE: &str = "acme_account_key";
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        if let Some(cache_dir) = &cache_dir {
            create_dir_all(cache_dir).await?;
        }
        let pkcs8 = match &cache_dir {
            Some(cache_dir) => read_if_exist(cache_dir, FILE).await?,
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
                    write(cache_dir, FILE, pkcs8.as_ref()).await?;
                }
                EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref())?
            }
        };
        let body = sign(
            &key_pair,
            None,
            directory.nonce().await?,
            &directory.new_account,
            "{\"termsOfServiceAgreed\": true}",
        )?;
        let response = https(&directory.new_account, Method::Post, Some(body)).await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
            cache: cache_dir.map(|p| p.as_ref().to_path_buf()),
        })
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
