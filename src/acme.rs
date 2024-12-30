use std::sync::Arc;

use crate::any_ecdsa_type;
use crate::crypto::error::{KeyRejected, Unspecified};
use crate::crypto::rand::SystemRandom;
use crate::crypto::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, ECDSA_P256_SHA256_FIXED_SIGNING};
use crate::https_helper::{https, HttpsRequestError};
use crate::jose::{key_authorization_sha256, sign, JoseError};
use base64::prelude::*;
use futures_rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use futures_rustls::rustls::{sign::CertifiedKey, ClientConfig};
use http::header::ToStrError;
use http::{Method, Response};
use rcgen::{CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub kid: String,
}

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

impl Account {
    pub fn generate_key_pair() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(ALG, &rng).unwrap();
        pkcs8.as_ref().to_vec()
    }
    pub async fn create<'a, S, I>(client_config: &Arc<ClientConfig>, directory: Directory, contact: I) -> Result<Self, AcmeError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let key_pair = Self::generate_key_pair();
        Self::create_with_keypair(client_config, directory, contact, &key_pair).await
    }
    pub async fn create_with_keypair<'a, S, I>(
        client_config: &Arc<ClientConfig>,
        directory: Directory,
        contact: I,
        key_pair: &[u8],
    ) -> Result<Self, AcmeError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let key_pair = EcdsaKeyPair::from_pkcs8(
            ALG,
            key_pair,
            // ring 0.17 has a third argument here; aws-lc-rs doesn't.
            #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
            &SystemRandom::new(),
        )?;
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
        .to_string();
        let body = sign(&key_pair, None, directory.nonce(client_config).await?, &directory.new_account, &payload)?;
        let response = https(client_config, &directory.new_account, Method::POST, Some(body)).await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account { key_pair, kid, directory })
    }
    async fn request(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>, payload: &str) -> Result<(Option<String>, String), AcmeError> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce(client_config).await?,
            url.as_ref(),
            payload,
        )?;
        let response = https(client_config, url.as_ref(), Method::POST, Some(body)).await?;
        let location = get_header(&response, "Location").ok();
        let body = response.into_body();
        log::debug!("response: {:?}", body);
        Ok((location, body))
    }
    pub async fn new_order(&self, client_config: &Arc<ClientConfig>, domains: Vec<String>) -> Result<(String, Order), AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let response = self.request(client_config, &self.directory.new_order, &payload).await?;
        let url = response.0.ok_or(AcmeError::MissingHeader("Location"))?;
        let order = serde_json::from_str(&response.1)?;
        Ok((url, order))
    }
    pub async fn auth(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let response = self.request(client_config, url, &payload).await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    pub async fn challenge(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>) -> Result<(), AcmeError> {
        self.request(client_config, &url, "{}").await?;
        Ok(())
    }
    pub async fn order(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>) -> Result<Order, AcmeError> {
        let response = self.request(client_config, &url, "").await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    pub async fn finalize(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>, csr: &[u8]) -> Result<Order, AcmeError> {
        let payload = format!("{{\"csr\":\"{}\"}}", BASE64_URL_SAFE_NO_PAD.encode(csr));
        let response = self.request(client_config, &url, &payload).await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    pub async fn certificate(&self, client_config: &Arc<ClientConfig>, url: impl AsRef<str>) -> Result<String, AcmeError> {
        Ok(self.request(client_config, &url, "").await?.1)
    }
    pub fn tls_alpn_01<'a>(&self, challenges: &'a [Challenge], domain: String) -> Result<(&'a Challenge, CertifiedKey), AcmeError> {
        let challenge = challenges.iter().find(|c| c.typ == ChallengeType::TlsAlpn01);
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let mut params = rcgen::CertificateParams::new(vec![domain])?;
        let key_auth = key_authorization_sha256(&self.key_pair, &challenge.token)?;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;

        let sk = any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()))).unwrap();
        let certified_key = CertifiedKey::new(vec![cert.der().clone()], sk);
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
    pub async fn discover(client_config: &Arc<ClientConfig>, url: impl AsRef<str>) -> Result<Self, AcmeError> {
        let body = https(client_config, url, Method::GET, None).await?.into_body();
        Ok(serde_json::from_str(&body)?)
    }
    pub async fn nonce(&self, client_config: &Arc<ClientConfig>) -> Result<String, AcmeError> {
        let response = &https(client_config, &self.new_nonce.as_str(), Method::HEAD, None).await?;
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
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(flatten)]
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub error: Option<Problem>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Valid { certificate: String },
    Invalid,
    Processing,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub status: AuthStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
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
    pub error: Option<Problem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub detail: Option<String>,
}

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("JOSE error: {0}")]
    Jose(#[from] JoseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http request error: {0}")]
    HttpRequest(#[from] HttpsRequestError),
    #[error("non-string http response header: {0}")]
    HttpResponseNonStringHeader(#[from] ToStrError),
    #[error("invalid key pair: {0}")]
    KeyRejected(#[from] KeyRejected),
    #[error("crypto error: {0}")]
    Crypto(#[from] Unspecified),
    #[error("acme service response is missing {0} header")]
    MissingHeader(&'static str),
    #[error("no tls-alpn-01 challenge found")]
    NoTlsAlpn01Challenge,
}

impl From<http::Error> for AcmeError {
    fn from(e: http::Error) -> Self {
        Self::HttpRequest(HttpsRequestError::from(e))
    }
}

fn get_header(response: &Response<String>, header: &'static str) -> Result<String, AcmeError> {
    match response.headers().get_all(header).iter().last() {
        None => Err(AcmeError::MissingHeader(header)),
        Some(value) => Ok(value.to_str()?.to_string()),
    }
}
