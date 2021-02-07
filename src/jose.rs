use base64::URL_SAFE_NO_PAD;
use ring::digest::{digest, Digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::Serialize;
use thiserror::Error;

pub(crate) fn sign(
    key: &EcdsaKeyPair,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: &str,
) -> Result<String, JoseError> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, nonce, url)?;
    let payload = base64::encode_config(payload, URL_SAFE_NO_PAD);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = key.sign(&SystemRandom::new(), combined.as_bytes())?;
    let signature = base64::encode_config(signature.as_ref(), URL_SAFE_NO_PAD);
    let body = Body {
        protected,
        payload,
        signature,
    };
    Ok(serde_json::to_string(&body)?)
}

pub(crate) fn key_authorization_sha256(
    key: &EcdsaKeyPair,
    token: &str,
) -> Result<Digest, JoseError> {
    let jwk = Jwk::new(key);
    let key_authorization = format!("{}.{}", token, jwk.thumb_sha256_base64()?);
    Ok(digest(&SHA256, key_authorization.as_bytes()))
}

#[derive(Serialize)]
struct Body {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: String,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn base64(
        jwk: Option<Jwk>,
        kid: Option<&'a str>,
        nonce: String,
        url: &'a str,
    ) -> Result<String, JoseError> {
        let protected = Self {
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(base64::encode_config(protected, URL_SAFE_NO_PAD))
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: base64::encode_config(x, URL_SAFE_NO_PAD),
            y: base64::encode_config(y, URL_SAFE_NO_PAD),
        }
    }
    pub(crate) fn thumb_sha256_base64(&self) -> Result<String, JoseError> {
        let jwk_thumb = JwkThumb {
            crv: self.crv,
            kty: self.kty,
            x: &self.x,
            y: &self.y,
        };
        let json = serde_json::to_vec(&jwk_thumb)?;
        let hash = digest(&SHA256, &json);
        Ok(base64::encode_config(hash, URL_SAFE_NO_PAD))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Error, Debug)]
pub enum JoseError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] ring::error::Unspecified),
}
