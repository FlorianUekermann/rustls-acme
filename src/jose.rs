use crate::crypto::digest::{digest, Digest, SHA256};
use crate::crypto::rand::SystemRandom;
use crate::crypto::signature::{EcdsaKeyPair, KeyPair};
use base64::prelude::*;
use serde::Serialize;
use thiserror::Error;

pub(crate) fn sign(key: &EcdsaKeyPair, kid: Option<&str>, nonce: String, url: &str, payload: &str) -> Result<String, JoseError> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, nonce, url)?;
    let payload = BASE64_URL_SAFE_NO_PAD.encode(payload);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = key.sign(&SystemRandom::new(), combined.as_bytes())?;
    let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    Ok(serde_json::to_string(&body)?)
}

pub(crate) fn key_authorization(key: &EcdsaKeyPair, token: &str) -> Result<String, JoseError> {
    let jwk = Jwk::new(key);
    Ok(format!("{}.{}", token, jwk.thumb_sha256_base64()?))
}

pub(crate) fn key_authorization_sha256(key: &EcdsaKeyPair, token: &str) -> Result<Digest, JoseError> {
    let key_authorization = key_authorization(key, token)?;
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
    fn base64(jwk: Option<Jwk>, kid: Option<&'a str>, nonce: String, url: &'a str) -> Result<String, JoseError> {
        let protected = Self {
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected)?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(protected))
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
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
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
        Ok(BASE64_URL_SAFE_NO_PAD.encode(hash))
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
    Crypto(#[from] crate::crypto::error::Unspecified),
}
