use async_web_client::prelude::*;
use futures::AsyncReadExt;
use futures_rustls::pki_types::InvalidDnsNameError;
use futures_rustls::rustls::ClientConfig;
use http::header::{CONTENT_TYPE, USER_AGENT};
use http::{Method, Request, Response};
use std::io;
use std::sync::Arc;
use thiserror::Error;

// RFC 8555§6.1:
//
// ACME clients MUST send a User-Agent header field, in accordance with
// [RFC7231].  This header field SHOULD include the name and version of
// the ACME software in addition to the name and version of the
// underlying HTTP client software.
//
// We don't have a version for `async-web-client` here so we only satisfy 3/4 of the SHOULD
const USER_AGENT_VALUE: &str = concat!("rustls-acme/", env!("CARGO_PKG_VERSION"), " async-web-client");

pub(crate) async fn https(
    client_config: &Arc<ClientConfig>,
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response<String>, HttpsRequestError> {
    let request = Request::builder().method(method).uri(url.as_ref()).header(USER_AGENT, USER_AGENT_VALUE);

    let request = if let Some(body) = body {
        request.header(CONTENT_TYPE, "application/jose+json").body(body)
    } else {
        request.body("".to_string())
    };
    let request = request?;
    let mut response = request.send_with_client_config(client_config.clone()).await?;
    let mut body = String::new();
    response.body_mut().read_to_string(&mut body).await?;
    let response = response.map(|_| body);
    let status = response.status();
    if !status.is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: status.into(),
            body: response.into_body(),
        });
    }
    Ok(response)
}

#[derive(Error, Debug)]
pub enum HttpsRequestError {
    #[error("io error: {0:?}")]
    Io(#[from] io::Error),
    #[error("invalid dns name: {0:?}")]
    InvalidDnsName(#[from] InvalidDnsNameError),
    #[error("http error: {0:?}")]
    Http(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("non 2xx http status: {status_code} {body:?}")]
    Non2xxStatus { status_code: u16, body: String },
    #[error("could not determine host from url")]
    UndefinedHost,
}

impl From<async_web_client::HttpError> for HttpsRequestError {
    fn from(e: async_web_client::HttpError) -> Self {
        Self::Http(e.into())
    }
}

impl From<http::Error> for HttpsRequestError {
    fn from(e: http::Error) -> Self {
        Self::Http(e.into())
    }
}
