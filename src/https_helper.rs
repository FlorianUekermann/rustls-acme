use async_web_client::prelude::*;
use futures::AsyncReadExt;
use futures_rustls::pki_types::InvalidDnsNameError;
use futures_rustls::rustls::ClientConfig;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response};
use std::io;
use std::sync::Arc;
use thiserror::Error;

pub(crate) async fn https(
    client_config: &Arc<ClientConfig>,
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response<String>, HttpsRequestError> {
    let request = Request::builder().method(method).uri(url.as_ref());
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
