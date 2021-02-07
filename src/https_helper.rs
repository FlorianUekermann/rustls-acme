use async_rustls::rustls::ClientConfig;
use async_rustls::webpki::{DNSNameRef, InvalidDNSNameError};
use async_rustls::TlsConnector;
use async_std::io;
use async_std::net::TcpStream;
use http_types::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use thiserror::Error;
use webpki_roots::TLS_SERVER_ROOTS;

pub(crate) async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response, HttpsRequestError> {
    let mut request = Request::new(method, url.as_ref());
    if let Some(body) = body {
        request.set_body(body);
        request.set_content_type("application/jose+json".parse()?);
    }
    let host = match request.host() {
        None => return Err(HttpsRequestError::UndefinedHost),
        Some(host) => host,
    };
    let port = match request.url().port() {
        None => 443,
        Some(port) => port,
    };
    let tcp = TcpStream::connect((host, port)).await?;
    let domain = DNSNameRef::try_from_ascii_str(host)?;
    let mut config = ClientConfig::default();
    config
        .root_store
        .add_server_trust_anchors(&TLS_SERVER_ROOTS);
    let tls = TlsConnector::from(Arc::new(config))
        .connect(domain, tcp)
        .await?;
    let response = async_h1::connect(tls, request).await?;
    if !response.status().is_success() {
        return Err(HttpsRequestError::Non2xxStatus(response.status()));
    }
    Ok(response)
}

#[derive(Error, Debug)]
pub enum HttpsRequestError {
    #[error("io error: {0:?}")]
    Io(#[from] io::Error),
    #[error("invalid dns name: {0:?}")]
    InvalidDNSName(#[from] InvalidDNSNameError),
    #[error("http error: {0:?}")]
    Http(http_types::Error),
    #[error("non 2xx http status: {0:?}")]
    Non2xxStatus(StatusCode),
    #[error("could not determine host from url")]
    UndefinedHost,
}

// TODO: Why does the #[from] annotation not work?
impl From<http_types::Error> for HttpsRequestError {
    fn from(e: http_types::Error) -> Self {
        Self::Http(e)
    }
}
