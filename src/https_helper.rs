use futures_rustls::rustls::ClientConfig;
use futures_rustls::TlsConnector;
use http_types::{Method, Request, Response};
use rustls::client::InvalidDnsNameError;
use rustls::ServerName;
use smol::net::TcpStream;
use std::convert::TryFrom;
use std::io;
use std::sync::Arc;
use thiserror::Error;

pub(crate) async fn https(
    client_config: &Arc<ClientConfig>,
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
    let domain = ServerName::try_from(host)?;
    let tls = TlsConnector::from(client_config.clone()).connect(domain, tcp).await?;
    let mut response = async_h1::connect(tls, request).await?;
    let status = response.status();
    if !status.is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: status.into(),
            body: response.body_string().await?,
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

impl From<http_types::Error> for HttpsRequestError {
    fn from(e: http_types::Error) -> Self {
        Self::Http(e.into_inner().into())
    }
}
