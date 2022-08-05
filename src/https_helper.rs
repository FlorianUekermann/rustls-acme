use futures_rustls::rustls::ClientConfig;
use futures_rustls::TlsConnector;
use http_types::{Method, Request, Response};
use rustls::client::InvalidDnsNameError;
use rustls::{RootCertStore, ServerName};
use smol::net::TcpStream;
use std::convert::TryFrom;
use std::io;
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
    let domain = ServerName::try_from(host)?;

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(domain, tcp)
        .await?;
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
