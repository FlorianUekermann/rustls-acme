use futures_rustls::pki_types::InvalidDnsNameError;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

#[cfg(feature = "default-http-client")]
use futures::AsyncReadExt;
#[cfg(feature = "default-http-client")]
use futures_rustls::rustls::ClientConfig;

// RFC 8555§6.1:
//
// ACME clients MUST send a User-Agent header field, in accordance with
// [RFC7231].  This header field SHOULD include the name and version of
// the ACME software in addition to the name and version of the
// underlying HTTP client software.
//
// We provide the `rustls-acme` part here; each `AcmeHttpClient` implementation appends the name
// and version of its own HTTP client.
const USER_AGENT: &str = concat!("rustls-acme/", env!("CARGO_PKG_VERSION"));

/// The HTTP methods used by the ACME protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMethod {
    Get,
    Post,
    Head,
}

/// An HTTP request issued by rustls-acme to an ACME server.
///
/// The `body`, when present, is a JOSE JSON document and should be sent with a `Content-Type:
/// application/jose+json` header. Implementations should append their own client name/version to
/// `user_agent` and send it as the `User-Agent` header.
pub struct AcmeRequest {
    pub method: AcmeMethod,
    pub url: String,
    pub body: Option<String>,
    pub user_agent: String,
}

/// An HTTP response returned to rustls-acme from an ACME server.
pub struct AcmeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl AcmeResponse {
    /// Returns the last value of the named header, if present. The lookup is case-insensitive, and
    /// the last value wins.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the status code is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// An HTTP client used by rustls-acme for ACME API calls.
///
/// Provide a custom implementation via
/// [`AcmeConfig::new_with_http_client`](crate::AcmeConfig::new_with_http_client) or
/// [`AcmeConfig::http_client`](crate::AcmeConfig::http_client) to reuse an HTTP client already
/// present in your application instead of the default one. With `default-features = false` (the
/// `default-http-client` feature off) this is the only way to supply a client.
pub trait AcmeHttpClient: Send + Sync + 'static {
    /// Send the given request and return the response.
    fn request(&self, req: AcmeRequest) -> Pin<Box<dyn Future<Output = Result<AcmeResponse, HttpsRequestError>> + Send + '_>>;
}

pub(crate) async fn https(
    client: &Arc<dyn AcmeHttpClient>,
    url: impl AsRef<str>,
    method: AcmeMethod,
    body: Option<String>,
) -> Result<AcmeResponse, HttpsRequestError> {
    let response = client
        .request(AcmeRequest {
            method,
            url: url.as_ref().to_string(),
            body,
            user_agent: USER_AGENT.to_string(),
        })
        .await?;
    if !response.is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: response.status,
            body: response.body,
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

/// The default [`AcmeHttpClient`], backed by [`async-web-client`](async_web_client) and configured
/// with a [`rustls::ClientConfig`](ClientConfig). Available when the `default-http-client` feature
/// is enabled (the default).
#[cfg(feature = "default-http-client")]
pub struct DefaultHttpClient {
    client_config: Arc<ClientConfig>,
}

#[cfg(feature = "default-http-client")]
impl DefaultHttpClient {
    pub fn new(client_config: Arc<ClientConfig>) -> Self {
        Self { client_config }
    }
}

#[cfg(feature = "default-http-client")]
impl AcmeHttpClient for DefaultHttpClient {
    fn request(&self, req: AcmeRequest) -> Pin<Box<dyn Future<Output = Result<AcmeResponse, HttpsRequestError>> + Send + '_>> {
        use async_web_client::prelude::*;
        use http::header::{CONTENT_TYPE, USER_AGENT as USER_AGENT_HEADER};
        use http::{Method, Request};

        let client_config = self.client_config.clone();
        Box::pin(async move {
            let method = match req.method {
                AcmeMethod::Get => Method::GET,
                AcmeMethod::Post => Method::POST,
                AcmeMethod::Head => Method::HEAD,
            };
            let request = Request::builder()
                .method(method)
                .uri(req.url)
                .header(USER_AGENT_HEADER, format!("{} async-web-client", req.user_agent));
            let request = match req.body {
                Some(body) => request.header(CONTENT_TYPE, "application/jose+json").body(body),
                None => request.body(String::new()),
            };
            let request = request?;
            let mut response = request.send_with_client_config(client_config).await?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_string(), value.to_string())))
                .collect();
            let mut body = String::new();
            response.body_mut().read_to_string(&mut body).await?;
            Ok(AcmeResponse { status, headers, body })
        })
    }
}

#[cfg(feature = "default-http-client")]
impl From<async_web_client::HttpError> for HttpsRequestError {
    fn from(e: async_web_client::HttpError) -> Self {
        Self::Http(e.into())
    }
}

#[cfg(feature = "default-http-client")]
impl From<http::Error> for HttpsRequestError {
    fn from(e: http::Error) -> Self {
        Self::Http(e.into())
    }
}
