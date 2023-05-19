use rustls::client::InvalidDnsNameError;
use thiserror::Error;

pub(crate) use self::imp::*;

#[cfg(feature = "async-std")]
mod imp {
    use super::*;

    use futures_rustls::TlsConnector;
    use rustls::{ClientConfig, ServerName};
    use smol::net::TcpStream;
    use std::convert::TryFrom;
    use std::sync::Arc;

    pub use http_types::{Method, Request, Response};

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
        let tls = TlsConnector::from(client_config.clone())
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

    impl From<http_types::Error> for HttpsRequestError {
        fn from(e: http_types::Error) -> Self {
            Self::Http(e.into_inner().into())
        }
    }
}

#[cfg(feature = "tokio")]
mod imp {
    use super::*;

    use rustls::ClientConfig;
    use std::sync::Arc;

    pub use reqwest::{Request, Response};

    #[derive(Copy, Clone)]
    pub enum Method {
        Post,
        Get,
        Head,
    }

    impl From<Method> for reqwest::Method {
        fn from(m: Method) -> Self {
            match m {
                Method::Post => reqwest::Method::POST,
                Method::Get => reqwest::Method::GET,
                Method::Head => reqwest::Method::HEAD,
            }
        }
    }

    pub(crate) async fn https(
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
        method: Method,
        body: Option<String>,
    ) -> Result<Response, HttpsRequestError> {
        let method: reqwest::Method = method.into();
        let client_config: Option<ClientConfig> = Some(client_config.as_ref().clone());
        let client = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(client_config)
            .build()?;
        let mut request = client.request(method, url.as_ref());
        if let Some(body) = body {
            request = request
                .body(body)
                .header("Content-Type", "application/jose+json");
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(HttpsRequestError::Non2xxStatus {
                status_code: status.into(),
                body: response.text().await?,
            });
        }
        Ok(response)
    }

    impl From<reqwest::Error> for HttpsRequestError {
        fn from(e: reqwest::Error) -> Self {
            Self::Http(e.into())
        }
    }
}

#[derive(Error, Debug)]
pub enum HttpsRequestError {
    #[error("io error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("invalid dns name: {0:?}")]
    InvalidDnsName(#[from] InvalidDnsNameError),
    #[error("http error: {0:?}")]
    Http(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("non 2xx http status: {status_code} {body:?}")]
    Non2xxStatus { status_code: u16, body: String },
    #[error("could not determine host from url")]
    UndefinedHost,
}
