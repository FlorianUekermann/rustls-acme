//! Exercises the pluggable [`AcmeHttpClient`] interface with a third-party HTTP client.
//!
//! The test drives the client against a small local server a GET (directory discovery) and a
//! HEAD (nonce, including header extraction).
//!
//! For brevity the client uses a plain-HTTP connector ([`Client::build_http`]), which is all the
//! local test server needs.
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, head};
use axum::{Json, Router};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls_acme::acme::Directory;
use rustls_acme::{AcmeHttpClient, AcmeMethod, AcmeRequest, AcmeResponse, HttpsRequestError};
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A reference [`AcmeHttpClient`] implementation backed by [`hyper`].
struct HyperHttpClient {
    client: Client<HttpConnector, Full<Bytes>>,
}

impl HyperHttpClient {
    fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }
}

fn boxed(e: impl Error + Send + Sync + 'static) -> HttpsRequestError {
    HttpsRequestError::Http(Box::new(e))
}

impl AcmeHttpClient for HyperHttpClient {
    fn request(&self, req: AcmeRequest) -> Pin<Box<dyn Future<Output = Result<AcmeResponse, HttpsRequestError>> + Send + '_>> {
        let client = self.client.clone();
        Box::pin(async move {
            let method = match req.method {
                AcmeMethod::Get => Method::GET,
                AcmeMethod::Post => Method::POST,
                AcmeMethod::Head => Method::HEAD,
            };
            let mut builder = Request::builder()
                .method(method)
                .uri(&req.url)
                .header(hyper::header::USER_AGENT, format!("{} hyper", req.user_agent));
            if req.body.is_some() {
                builder = builder.header(hyper::header::CONTENT_TYPE, "application/jose+json");
            }
            let request = builder.body(Full::new(Bytes::from(req.body.unwrap_or_default()))).map_err(boxed)?;
            let response = client.request(request).await.map_err(boxed)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_string(), value.to_string())))
                .collect();
            let body = response.into_body().collect().await.map_err(boxed)?.to_bytes();
            let body = String::from_utf8_lossy(&body).into_owned();
            Ok(AcmeResponse { status, headers, body })
        })
    }
}

#[tokio::test]
async fn custom_http_client_discovers_directory_and_nonce() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    let directory_json = serde_json::json!({
        "newNonce": format!("{base}/new-nonce"),
        "newAccount": format!("{base}/new-account"),
        "newOrder": format!("{base}/new-order"),
    });

    let app = Router::new().route("/directory", get(move || async move { Json(directory_json) })).route(
        "/new-nonce",
        head(|| async {
            let mut headers = HeaderMap::new();
            headers.insert("replay-nonce", "test-nonce-value".parse().unwrap());
            headers.into_response()
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client: Arc<dyn AcmeHttpClient> = Arc::new(HyperHttpClient::new());

    // GET: directory discovery goes through the custom client and parses the JSON body.
    let directory = Directory::discover(&client, format!("{base}/directory")).await.unwrap();
    assert_eq!(directory.new_nonce, format!("{base}/new-nonce"));
    assert_eq!(directory.new_account, format!("{base}/new-account"));
    assert_eq!(directory.new_order, format!("{base}/new-order"));

    // HEAD: fetching a nonce exercises the response header extraction path.
    let nonce = directory.nonce(&client).await.unwrap();
    assert_eq!(nonce, "test-nonce-value");
}
