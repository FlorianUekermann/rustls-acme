use crate::ResolvesServerCertAcme;
use http::{header, HeaderValue, Request, StatusCode};
use std::sync::Arc;

#[derive(Clone)]
pub struct TowerHttp01ChallengeService(pub(crate) Arc<ResolvesServerCertAcme>);

impl<B> tower_service::Service<Request<B>> for TowerHttp01ChallengeService {
    type Response = http::Response<String>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut response = http::Response::new(String::new());
        *response.status_mut() = StatusCode::NOT_FOUND;
        let Some((_, token)) = req.uri().path().rsplit_once('/') else {
            return std::future::ready(Ok(response));
        };
        let Some(body) = self.0.get_http_01_key_auth(token) else {
            return std::future::ready(Ok(response));
        };
        *response.status_mut() = StatusCode::OK;
        *response.body_mut() = body;
        response
            .headers_mut()
            .append(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        std::future::ready(Ok(response))
    }
}
