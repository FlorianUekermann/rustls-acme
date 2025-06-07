use crate::futures_rustls::rustls::ServerConfig;
use crate::{AcmeAccept, AcmeAcceptor};
use futures::prelude::*;
use futures_rustls::Accept;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[derive(Clone)]
pub struct AxumAcceptor {
    acme_acceptor: AcmeAcceptor,
    config: Arc<ServerConfig>,
}

impl AxumAcceptor {
    pub fn new(acme_acceptor: AcmeAcceptor, config: Arc<ServerConfig>) -> Self {
        Self { acme_acceptor, config }
    }
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> axum_server::accept::Accept<I, S> for AxumAcceptor {
    type Stream = Compat<futures_rustls::server::TlsStream<Compat<I>>>;
    type Service = S;
    type Future = AxumAccept<I, S>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acme_accept = self.acme_acceptor.accept(stream.compat());
        Self::Future {
            config: self.config.clone(),
            acme_accept,
            tls_accept: None,
            service: Some(service),
        }
    }
}

pub struct AxumAccept<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> {
    config: Arc<ServerConfig>,
    acme_accept: AcmeAccept<Compat<I>>,
    tls_accept: Option<Accept<Compat<I>>>,
    service: Option<S>,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Unpin for AxumAccept<I, S> {}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Future for AxumAccept<I, S> {
    type Output = io::Result<(Compat<futures_rustls::server::TlsStream<Compat<I>>>, S)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(tls_accept) = &mut self.tls_accept {
                return match Pin::new(&mut *tls_accept).poll(cx) {
                    Poll::Ready(Ok(tls)) => Poll::Ready(Ok((tls.compat(), self.service.take().unwrap()))),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                };
            }
            return match Pin::new(&mut self.acme_accept).poll(cx) {
                Poll::Ready(Ok(Some(start_handshake))) => {
                    let config = self.config.clone();
                    self.tls_accept = Some(start_handshake.into_stream(config));
                    continue;
                }
                Poll::Ready(Ok(None)) => Poll::Ready(Err(io::Error::other("TLS-ALPN-01 validation request"))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}
