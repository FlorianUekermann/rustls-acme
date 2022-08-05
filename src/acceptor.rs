use crate::acme::ACME_TLS_ALPN_NAME;
use crate::ResolvesServerCertAcme;
use futures::prelude::*;
use futures_rustls::{Accept, LazyConfigAcceptor, StartHandshake};
use rustls::server::Acceptor;
use rustls::ServerConfig;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct AcmeAcceptor {
    config: Arc<ServerConfig>,
}

impl AcmeAcceptor {
    pub(crate) fn new(resolver: Arc<ResolvesServerCertAcme>) -> Self {
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Self {
            config: Arc::new(config),
        }
    }
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, io: IO) -> AcmeAccept<IO> {
        AcmeAccept::new(io, self.config.clone())
    }
}

pub struct AcmeAccept<IO: AsyncRead + AsyncWrite + Unpin> {
    acceptor: LazyConfigAcceptor<IO>,
    config: Arc<ServerConfig>,
    validation_accept: Option<Accept<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AcmeAccept<IO> {
    pub(crate) fn new(io: IO, config: Arc<ServerConfig>) -> Self {
        Self {
            acceptor: LazyConfigAcceptor::new(Acceptor::new().unwrap(), io),
            config,
            validation_accept: None,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for AcmeAccept<IO> {
    type Output = io::Result<Option<StartHandshake<IO>>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if let Some(validation_accept) = &mut self.validation_accept {
                return match Pin::new(validation_accept).poll(cx) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                };
            }

            return match Pin::new(&mut self.acceptor).poll(cx) {
                Poll::Ready(Ok(handshake)) => {
                    let is_validation = handshake
                        .client_hello()
                        .alpn()
                        .into_iter()
                        .flatten()
                        .eq([ACME_TLS_ALPN_NAME]);
                    if is_validation {
                        self.validation_accept = Some(handshake.into_stream(self.config.clone()));
                        continue;
                    }
                    Poll::Ready(Ok(Some(handshake)))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}
