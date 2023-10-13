use crate::acme::ACME_TLS_ALPN_NAME;
use crate::is_tls_alpn_challenge;
use core::fmt;
use futures::prelude::*;
use futures_rustls::{Accept, LazyConfigAcceptor, StartHandshake};
use rustls::server::{Acceptor, ResolvesServerCert};
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
    #[deprecated(note = "please use high-level API via `AcmeState::incoming()` instead or refer to updated low-level API examples")]
    pub(crate) fn new<T: ResolvesServerCert + 'static>(resolver: Arc<T>) -> Self {
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        Self { config: Arc::new(config) }
    }
    pub fn accept<IO: AsyncRead + AsyncWrite + Unpin>(&self, io: IO) -> AcmeAccept<IO> {
        AcmeAccept::new(io, self.config.clone())
    }
}

impl fmt::Debug for AcmeAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeAcceptor").finish_non_exhaustive()
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
            acceptor: LazyConfigAcceptor::new(Acceptor::default(), io),
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
                return Pin::new(validation_accept).poll(cx).map_ok(|_| None);
            }
            let poll = Pin::new(&mut self.acceptor).poll(cx);
            let Poll::Ready(Ok(handshake)) = poll else {
                return poll.map_ok(|_| None);
            };
            if is_tls_alpn_challenge(&handshake.client_hello()) {
                self.validation_accept = Some(handshake.into_stream(self.config.clone()));
            } else {
                return Poll::Ready(Ok(Some(handshake)));
            }
        }
    }
}
