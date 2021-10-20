use crate::acme::ACME_TLS_ALPN_NAME;
use crate::ResolvesServerCertUsingAcme;
use async_rustls::rustls::{ServerConfig, Session};
use futures::{AsyncRead, AsyncWrite};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn new(mut config: ServerConfig, resolver: Arc<ResolvesServerCertUsingAcme>) -> Self {
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        config.cert_resolver = resolver;
        let config = Arc::new(config);
        TlsAcceptor { config }
    }
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Accept(async_rustls::TlsAcceptor::from(self.config.clone()).accept(stream))
    }
}

pub struct Accept<IO>(async_rustls::Accept<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = std::io::Result<Option<async_rustls::server::TlsStream<IO>>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let tls = match Pin::new(&mut self.0).poll(cx) {
            Poll::Ready(result) => match result {
                Ok(tls) => tls,
                Err(err) => return Poll::Ready(Err(err)),
            },
            Poll::Pending => return Poll::Pending,
        };
        if tls.get_ref().1.get_alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
            log::debug!("completed acme-tls/1 handshake");
            return Poll::Ready(Ok(None));
        }
        Poll::Ready(Ok(Some(tls)))
    }
}
