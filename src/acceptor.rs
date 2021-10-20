use crate::acme::ACME_TLS_ALPN_NAME;
use crate::ResolvesServerCertUsingAcme;
use async_rustls::rustls::{ServerConfig, Session};
use async_rustls::server::TlsStream;
use futures::{AsyncRead, AsyncWrite};
use std::future::Future;
use std::mem::replace;
use std::ops::DerefMut;
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
        Accept::Accepting(async_rustls::TlsAcceptor::from(self.config.clone()).accept(stream))
    }
}

pub enum Accept<IO> {
    Accepting(async_rustls::Accept<IO>),
    Closing(TlsStream<IO>),
    Closed,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = std::io::Result<async_rustls::server::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.deref_mut() {
                Accept::Accepting(accept) => match Pin::new(accept).poll(cx) {
                    Poll::Ready(Ok(tls)) => match tls.get_ref().1.get_alpn_protocol() {
                        Some(ACME_TLS_ALPN_NAME) => self.set(Accept::Closing(tls)),
                        _ => return Poll::Ready(Ok(tls)),
                    },
                    p => return p,
                },
                Accept::Closing(tls) => match Pin::new(tls).poll_close(cx) {
                    Poll::Ready(Ok(())) => match replace(self.get_mut(), Accept::Closed) {
                        Accept::Closing(tls) => return Poll::Ready(Ok(tls)),
                        _ => unreachable!(),
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                },
                Accept::Closed => panic!("polled after returning closed tls connection"),
            }
        }
    }
}
