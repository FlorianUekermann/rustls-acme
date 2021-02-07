use crate::acme::ACME_TLS_ALPN_NAME;
use crate::ResolvesServerCertUsingAcme;
use async_rustls::rustls::{ServerConfig, Session};
use async_rustls::server::TlsStream;
use futures::{AsyncRead, AsyncWrite};
use std::sync::Arc;

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
    pub async fn accept<IO>(&self, stream: IO) -> std::io::Result<Option<TlsStream<IO>>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = async_rustls::TlsAcceptor::from(self.config.clone())
            .accept(stream)
            .await?;
        if tls.get_ref().1.get_alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
            log::debug!("completed acme-tls/1 handshake");
            return Ok(None);
        }
        Ok(Some(tls))
    }
}
