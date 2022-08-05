use crate::acceptor::{AcmeAccept, AcmeAcceptor};
use crate::AcmeState;
use futures::stream::FuturesUnordered;
use futures::{AsyncRead, AsyncWrite, Stream};
use futures_rustls::server::TlsStream;
use futures_rustls::Accept;
use pin_project::pin_project;
use rustls::ServerConfig;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[pin_project]
pub struct Incoming<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>>,
    EC: Debug + 'static,
    EA: Debug + 'static,
> {
    #[pin]
    state: AcmeState<EC, EA>,
    acceptor: AcmeAcceptor,
    rustls_config: Arc<ServerConfig>,
    #[pin]
    tcp_incoming: ITCP,
    #[pin]
    acme_accepting: FuturesUnordered<AcmeAccept<TCP>>,
    #[pin]
    tls_accepting: FuturesUnordered<Accept<TCP>>,
}

impl<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>>,
        EC: Debug + 'static,
        EA: Debug + 'static,
    > Incoming<TCP, ETCP, ITCP, EC, EA>
{
    pub fn new(tcp_incoming: ITCP, state: AcmeState<EC, EA>, acceptor: AcmeAcceptor) -> Self {
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver());
        Self {
            state,
            acceptor,
            rustls_config: Arc::new(config),
            tcp_incoming,
            acme_accepting: FuturesUnordered::new(),
            tls_accepting: FuturesUnordered::new(),
        }
    }
}

impl<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>>,
        EC: Debug + 'static,
        EA: Debug + 'static,
    > Stream for Incoming<TCP, ETCP, ITCP, EC, EA>
{
    type Item = Result<TlsStream<TCP>, ETCP>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match this.state.as_mut().poll_next(cx) {
                Poll::Ready(Some(event)) => {
                    match event {
                        Ok(ok) => log::info!("event: {:?}", ok),
                        Err(err) => log::error!("event: {:?}", err),
                    }
                    continue;
                }
                Poll::Ready(None) => unreachable!(),
                Poll::Pending => {}
            }
            match this.acme_accepting.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Some(tls)))) => this
                    .tls_accepting
                    .push(tls.into_stream(this.rustls_config.clone())),
                Poll::Ready(Some(Ok(None))) => {
                    log::info!("received TLS-ALPN-01 validation request")
                }
                Poll::Ready(Some(Err(err))) => log::error!("tls accept failed, {:?}", err),
                Poll::Ready(None) | Poll::Pending => {}
            }
            match this.tls_accepting.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(tls))) => return Poll::Ready(Some(Ok(tls))),
                Poll::Ready(Some(Err(err))) => log::error!("tls accept failed, {:?}", err),
                Poll::Ready(None) | Poll::Pending => {}
            }
            match this.tcp_incoming.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(tcp))) => this.acme_accepting.push(this.acceptor.accept(tcp)),
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
