use crate::acme::ACME_TLS_ALPN_NAME;
use crate::AcmeState;
use async_rustls::rustls::Session;
use async_rustls::server::TlsStream;
use async_rustls::{Accept, TlsAcceptor};
use futures::stream::FuturesUnordered;
use futures::{AsyncRead, AsyncWrite, Stream};
use pin_project::pin_project;
use std::fmt::Debug;
use std::pin::Pin;
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
    acceptor: TlsAcceptor,
    #[pin]
    tcp_incoming: ITCP,
    #[pin]
    tcp_accepting: FuturesUnordered<Accept<TCP>>,
}

impl<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>>,
        EC: Debug + 'static,
        EA: Debug + 'static,
    > Incoming<TCP, ETCP, ITCP, EC, EA>
{
    pub fn new(tcp_incoming: ITCP, state: AcmeState<EC, EA>, acceptor: TlsAcceptor) -> Self {
        Self {
            state,
            acceptor,
            tcp_incoming,
            tcp_accepting: FuturesUnordered::new(),
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
            match this.tcp_accepting.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(tls))) => match tls.get_ref().1.get_alpn_protocol() {
                    Some(ACME_TLS_ALPN_NAME) => {
                        log::info!("received TLS-ALPN-01 validation request")
                    }
                    _ => return Poll::Ready(Some(Ok(tls))),
                },
                Poll::Ready(Some(Err(err))) => log::error!("tls accept failed, {:?}", err),
                Poll::Ready(None) | Poll::Pending => {}
            }
            match this.tcp_incoming.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(tcp))) => this.tcp_accepting.push(this.acceptor.accept(tcp)),
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
