use crate::Incoming;
use futures::{AsyncRead, AsyncWrite, Stream};
use futures_rustls::server::TlsStream;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncReadCompatExt;

pub struct TokioIncomingTcpWrapper<
    TokioTCP: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    ETCP,
    TokioITCP: Stream<Item = Result<TokioTCP, ETCP>> + Unpin,
> {
    incoming_tcp: TokioITCP,
}

impl<TokioTCP: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin, ETCP, TokioITCP: Stream<Item = Result<TokioTCP, ETCP>> + Unpin>
    TokioIncomingTcpWrapper<TokioTCP, ETCP, TokioITCP>
{
    pub fn into_inner(self) -> TokioITCP {
        self.incoming_tcp
    }
}

impl<TokioTCP: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin, ETCP, TokioITCP: Stream<Item = Result<TokioTCP, ETCP>> + Unpin> Stream
    for TokioIncomingTcpWrapper<TokioTCP, ETCP, TokioITCP>
{
    type Item = Result<tokio_util::compat::Compat<TokioTCP>, ETCP>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.incoming_tcp).poll_next(cx) {
            Poll::Ready(Some(Ok(tcp))) => Poll::Ready(Some(Ok(tcp.compat()))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<TokioTCP: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin, ETCP, TokioITCP: Stream<Item = Result<TokioTCP, ETCP>> + Unpin> From<TokioITCP>
    for TokioIncomingTcpWrapper<TokioTCP, ETCP, TokioITCP>
{
    fn from(incoming_tcp: TokioITCP) -> Self {
        Self { incoming_tcp }
    }
}

pub struct TokioIncoming<
    TCP: AsyncRead + AsyncWrite + Unpin,
    ETCP,
    ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    EC: Debug + 'static,
    EA: Debug + 'static,
> {
    incoming: Incoming<TCP, ETCP, ITCP, EC, EA>,
}

impl<TCP: AsyncRead + AsyncWrite + Unpin, ETCP, ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin, EC: Debug + 'static, EA: Debug + 'static> Stream
    for TokioIncoming<TCP, ETCP, ITCP, EC, EA>
{
    type Item = Result<tokio_util::compat::Compat<TlsStream<TCP>>, ETCP>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.incoming).poll_next(cx) {
            Poll::Ready(Some(Ok(tls))) => Poll::Ready(Some(Ok(tls.compat()))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<TCP: AsyncRead + AsyncWrite + Unpin, ETCP, ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin, EC: Debug + 'static, EA: Debug + 'static>
    From<Incoming<TCP, ETCP, ITCP, EC, EA>> for TokioIncoming<TCP, ETCP, ITCP, EC, EA>
{
    fn from(incoming: Incoming<TCP, ETCP, ITCP, EC, EA>) -> Self {
        Self { incoming }
    }
}

impl<TCP: AsyncRead + AsyncWrite + Unpin, ETCP, ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin, EC: Debug + 'static, EA: Debug + 'static>
    From<TokioIncoming<TCP, ETCP, ITCP, EC, EA>> for Incoming<TCP, ETCP, ITCP, EC, EA>
{
    fn from(tokio_incoming: TokioIncoming<TCP, ETCP, ITCP, EC, EA>) -> Self {
        tokio_incoming.incoming
    }
}
