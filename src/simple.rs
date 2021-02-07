use crate::{ResolvesServerCertUsingAcme, TlsAcceptor};
use async_rustls::rustls::{NoClientAuth, ServerConfig};
use async_std::io;
use async_std::net::{TcpListener, TcpStream, ToSocketAddrs};
use async_std::path::Path;
use async_std::sync::Arc;
use async_std::task::spawn;
use futures::{Future, StreamExt};

pub type TlsStream = async_rustls::server::TlsStream<TcpStream>;

pub async fn bind_listen_serve<A, P, F, Fut>(
    addrs: A,
    directory_url: impl AsRef<str>,
    domains: Vec<String>,
    cache_dir: Option<P>,
    f: F,
) -> io::Result<()>
where
    A: ToSocketAddrs,
    P: AsRef<Path>,
    F: 'static + Sync + Send + Fn(TlsStream) -> Fut,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(addrs).await?;
    let resolver = ResolvesServerCertUsingAcme::new();
    let config = ServerConfig::new(NoClientAuth::new());
    let acceptor = TlsAcceptor::new(config, resolver.clone());

    let directory_url = directory_url.as_ref().to_string();
    let cache_dir = cache_dir.map(|p| p.as_ref().to_path_buf());
    spawn(async move {
        resolver.run(directory_url, domains, cache_dir).await;
    });

    let f = Arc::new(f);
    while let Some(tcp) = listener.incoming().next().await {
        let tcp = match tcp {
            Ok(tcp) => tcp,
            Err(err) => {
                log::error!("tcp accept error: {:?}", err);
                continue;
            }
        };
        let f = f.clone();
        let acceptor = acceptor.clone();
        spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(Some(tls)) => f(tls).await,
                Ok(None) => {}
                Err(err) => log::error!("tls accept error: {:?}", err),
            }
        });
    }
    Ok(())
}
