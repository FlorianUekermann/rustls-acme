use async_rustls::rustls::{NoClientAuth, ServerConfig};
use async_std::net::TcpListener;
use async_std::path::PathBuf;
use async_std::task;
use futures::AsyncWriteExt;
use futures::StreamExt;
use log;
use rustls_acme::{acme::LETS_ENCRYPT_STAGING_DIRECTORY, ResolvesServerCertUsingAcme, TlsAcceptor};
use std::error::Error;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "server_simple", about = "Simple TLS server example.")]
struct Opt {
    /// Domain
    #[structopt(short)]
    domain: String,

    /// Cache directory
    #[structopt(short, parse(from_os_str))]
    cache_dir: Option<PathBuf>,

    #[structopt(short, long, default_value = "443")]
    port: u16,
}

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();
    let opt = Opt::from_args();

    let resolver = ResolvesServerCertUsingAcme::new();
    let config = ServerConfig::new(NoClientAuth::new());
    let acceptor = TlsAcceptor::new(config, resolver.clone());

    let domains = vec![opt.domain.clone()];
    let cache_dir = opt.cache_dir.clone();
    task::spawn(async move {
        resolver
            .run(LETS_ENCRYPT_STAGING_DIRECTORY, domains, cache_dir)
            .await;
    });

    task::block_on(async move {
        serve(acceptor).await.unwrap();
    });
}

async fn serve(acceptor: TlsAcceptor) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("192.168.0.103:4433").await?;
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        task::spawn(async move {
            if let Some(mut tls) = acceptor.accept(tcp.unwrap()).await.unwrap() {
                tls.write_all(HELLO).await.unwrap();
            }
        });
    }
    Ok(())
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
