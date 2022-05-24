use async_rustls::rustls::Session;
use async_rustls::TlsAcceptor;
use clap::Parser;
use futures::AsyncWriteExt;
use futures::StreamExt;
use rustls_acme::acme::ACME_TLS_ALPN_NAME;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use smol::net::TcpListener;
use smol::spawn;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    /// Domains
    #[clap(short, required = true)]
    domains: Vec<String>,

    /// Contact info
    #[clap(short)]
    email: Vec<String>,

    /// Cache directory
    #[clap(short, parse(from_os_str))]
    cache: Option<PathBuf>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    prod: Option<bool>,

    #[clap(short, long, default_value = "443")]
    port: u16,
}

#[smol_potat::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains.clone())
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)).collect())
        .cache_option(args.cache.clone().map(DirCache::new))
        .state();
    let acceptor = state.acceptor();

    spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    })
    .detach();

    serve(acceptor, args.port).await;
}

async fn serve(acceptor: TlsAcceptor, port: u16) {
    let listener = TcpListener::bind(format!("[::]:{}", port)).await.unwrap();
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        spawn(async move {
            let mut tls = acceptor.accept(tcp.unwrap()).await.unwrap();
            match tls.get_ref().1.get_alpn_protocol() {
                Some(ACME_TLS_ALPN_NAME) => log::info!("received TLS-ALPN-01 validation request"),
                _ => tls.write_all(HELLO).await.unwrap(),
            }
            tls.close().await.unwrap();
        })
        .detach();
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
