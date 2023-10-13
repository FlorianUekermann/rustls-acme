use clap::Parser;
use rustls_acme::caches::DirCache;
use rustls_acme::{is_tls_alpn_challenge, AcmeConfig};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::StreamExt;

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
    prod: bool,

    #[clap(short, long, default_value = "443")]
    port: u16,
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .state();
    let challenge_rustls_config = state.challenge_rustls_config();
    let default_rustls_config = state.default_rustls_config();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port)).await.unwrap();
    loop {
        let (tcp, _) = listener.accept().await.unwrap();
        let challenge_rustls_config = challenge_rustls_config.clone();
        let default_rustls_config = default_rustls_config.clone();

        tokio::spawn(async move {
            let start_handshake = LazyConfigAcceptor::new(Default::default(), tcp).await.unwrap();

            if is_tls_alpn_challenge(&start_handshake.client_hello()) {
                log::info!("received TLS-ALPN-01 validation request");
                let mut tls = start_handshake.into_stream(challenge_rustls_config).await.unwrap();
                tls.shutdown().await.unwrap();
            } else {
                let mut tls = start_handshake.into_stream(default_rustls_config).await.unwrap();
                tls.write_all(HELLO).await.unwrap();
                tls.shutdown().await.unwrap();
            }
        });
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
