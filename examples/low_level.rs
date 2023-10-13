use clap::Parser;
use futures::AsyncWriteExt;
use futures::StreamExt;
use futures_rustls::LazyConfigAcceptor;
use rustls_acme::caches::DirCache;
use rustls_acme::is_tls_alpn_challenge;
use rustls_acme::AcmeConfig;
use smol::net::TcpListener;
use smol::spawn;
use std::net::Ipv6Addr;
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
    prod: bool,

    #[clap(short, long, default_value = "443")]
    port: u16,
}

#[smol_potat::main]
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

    spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    })
    .detach();

    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port)).await.unwrap();
    while let Some(tcp) = listener.incoming().next().await {
        let challenge_rustls_config = challenge_rustls_config.clone();
        let default_rustls_config = default_rustls_config.clone();

        spawn(async move {
            let start_handshake = LazyConfigAcceptor::new(Default::default(), tcp.unwrap()).await.unwrap();

            if is_tls_alpn_challenge(&start_handshake.client_hello()) {
                log::info!("received TLS-ALPN-01 validation request");
                let mut tls = start_handshake.into_stream(challenge_rustls_config).await.unwrap();
                tls.close().await.unwrap();
            } else {
                let mut tls = start_handshake.into_stream(default_rustls_config).await.unwrap();
                tls.write_all(HELLO).await.unwrap();
                tls.close().await.unwrap();
            }
        })
        .detach();
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
