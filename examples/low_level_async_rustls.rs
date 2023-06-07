use async_rustls::LazyConfigAcceptor;
use clap::Parser;
use futures::AsyncWriteExt;
use futures::StreamExt;
use rustls::ServerConfig;
use rustls_acme::acme::ACME_TLS_ALPN_NAME;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use smol::net::TcpListener;
use smol::spawn;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::Arc;

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
    let resolver = state.resolver();

    spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    })
    .detach();

    let rustls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let mut acme_rustls_config = rustls_config.clone();
    acme_rustls_config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
    let rustls_config = Arc::new(rustls_config);
    let acme_rustls_config = Arc::new(acme_rustls_config);

    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port)).await.unwrap();
    while let Some(tcp) = listener.incoming().next().await {
        let rustls_config = rustls_config.clone();
        let acme_rustls_config = acme_rustls_config.clone();

        spawn(async move {
            let start_handshake = LazyConfigAcceptor::new(Default::default(), tcp.unwrap()).await.unwrap();

            let is_validation = start_handshake.client_hello().alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME]);
            if is_validation {
                log::info!("received TLS-ALPN-01 validation request");
                let mut tls = start_handshake.into_stream(acme_rustls_config).await.unwrap();
                tls.close().await.unwrap();
                return;
            }

            let mut tls = start_handshake.into_stream(rustls_config).await.unwrap();
            tls.write_all(HELLO).await.unwrap();
            tls.close().await.unwrap();
        })
        .detach();
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
