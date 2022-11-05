use clap::Parser;
use futures::AsyncWriteExt;
use futures::StreamExt;
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeAcceptor, AcmeConfig};
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

    #[cfg(feature = "rustls-native-certs")]
    /// Custom acme directory
    #[clap(long)]
    directory: Option<String>,


    #[clap(short, long, default_value = "443")]
    port: u16,
}

#[smol_potat::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let acme_config = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new));
    #[cfg(feature = "rustls-native-certs")]
    let acme_config = match args.directory {
        Some(dir) => acme_config.directory(&dir),
        None => acme_config.directory_lets_encrypt(args.prod),
    };
    #[cfg(not(feature = "rustls-native-certs"))]
    let acme_config = acme_config.directory_lets_encrypt(args.prod);
    let mut state = acme_config.state();
    let rustls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
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

    serve(acceptor, Arc::new(rustls_config), args.port).await;
}

async fn serve(acceptor: AcmeAcceptor, rustls_config: Arc<ServerConfig>, port: u16) {
    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();

    while let Some(tcp) = listener.incoming().next().await {
        let rustls_config = rustls_config.clone();
        let accept_future = acceptor.accept(tcp.unwrap());

        spawn(async move {
            match accept_future.await.unwrap() {
                None => log::info!("received TLS-ALPN-01 validation request"),
                Some(start_handshake) => {
                    let mut tls = start_handshake.into_stream(rustls_config).await.unwrap();
                    tls.write_all(HELLO).await.unwrap();
                    tls.close().await.unwrap();
                }
            }
        })
        .detach();
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
