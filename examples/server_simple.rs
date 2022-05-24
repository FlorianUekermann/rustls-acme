use clap::Parser;
use futures::AsyncWriteExt;
use futures::StreamExt;
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

    let tcp_listener = TcpListener::bind(format!("[::]:{}", args.port))
        .await
        .unwrap();

    let mut tls_incoming = AcmeConfig::new(args.domains.clone())
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)).collect())
        .cache_option(args.cache.clone().map(DirCache::new))
        .incoming(tcp_listener.incoming());

    while let Some(tls) = tls_incoming.next().await {
        let mut tls = tls.unwrap();
        spawn(async move {
            tls.write_all(HELLO).await.unwrap();
            tls.close().await.unwrap();
        })
        .detach()
    }
    unreachable!()
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
