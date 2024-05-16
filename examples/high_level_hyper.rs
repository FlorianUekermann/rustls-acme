use clap::Parser;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use tokio_stream::wrappers::TcpListenerStream;
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

    let tcp_listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, args.port)).await.unwrap();
    let tcp_incoming = TcpListenerStream::new(tcp_listener);

    let mut tls_incoming = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .tokio_incoming(tcp_incoming, Vec::new());

    while let Some(tls) = tls_incoming.next().await {
        let tls = tls.unwrap();
        tokio::spawn(async move {
            use hyper::{server::conn::http1, service::service_fn};
            use hyper_util::rt::TokioIo;
            let tls = TokioIo::new(tls);
            if let Err(err) = http1::Builder::new().serve_connection(tls, service_fn(hello)).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
    unreachable!()
}

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use std::convert::Infallible;

async fn hello(_: Request<impl hyper::body::Body>) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello Tls!"))))
}
