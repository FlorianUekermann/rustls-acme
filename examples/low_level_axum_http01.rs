use axum::extract::State;
use axum::{routing::get, Router};
use axum_server::bind;
use clap::Parser;
use rustls_acme::caches::DirCache;
use rustls_acme::tower::TowerHttp01ChallengeService;
use rustls_acme::AcmeConfig;
use rustls_acme::UseChallenge::Http01;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use tokio::try_join;
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

    #[clap(long, default_value = "443")]
    https_port: u16,

    #[clap(long, default_value = "80")]
    http_port: u16,
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .challenge_type(Http01)
        .state();
    let acceptor = state.axum_acceptor(state.default_rustls_config());
    let acme_challenge_tower_service: TowerHttp01ChallengeService = state.http01_challenge_tower_service();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    let http_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.http_port));
    let https_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.https_port));

    let app = Router::new()
        .route("/", get(move |State(t): State<&'static str>| async move { format!("Hello {t}!") }))
        .route_service("/.well-known/acme-challenge/{challenge_token}", acme_challenge_tower_service);

    let http_future = bind(http_addr).serve(app.clone().with_state("Tcp").into_make_service());
    let https_future = bind(https_addr).acceptor(acceptor).serve(app.with_state("Tls").into_make_service());
    try_join!(https_future, http_future).unwrap();
}
