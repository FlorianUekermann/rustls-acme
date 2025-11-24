use actix_web::{web, App, HttpResponse, HttpServer};
use clap::Parser;
use futures::StreamExt;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use std::{path::PathBuf, sync::Arc};

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

#[actix_web::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .state();
    let challenge_rustls_config = Arc::into_inner(state.challenge_rustls_config()).unwrap();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    HttpServer::new(move || App::new().default_service(web::get().to(HttpResponse::Ok)))
        .bind_rustls_0_23(("0.0.0.0", args.port), challenge_rustls_config)
        .unwrap()
        .run()
        .await
        .unwrap();
}
