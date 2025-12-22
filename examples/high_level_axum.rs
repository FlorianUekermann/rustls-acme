use axum::{routing::get, Router};
use clap::Parser;
use rustls_acme::acme::{Account, AcmeError, Directory, LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY};
use rustls_acme::caches::DirCache;
use rustls_acme::{AccountCache, RuntimeResolver};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// Dependencies for key generation (ring)
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

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
    #[clap(long)]
    prod: bool,

    #[clap(short, long, default_value = "44300")]
    port: u16,
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let directory_url = if args.prod {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
    } else {
        LETS_ENCRYPT_STAGING_DIRECTORY
    };

    // 1. Setup Cache
    let cache_path = args.cache.unwrap_or_else(|| PathBuf::from("./rustls_acme_cache"));
    let cache = DirCache::new(cache_path);

    // 2. Setup Upstream Client Config
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store) // In real app, load webpki-roots
            .with_no_client_auth(),
    );

    // 3. Discover Directory
    let directory = Directory::discover(&client_config, directory_url)
        .await
        .expect("Could not retrieve acme directory");

    // 4. Load or Generate Account Key
    let contact: Vec<String> = args.email.iter().map(|e| format!("mailto:{}", e)).collect();

    let keypair = if let Some(keypair) = cache
        .load_account(&contact, directory_url)
        .await
        .ok()
        .flatten()
    {
        keypair
    } else {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("failed to generate keypair");
        cache
            .store_account(&contact, directory_url, pkcs8_bytes.as_ref())
            .await
            .expect("failed to store account");
        pkcs8_bytes.as_ref().to_vec()
    };

    // 5. Create Account (with Retry Loop)
    let account = loop {
        match Account::create_with_keypair(
            &client_config,
            directory.clone(),
            &contact,
            &keypair,
        )
            .await
        {
            Ok(account) => break account,
            Err(AcmeError::HttpRequest(res)) => {
                log::error!("Waiting 30min for acme to clear error: {res}");
                sleep(Duration::from_secs(30 * 60)).await;
            }
            Err(e) => panic!("Could not create acme account: {}", e),
        }
    };

    // 6. Create Resolver
    let (resolver, updater) = RuntimeResolver::new_with_updater(
        account,
        client_config,
        directory_url.to_string(),
        cache,
    )
        .await
        .expect("Failed to create resolver");

    // 7. Register Domains
    for domain in &args.domains {
        resolver
            .get_or_create_domain_handle([domain.clone()], true)
            .await
            .expect("Could not get certificates");
    }

    // 8. Spawn Updater
    tokio::spawn(updater);

    // 9. Configure Rustls Server
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

    // 10. Create Axum Acceptor
    // Note: requires `axum` feature in rustls-acme
    let acceptor = resolver.axum_acceptor(Arc::new(rustls_config));

    let app = Router::new().route("/", get(hello));

    log::info!("Server listening on https://[::]:{}", args.port);

    // 11. Serve using axum-server
    axum_server::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.port)))
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn hello() -> &'static str {
    "Hello Secure World!"
}