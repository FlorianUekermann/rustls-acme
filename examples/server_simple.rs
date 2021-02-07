use async_std::path::PathBuf;
use async_std::task;
use futures::AsyncWriteExt;
use rustls_acme::{acme::LETS_ENCRYPT_STAGING_DIRECTORY, bind_listen_serve, TlsStream};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "server_simple", about = "Simple TLS server example.")]
struct Opt {
    /// Domain
    #[structopt(short)]
    domain: String,

    /// Cache directory
    #[structopt(short, parse(from_os_str))]
    cache_dir: Option<PathBuf>,

    #[structopt(short, long, default_value = "443")]
    port: u16,
}

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();
    let opt = Opt::from_args();

    task::block_on(async {
        bind_listen_serve(
            format!("0.0.0.0:{}", opt.port),
            LETS_ENCRYPT_STAGING_DIRECTORY,
            vec![opt.domain.clone()],
            opt.cache_dir.clone(),
            hello,
        )
        .await
        .unwrap();
    })
}

async fn hello(mut tls: TlsStream) {
    if let Err(err) = tls.write_all(HELLO).await {
        log::error!("{:?}", err);
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
