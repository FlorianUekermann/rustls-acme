//! rustls-acme is an easy-to-use, async compatible ACME client library for rustls.
//! The validation mechanism used is tls-alpn-01, which allows serving acme challenge responses and
//! regular TLS traffic on the same port.
//!
//! The goal is to provide TLS serving and certificate management in one simple function,
//! in a way that is compatible with [Let's Encrypt](https://letsencrypt.org/).
//!
//! To use rustls-acme add the following lines to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rustls-acme = "*"
//! ```
//!
//! ## High-level API
//!
//! The high-level API consinsts of a single function: bind_listen_serve, which takes care of
//! aquisition and renewal of signed certificates as well as accepting TLS connections and handing
//! over the resulting TLS stream to a user provided handler function.
//!
//! ```rust,ignore
//! use rustls_acme::*;
//! use async_std::prelude::*;
//! use simple_logger::SimpleLogger;
//!
//! const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
//! Content-Length: 11
//! Content-Type: text/plain; charset=utf-8
//!
//! Hello Tls!"#;
//!
//! #[async_std::main]
//! async fn main() {
//!     SimpleLogger::new().with_level(log::LevelFilter::Info).init().unwrap();
//!
//!     let tls_handler = |mut tls: TlsStream| async move {
//!         if let Err(err) = tls.write_all(HELLO).await {
//!             log::error!("{:?}", err);
//!        }
//!     };
//!
//!     rustls_acme::bind_listen_serve(
//!         "0.0.0.0:443",
//!         acme::LETS_ENCRYPT_STAGING_DIRECTORY,
//!         vec!["example.com".to_string()],
//!         Some("/tmp/cert_cache"),
//!         tls_handler,
//!     ).await.unwrap();
//! }
//! ```
//!
//! The server_simple example is a "Hello Tls!" server similar to the one above which accepts
//! domain, port and cache directory parameters.
//!
//! Note that all examples use the let's encrypt staging directory. The production directory imposes
//! string rate limits, which are easily exhausted accidentally during testing and development.
//! For testing with the staging directory you may open
//! `https://<your domain>:<port>` in a browser that allows TLS connection to servers signed by an
//! untrusted CA (in Firefox click "Advanced..." -> "Accept the Risk and Continue").
//!
//! Due to limitations in rustls and the futures ecosystems in Rust at the moment, the simple API
//! depends on the async-std runtime and spawns a single task at startup. (Ideas how to avoid this
//! are welcome.)
//!
//! ## Lower-level Rustls API
//!
//! rustls-acme relies heavily on rustls and async-rustls. In particular, the
//! rustls::ResolvesServerCert trait is used to allow domain validation and tls serving via a single
//! tcp listener. See the server_runtime_indendent example on how to use the lower-level API
//! directly with rustls. This does not use the async-std runtime and allows users to run the
//! certificate aquisition and renewal task any way they like.
//!
//! ## Account and certificate caching
//!
//! A production server using the let's encrypt production directory must implement both account and
//! certificate caching to avoid exhausting the let's encrypt API rate limits.
//!
//! ## The acme module
//!
//! The underlying implementation of an async acme client may be useful to others and is exposed as
//! a module. It is incomplete (contributions welcome) and not covered by any stability
//! promises.
//!
//! ## Special thanks
//!
//! This crate was inspired by the [autocert](https://golang.org/x/crypto/acme/autocert/)
//! package for [Go](https://golang.org).
//!
//! This crate builds on the excellent work of the authors of
//! [rustls](https://github.com/ctz/rustls),
//! [async-rustls](https://github.com/smol-rs/async-rustls),
//! [async-std](https://github.com/async-rs/async-std),
//! and many others.
//!

mod acceptor;
pub mod acme;
mod https_helper;
mod jose;
mod persist;
mod resolver;
mod simple;

pub use acceptor::*;
use https_helper::*;
use jose::*;
use persist::*;
pub use resolver::*;
pub use simple::*;
