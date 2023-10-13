use rustls::server::ClientHello;

use crate::acme::ACME_TLS_ALPN_NAME;

/// Returns `true` if the client_hello indicates a tls-alpn-01 challenge connection.
pub fn is_tls_alpn_challenge(client_hello: &ClientHello) -> bool {
    return client_hello.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME]);
}
