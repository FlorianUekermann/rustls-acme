use crate::acme::{Account, AuthStatus};
use crate::{CertificateHandle, OrderError};
use async_io::Timer;
use futures::future::try_join_all;
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;

pub async fn authorize_all<U: AsRef<str>>(
    ref client_config: &Arc<ClientConfig>,
    ref resolver: &CertificateHandle,
    ref account: &Account,
    urls: impl IntoIterator<Item = U>,
) -> Result<(), OrderError> {
    try_join_all(urls.into_iter().map(|url| authorize(client_config, resolver, account, url)))
        .await
        .map(|_| ())
}
pub async fn authorize(
    client_config: &Arc<ClientConfig>,
    resolver: &CertificateHandle,
    account: &Account,
    url: impl AsRef<str>,
) -> Result<(), OrderError> {
    let url = url.as_ref();
    let auth = account.auth(client_config, url).await?;
    let (domain, challenge_url) = match auth.status {
        AuthStatus::Pending => {
            let domain: &str = &auth.identifier;
            log::info!("trigger challenge for {}", domain);
            let (challenge, auth_key) = account.tls_alpn_01(&auth.challenges, domain)?;
            resolver.set_auth_key(domain, Arc::new(auth_key));
            account.challenge(client_config, &challenge.url).await?;
            (domain, challenge.url.clone())
        }
        AuthStatus::Valid => return Ok(()),
        _ => return Err(OrderError::BadAuth(auth)),
    };
    for i in 0u64..5 {
        Timer::after(Duration::from_secs(1u64 << i)).await;
        let auth = account.auth(client_config, url).await?;
        match auth.status {
            AuthStatus::Pending => {
                log::info!("authorization for {} still pending", &domain);
                account.challenge(client_config, &challenge_url).await?
            }
            AuthStatus::Valid => return Ok(()),
            _ => return Err(OrderError::BadAuth(auth)),
        }
    }
    Err(OrderError::TooManyAttemptsAuth(domain.to_string()))
}
