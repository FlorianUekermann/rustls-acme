use crate::acme::{Account, AcmeError, Order, OrderStatus, SerIdentifier};
use crate::rework::auth::authorize_all;
use crate::{CertificateHandle, OrderError};
use async_io::Timer;
use rcgen::{Certificate, CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;

struct OrderProcess<'a> {
    account: &'a Account,
    client_config: &'a Arc<ClientConfig>,
    handle: &'a CertificateHandle,
    order: Order,
    url: String,
    cert: Certificate,
}
impl<'a> OrderProcess<'a> {
    async fn new(account: &'a Account, client_config: &'a Arc<ClientConfig>, handle: &'a CertificateHandle) -> Result<OrderProcess<'a>, AcmeError> {
        let (url, order) = account.new_order(client_config, handle.domains().iter()).await?;
        let mut params = CertificateParams::new(order.identifiers.iter().map(|it| it.to_string()).collect::<Vec<_>>());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = Certificate::from_params(params)?;
        Ok(Self {
            client_config,
            account,
            url,
            order,
            handle,
            cert,
        })
    }

    async fn update(mut self) -> Result<OrderProcess<'a>, AcmeError> {
        let Self {
            ref account,
            ref client_config,
            order,
            ref url,
            ..
        } = &mut self;
        *order = account.order(client_config, url).await?;
        Ok(self)
    }

    async fn authorize(mut self) -> Result<OrderProcess<'a>, OrderError> {
        authorize_all(&self.client_config, &self.handle, &self.account, self.order.identifiers.iter()).await?;
        log::info!("completed all authorizations");
        Ok(self.update().await?)
    }
    async fn process(mut self) -> Result<OrderProcess<'a>, OrderError> {
        for i in 0u64..10 {
            log::info!("order processing");
            Timer::after(Duration::from_secs(1u64 << i)).await;
            self = self.update().await?;
            if self.order.status != OrderStatus::Processing {
                return Ok(self);
            }
        }
        if self.order.status == OrderStatus::Processing {
            return Err(OrderError::ProcessingTimeout(self.order));
        }
        Ok(self)
    }
    async fn finalize(mut self) -> Result<OrderProcess<'a>, OrderError> {
        log::info!("sending csr");
        let csr = self.cert.serialize_request_der()?;
        self.order = self.account.finalize(&self.client_config, &self.order.finalize, csr).await?;
        Ok(self)
    }

    async fn to_certificate(&self, certificate: &str) -> Result<(), OrderError> {
        log::info!("download certificate");
        let pem: String = [
            &self.cert.serialize_private_key_pem(),
            "\n",
            &self.account.certificate(&self.client_config, certificate).await?,
        ]
        .concat();
        self.handle.use_pem(pem.as_bytes(), true)?;
        return Ok(());
    }
}

pub async fn order(account: &Account, client_config: &Arc<ClientConfig>, handle: &CertificateHandle) -> Result<(), OrderError> {
    let mut this = OrderProcess::new(account, client_config, handle).await?;
    loop {
        match this.order.status {
            OrderStatus::Pending => this = this.authorize().await?,
            OrderStatus::Processing => this = this.process().await?,
            OrderStatus::Ready => this = this.finalize().await?,
            OrderStatus::Valid { ref certificate } => return this.to_certificate(&certificate).await,
            OrderStatus::Invalid => return Err(OrderError::BadOrder(this.order)),
        }
    }
}
