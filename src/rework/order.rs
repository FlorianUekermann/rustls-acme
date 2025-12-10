use crate::acme::{Account, AcmeError, Order, OrderStatus};
use crate::rework::auth::authorize_all;
use crate::{CertificateHandle, CertificateInfo, OrderError};
use async_io::Timer;

use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::sync::Arc;
use std::time::Duration;
use futures_rustls::rustls::ClientConfig;

struct OrderProcess<'a> {
    account: &'a Account,
    client_config: &'a Arc<ClientConfig>,
    handle: &'a CertificateHandle,
    order: Order,
    url: String,
    params: CertificateParams,
    key_pair: KeyPair
}
impl<'a> OrderProcess<'a> {
    async fn new(account: &'a Account, client_config: &'a Arc<ClientConfig>, handle: &'a CertificateHandle) -> Result<OrderProcess<'a>, AcmeError> {
        log::info!("starting order");
        let (url, order) = account.new_order(client_config, handle.domains().iter().cloned().collect()).await?;
        log::debug!("order: {:?}", order);
        let mut params = CertificateParams::new(handle.domains())?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        Ok(Self {
            client_config,
            account,
            url,
            order,
            handle,
            params,
            key_pair
        })
    }

    async fn update(mut self) -> Result<OrderProcess<'a>, AcmeError> {
        log::debug!("updating order");
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

    async fn authorize(self) -> Result<OrderProcess<'a>, OrderError> {
        authorize_all(&self.client_config, &self.handle, &self.account, self.order.authorizations.iter()).await?;
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
        let csr = self.params.serialize_request(&self.key_pair)?;
        self.order = self.account.finalize(&self.client_config, &self.order.finalize, csr.der()).await?;
        Ok(self)
    }

    async fn to_certificate(&self, certificate_url: &str) -> Result<CertificateInfo, OrderError> {
        log::info!("download certificate");
        let pem: String = [
            &self.key_pair.serialize_pem(),
            "\n",
            &self.account.certificate(&self.client_config, certificate_url).await?,
        ]
        .concat();
        Ok(self.handle.use_pem(pem, true)?)
    }
}

pub async fn order(account: &Account, client_config: &Arc<ClientConfig>, handle: &CertificateHandle) -> Result<CertificateInfo, OrderError> {
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
