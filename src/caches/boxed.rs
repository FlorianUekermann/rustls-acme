use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use std::fmt::Debug;

pub struct BoxedErrCache<T: Send + Sync> {
    inner: T,
}

impl<T: Send + Sync> BoxedErrCache<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait]
impl<T: CertCache> CertCache for BoxedErrCache<T>
where
    <T as CertCache>::EC: 'static,
{
    type EC = Box<dyn Debug>;
    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        match self.inner.load_cert(domains, directory_url).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(Box::new(err)),
        }
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        match self.inner.store_cert(domains, directory_url, cert).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(Box::new(err)),
        }
    }
}

#[async_trait]
impl<T: AccountCache> AccountCache for BoxedErrCache<T>
where
    <T as AccountCache>::EA: 'static,
{
    type EA = Box<dyn Debug>;
    async fn load_account(&self, contact: &[String]) -> Result<Option<Vec<u8>>, Self::EA> {
        match self.inner.load_account(contact).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(Box::new(err)),
        }
    }

    async fn store_account(&self, contact: &[String], account: &[u8]) -> Result<(), Self::EA> {
        match self.inner.store_account(contact, account).await {
            Ok(ok) => Ok(ok),
            Err(err) => Err(Box::new(err)),
        }
    }
}
