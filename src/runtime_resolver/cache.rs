use crate::caches::TestCache;
use crate::{CertCache, CertificateInfo};
use async_trait::async_trait;
pub use bytes::Bytes;
use std::fmt::Debug;

#[derive(Clone)]
pub struct CachedCertificate {
    pub automatic: bool,
    pub pem: Bytes,
}
#[async_trait]
pub trait MultiCertCache: Send + Sync {
    type EC: Debug;
    async fn load_all_certs(&self) -> Result<Vec<CachedCertificate>, Self::EC>;
    async fn load_cert(&self, domains: &[String], directory_url: &str) -> Result<Option<CachedCertificate>, Self::EC>;
    async fn store_cert(&self, cert: &CertificateInfo, directory_url: &str) -> Result<(), Self::EC>;
}

#[async_trait]
impl<EC: Debug, EA: Debug> MultiCertCache for TestCache<EC, EA> {
    type EC = EC;

    async fn load_all_certs(&self) -> Result<Vec<CachedCertificate>, Self::EC> {
        Ok(vec![])
    }

    async fn load_cert(&self, domains: &[String], directory_url: &str) -> Result<Option<CachedCertificate>, Self::EC> {
        CertCache::load_cert(self, domains, directory_url).await.map(|it| {
            it.map(|it| CachedCertificate {
                automatic: false,
                pem: it.into(),
            })
        })
    }

    async fn store_cert(&self, cert: &CertificateInfo, directory_url: &str) -> Result<(), Self::EC> {
        CertCache::store_cert(self, &cert.domains, directory_url, &cert.pem).await
    }
}
