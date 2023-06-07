use crate::{AccountCache, CertCache};
use async_trait::async_trait;
use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::atomic::AtomicPtr;
use std::sync::Arc;

/// Test cache, which generates certificates for ACME incompatible test environments.
/// ```rust
/// # use rustls_acme::{AcmeConfig};
/// # use rustls_acme::caches::{DirCache, TestCache};
/// # let test_environment = true;
/// let mut config = AcmeConfig::new(["example.com"])
///     .cache(DirCache::new("./cache"));
/// if test_environment {
///     config = config.cache(TestCache::new());
/// }
/// ```
#[derive(Clone)]
pub struct TestCache<EC: Debug = std::io::Error, EA: Debug = std::io::Error> {
    ca_cert: Arc<rcgen::Certificate>,
    ca_pem: Arc<String>,
    _cert_error: PhantomData<AtomicPtr<Box<EC>>>,
    _account_error: PhantomData<AtomicPtr<Box<EA>>>,
}

impl<EC: Debug, EA: Debug> TestCache<EC, EA> {
    pub fn new() -> Self {
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, "US");
        distinguished_name.push(DnType::OrganizationName, "Test CA");
        distinguished_name.push(DnType::CommonName, "Test CA");
        params.distinguished_name = distinguished_name;
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(3000, 1, 1);

        let ca_cert = rcgen::Certificate::from_params(params).unwrap();
        let ca_pem = ca_cert.serialize_pem().unwrap();
        Self {
            ca_cert: ca_cert.into(),
            ca_pem: ca_pem.into(),
            _cert_error: Default::default(),
            _account_error: Default::default(),
        }
    }
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
}

#[async_trait]
impl<EC: Debug, EA: Debug> CertCache for TestCache<EC, EA> {
    type EC = EC;
    async fn load_cert(&self, domains: &[String], _directory_url: &str) -> Result<Option<Vec<u8>>, Self::EC> {
        let mut params = CertificateParams::new(domains);
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Test Cert");
        params.distinguished_name = distinguished_name;
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(3000, 1, 1);
        let cert = match rcgen::Certificate::from_params(params) {
            Ok(cert) => cert,
            Err(err) => {
                log::error!("test cache: generation error: {:?}", err);
                return Ok(None);
            }
        };
        let cert_pem = match cert.serialize_pem_with_signer(&self.ca_cert) {
            Ok(pem) => pem,
            Err(err) => {
                log::error!("test cache: signing error: {:?}", err);
                return Ok(None);
            }
        };

        let pem = [&cert.serialize_private_key_pem(), "\n", &cert_pem, "\n", &self.ca_pem].concat();
        Ok(Some(pem.into_bytes()))
    }
    async fn store_cert(&self, _domains: &[String], _directory_url: &str, _cert: &[u8]) -> Result<(), Self::EC> {
        log::info!("test cache configured, could not store certificate");
        Ok(())
    }
}

#[async_trait]
impl<EC: Debug, EA: Debug> AccountCache for TestCache<EC, EA> {
    type EA = EA;
    async fn load_account(&self, _contact: &[String], _directory_url: &str) -> Result<Option<Vec<u8>>, Self::EA> {
        log::info!("test cache configured, could not load account");
        Ok(None)
    }
    async fn store_account(&self, _contact: &[String], _directory_url: &str, _account: &[u8]) -> Result<(), Self::EA> {
        log::info!("test cache configured, could not store account");
        Ok(())
    }
}
