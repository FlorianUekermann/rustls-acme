use crate::acme::Account;
use crate::rework::order::order;
use crate::{CertParseError, OrderError};
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use rustls::sign::{any_ecdsa_type, CertifiedKey};
use rustls::{Certificate, ClientConfig, PrivateKey};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use x509_parser::certificate::Validity;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

pub struct FinalCertificate {
    validity: [DateTime<Utc>; 2],
    pem: Bytes,
    certificate: Arc<CertifiedKey>,
}

pub struct InnerCertificateHandle {
    automatic: bool,
    domains: Arc<HashSet<String>>,
    auth_keys: HashMap<String, Arc<CertifiedKey>>,
    certificate: Option<FinalCertificate>,
}

impl InnerCertificateHandle {
    fn from_domains<S: Into<String>>(domains: impl IntoIterator<Item = S>, automatic: bool) -> Self {
        Self {
            automatic,
            domains: Arc::new(domains.into_iter().map(Into::into).collect()),
            auth_keys: Default::default(),
            certificate: None,
        }
    }
    fn from_pem(pem: impl Into<Bytes>, automatic: bool) -> Result<Self, CertParseError> {
        let pem = pem.into();
        let mut pems = pem::parse_many(&pem)?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk = any_ecdsa_type(&PrivateKey(pems.remove(0).contents)).map_err(|_| CertParseError::InvalidPrivateKey)?;
        let cert_chain: Vec<Certificate> = pems.into_iter().map(|p| Certificate(p.contents)).collect();
        let (_, x509) = parse_x509_certificate(&cert_chain.first().unwrap().0).map_err(CertParseError::X509)?;
        let Validity { not_before, not_after } = x509.validity();
        let validity = [not_before, not_after].map(|t| Utc.timestamp_opt(t.timestamp(), 0).earliest().unwrap());
        let domains: HashSet<_> = x509
            .subject_alternative_name()
            .ok()
            .flatten()
            .iter()
            .flat_map(|it| {
                it.value.general_names.iter().filter_map(|it| {
                    if let GeneralName::DNSName(dns) = it {
                        Some(String::from(*dns))
                    } else {
                        None
                    }
                })
            })
            .collect();
        drop(x509);
        let certificate = Arc::new(CertifiedKey::new(cert_chain, pk));
        if domains.is_empty() {
            return Err(CertParseError::NoDns);
        }
        Ok(Self {
            automatic,
            domains: Arc::new(domains),
            auth_keys: Default::default(),
            certificate: Some(FinalCertificate { validity, certificate, pem }),
        })
    }
}

pub struct CertificateHandle(Mutex<InnerCertificateHandle>);

impl CertificateHandle {
    pub fn from_domains<S: Into<String>>(domains: impl IntoIterator<Item = S>, automatic: bool) -> Self {
        Self(Mutex::new(InnerCertificateHandle::from_domains(domains, automatic)))
    }
    pub fn from_pem(pem: impl Into<Bytes>, automatic: bool) -> Result<Self, CertParseError> {
        Ok(Self(Mutex::new(InnerCertificateHandle::from_pem(pem, automatic)?)))
    }

    pub fn use_pem(&self, pem: impl Into<Bytes>, automatic: bool) -> Result<(), CertParseError> {
        let inner = InnerCertificateHandle::from_pem(pem, automatic)?;
        if self.domains() != inner.domains {
            return Err(CertParseError::InvalidDns);
        }
        *self.0.lock().unwrap() = inner;
        Ok(())
    }

    pub fn domains(&self) -> Arc<HashSet<String>> {
        self.0.lock().unwrap().domains.clone()
    }
    pub fn get_final_certificate(&self) -> Option<Arc<CertifiedKey>> {
        Some(self.0.lock().unwrap().certificate.as_ref()?.certificate.clone())
    }
    pub fn get_challenge_certificate(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.0.lock().unwrap().auth_keys.get(domain).cloned()
    }

    pub fn replace(&self, other: InnerCertificateHandle) {
        let mut lock = self.0.lock().unwrap();
        *lock = other;
    }

    pub fn set_auth_key(&self, domain: impl Into<String>, key: Arc<CertifiedKey>) {
        let mut lock = self.0.lock().unwrap();
        lock.auth_keys.insert(domain.into(), key);
    }

    pub async fn order(&self, account: &Account, client_config: &Arc<ClientConfig>) -> Result<(), OrderError> {
        order(account, client_config, self).await
    }
    pub fn get_should_update(&self) -> CertificateShouldUpdate {
        let lock = self.0.lock().unwrap();
        if !lock.automatic {
            return CertificateShouldUpdate::Ignore;
        }
        let Some(cert) = &lock.certificate else {
            return CertificateShouldUpdate::Renew;
        };
        let renew_after = cert.validity[1] - (cert.validity[1] - cert.validity[0]) / 3;
        if renew_after < Utc::now() {
            CertificateShouldUpdate::Renew
        } else {
            CertificateShouldUpdate::RenewLater(renew_after)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CertificateShouldUpdate {
    Renew,
    RenewLater(DateTime<Utc>),
    Ignore,
}

impl CertificateShouldUpdate {
    pub fn ignored(self) -> Option<Self> {
        match self {
            Self::Ignore => None,
            other => Some(other),
        }
    }
}
