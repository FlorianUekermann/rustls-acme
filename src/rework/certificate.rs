use crate::acme::Account;
use crate::rework::order::order;
use crate::{CertParseError, OrderError};
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use rustls::sign::{any_ecdsa_type, CertifiedKey};
use rustls::{Certificate, ClientConfig, PrivateKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x509_parser::certificate::Validity;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

#[derive(Clone)]
pub struct FinalCertificate {
    validity: [DateTime<Utc>; 2],
    pem: Bytes,
    certificate: Arc<CertifiedKey>,
}

#[derive(Clone)]
pub struct CertificateInfo {
    pub automatic: bool,
    pub domains: Vec<String>,
    pub validity: [DateTime<Utc>; 2],
    pub pem: Bytes,
}

struct InnerCertificateHandle {
    automatic: bool,
    auth_keys: HashMap<String, Arc<CertifiedKey>>,
    certificate: Option<FinalCertificate>,
}

impl InnerCertificateHandle {}

pub struct CertificateHandle {
    inner: Mutex<InnerCertificateHandle>,
    domains: Vec<String>,
}

impl CertificateHandle {
    pub fn from_domains<S: Into<String>>(domains: impl IntoIterator<Item = S>, automatic: bool) -> Self {
        Self {
            inner: Mutex::new(InnerCertificateHandle {
                automatic,
                auth_keys: Default::default(),
                certificate: None,
            }),
            domains: domains.into_iter().map(Into::into).collect(),
        }
        .normalize_domains()
    }

    pub fn from_pem(pem: impl Into<Bytes>, automatic: bool) -> Result<Self, CertParseError> {
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
        let domains: Vec<_> = x509
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
        let inner = InnerCertificateHandle {
            automatic,
            auth_keys: Default::default(),
            certificate: Some(FinalCertificate { validity, certificate, pem }),
        };
        Ok(Self {
            inner: Mutex::new(inner),
            domains,
        }
        .normalize_domains())
    }

    fn normalize_domains(mut self) -> Self {
        self.domains.sort();
        self.domains.dedup();
        self
    }

    pub fn use_pem(&self, pem: impl Into<Bytes>, automatic: bool) -> Result<CertificateInfo, CertParseError> {
        let new = Self::from_pem(pem, automatic)?;
        let info = new.get_info().unwrap();
        self.replace(new)?;
        Ok(info)
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
    pub fn get_certificate(&self) -> Option<Arc<CertifiedKey>> {
        Some(self.inner.lock().unwrap().certificate.as_ref()?.certificate.clone())
    }
    pub fn get_challenge_certificate(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.inner.lock().unwrap().auth_keys.get(domain).cloned()
    }

    pub fn replace(&self, other: Self) -> Result<(), CertParseError> {
        if self.domains != other.domains {
            return Err(CertParseError::InvalidDns);
        }
        *self.inner.lock().unwrap() = other.inner.into_inner().unwrap();
        Ok(())
    }

    pub fn set_auth_key(&self, domain: impl Into<String>, key: Arc<CertifiedKey>) {
        let mut lock = self.inner.lock().unwrap();
        lock.auth_keys.insert(domain.into(), key);
    }

    pub async fn order(&self, account: &Account, client_config: &Arc<ClientConfig>) -> Result<CertificateInfo, OrderError> {
        order(account, client_config, self).await
    }

    pub fn get_info(&self) -> Option<CertificateInfo> {
        let lock = self.inner.lock().unwrap();
        lock.certificate.as_ref().map(|cert| CertificateInfo {
            automatic: lock.automatic,
            domains: self.domains.clone(),
            validity: cert.validity.clone(),
            pem: cert.pem.clone(),
        })
    }

    pub fn get_validity(&self) -> Option<[DateTime<Utc>; 2]> {
        let lock = self.inner.lock().unwrap();
        lock.certificate.as_ref().map(|it| it.validity.clone())
    }

    pub fn get_should_update(&self) -> CertificateShouldUpdate {
        let lock = self.inner.lock().unwrap();
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

    pub fn into_datetime(self) -> Option<DateTime<Utc>> {
        match self {
            CertificateShouldUpdate::Renew => Some(Utc::now()),
            CertificateShouldUpdate::RenewLater(later) => Some(later),
            CertificateShouldUpdate::Ignore => None,
        }
    }
}
