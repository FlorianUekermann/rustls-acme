use std::fmt::Debug;
use crate::crypto::digest::{Context, SHA256};
use crate::{AccountCache, CachedCertificate, CertCache, CertificateInfo, MultiCertCache};
use async_trait::async_trait;
use base64::prelude::*;
use blocking::unblock;
use futures::future::join_all;
use std::io::ErrorKind;
use std::path::Path;

#[derive(Debug)]
pub struct DirCache<P: AsRef<Path> + Send + Sync> {
    inner: P,
}

impl<P: AsRef<Path> + Send + Sync> DirCache<P> {
    pub fn new(dir: P) -> Self {
        Self { inner: dir }
    }
    async fn read_if_exist(&self, file: impl AsRef<Path>) -> Result<Option<Vec<u8>>, std::io::Error> {
        let path = self.inner.as_ref().join(file);
        match unblock(move || std::fs::read(&path)).await {
            Ok(content) => Ok(Some(content)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }
    async fn write(&self, file: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<(), std::io::Error> {
        let path = self.inner.as_ref().to_owned();
        unblock(move || std::fs::create_dir_all(&path)).await?;
        let path = self.inner.as_ref().join(file);
        let contents = contents.as_ref().to_owned();
        unblock(move || std::fs::write(path, contents)).await
    }
    fn cached_account_file_name(contact: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for el in contact {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = BASE64_URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_account_{hash}")
    }
    fn cached_cert_file_name(domains: &[String], directory_url: impl AsRef<str>) -> String {
        let mut ctx = Context::new(&SHA256);
        for domain in domains {
            ctx.update(domain.as_ref());
            ctx.update(&[0])
        }
        ctx.update(directory_url.as_ref().as_bytes());
        let hash = BASE64_URL_SAFE_NO_PAD.encode(ctx.finish());
        format!("cached_cert_{hash}")
    }
}

#[async_trait]
impl<P: AsRef<Path> + Send + Sync> CertCache for DirCache<P> {
    type EC = std::io::Error;
    async fn load_cert(&self, domains: &[String], directory_url: &str) -> Result<Option<Vec<u8>>, Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url);
        self.read_if_exist(file_name).await
    }
    async fn store_cert(&self, domains: &[String], directory_url: &str, cert: &[u8]) -> Result<(), Self::EC> {
        let file_name = Self::cached_cert_file_name(domains, directory_url);
        self.write(file_name, cert).await
    }
}

#[async_trait]
impl<P: AsRef<Path> + Send + Sync> AccountCache for DirCache<P> {
    type EA = std::io::Error;
    async fn load_account(&self, contact: &[String], directory_url: &str) -> Result<Option<Vec<u8>>, Self::EA> {
        let file_name = Self::cached_account_file_name(contact, directory_url);
        self.read_if_exist(file_name).await
    }

    async fn store_account(&self, contact: &[String], directory_url: &str, account: &[u8]) -> Result<(), Self::EA> {
        let file_name = Self::cached_account_file_name(contact, directory_url);
        self.write(file_name, account).await
    }
}

#[async_trait]
impl<T: AsRef<Path> + Send + Sync> MultiCertCache for DirCache<T> {
    type EC = std::io::Error;

    async fn load_all_certs(&self) -> Result<Vec<CachedCertificate>, Self::EC> {
        let path = self.inner.as_ref().join(self.inner.as_ref());
        let paths: Vec<_> = unblock(move || {
            let dir = match std::fs::read_dir(&path) {
                Ok(dir) => dir,
                Err(err) => {
                    return match err.kind() {
                        ErrorKind::NotFound => Ok(vec![]),
                        _ => Err(err.into()),
                    }
                }
            };
            Result::<_, std::io::Error>::Ok(dir.filter_map(|it| it.ok().map(|it| it.path())).collect())
        })
        .await?;
        Ok(join_all(paths.into_iter().map(|path| unblock(move || std::fs::read(&path))))
            .await
            .into_iter()
            .filter_map(|it| it.ok())
            .map(|it| CachedCertificate {
                automatic: true,
                pem: it.into(),
            })
            .collect())
    }

    async fn load_cert(&self, domains: &[String], directory_url: &str) -> Result<Option<CachedCertificate>, Self::EC> {
        let file_name = Self::cached_cert_file_name(&domains, directory_url);
        Ok(self.read_if_exist(file_name).await?.map(|it| CachedCertificate {
            automatic: true,
            pem: it.into(),
        }))
    }

    async fn store_cert(&self, cert: &CertificateInfo, directory_url: &str) -> Result<(), Self::EC> {
        let file_name = Self::cached_cert_file_name(&cert.domains, directory_url);
        self.write(file_name, &cert.pem).await
    }
}
