use std::io;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniGuardMode {
    Disable,
    DnsSan,
    Strict,
}

impl SniGuardMode {
    pub fn parse(raw: &str) -> Result<Self, io::Error> {
        let guard = if raw.trim().is_empty() {
            "dns-san"
        } else {
            raw.trim()
        };
        match guard.to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "dns-san" => Ok(Self::DnsSan),
            "strict" => Ok(Self::Strict),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls.sniGuard must be one of: disable, dns-san, strict",
            )),
        }
    }
}

#[derive(Debug)]
pub struct GuardedCertResolver {
    certified_key: Arc<CertifiedKey>,
    mode: SniGuardMode,
    end_entity_der: Vec<u8>,
    has_dns_san: bool,
}

impl GuardedCertResolver {
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
        mode: SniGuardMode,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self, rustls::Error> {
        let certified_key = Arc::new(CertifiedKey::from_der(cert_chain, key_der, provider)?);
        let end_entity_der = certified_key.end_entity_cert()?.as_ref().to_vec();
        let end_entity = CertificateDer::from(end_entity_der.clone());
        let parsed = webpki::EndEntityCert::try_from(&end_entity)
            .map_err(|err| rustls::Error::General(format!("invalid server cert: {err}")))?;
        let has_dns_san = parsed.valid_dns_names().next().is_some();
        Ok(Self {
            certified_key,
            mode,
            end_entity_der,
            has_dns_san,
        })
    }

    fn allow_client_hello(&self, client_hello: ClientHello<'_>) -> bool {
        match self.mode {
            SniGuardMode::Disable => true,
            SniGuardMode::DnsSan => {
                if self.has_dns_san {
                    self.verify_strict(client_hello)
                } else {
                    true
                }
            }
            SniGuardMode::Strict => self.verify_strict(client_hello),
        }
    }

    fn verify_strict(&self, client_hello: ClientHello<'_>) -> bool {
        let Some(raw_name) = client_hello.server_name() else {
            return false;
        };
        let name = raw_name.trim();
        if name.is_empty() {
            return false;
        }
        let server_name = match ServerName::try_from(name) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let end_entity = CertificateDer::from(self.end_entity_der.clone());
        let parsed = match webpki::EndEntityCert::try_from(&end_entity) {
            Ok(v) => v,
            Err(_) => return false,
        };
        parsed
            .verify_is_valid_for_subject_name(&server_name)
            .is_ok()
    }
}

impl ResolvesServerCert for GuardedCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !self.allow_client_hello(client_hello) {
            return None;
        }
        Some(Arc::clone(&self.certified_key))
    }
}
