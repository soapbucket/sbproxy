use std::fmt;

use anyhow::{anyhow, Result};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use url::Url;

const INVALID_CONNECTION: &str = "invalid Redis connection configuration";

/// Optional certificate material for a Redis TLS connection.
#[derive(Clone, Default)]
pub struct RedisTlsConfig {
    /// Additional PEM-encoded root certificates.
    pub root_cert: Option<Vec<u8>>,
    /// PEM-encoded client certificate chain for mutual TLS.
    pub client_cert: Option<Vec<u8>>,
    /// PEM-encoded client private key for mutual TLS.
    pub client_key: Option<Vec<u8>>,
}

impl fmt::Debug for RedisTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisTlsConfig")
            .field("root_cert", &self.root_cert.is_some())
            .field("client_cert", &self.client_cert.is_some())
            .field("client_key", &self.client_key.is_some())
            .finish()
    }
}

/// A parsed Redis client whose connection material is redacted from debug output.
#[derive(Clone)]
pub struct ValidatedRedisConnection {
    client: redis::Client,
    uses_tls: bool,
}

impl fmt::Debug for ValidatedRedisConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRedisConnection")
            .field("uses_tls", &self.uses_tls)
            .finish()
    }
}

impl ValidatedRedisConnection {
    /// Parse and validate a Redis DSN without opening a network connection.
    pub fn new(dsn: &str, tls: RedisTlsConfig) -> Result<Self> {
        Self::build(dsn, tls).map_err(|_| anyhow!(INVALID_CONNECTION))
    }

    fn build(dsn: &str, tls: RedisTlsConfig) -> Result<Self> {
        let trimmed = dsn.trim();
        let is_legacy = !trimmed.contains("://")
            && !trimmed.contains('/')
            && !trimmed.contains('?')
            && !trimmed.contains('#');
        let normalized = if is_legacy {
            let bracketed = trimmed.starts_with('[') && trimmed.contains(']');
            anyhow::ensure!(bracketed || trimmed.matches(':').count() <= 1);
            format!("redis://{trimmed}")
        } else {
            trimmed.to_string()
        };

        let parsed = Url::parse(&normalized)?;
        anyhow::ensure!(matches!(parsed.scheme(), "redis" | "rediss"));
        anyhow::ensure!(parsed.host().is_some());
        anyhow::ensure!(parsed.query().is_none());
        anyhow::ensure!(parsed.fragment().is_none());
        anyhow::ensure!(parsed.username().is_empty() || parsed.password().is_some());

        let uses_tls = parsed.scheme() == "rediss";
        let parsed_client = redis::Client::open(normalized.as_str())?;
        anyhow::ensure!(parsed_client.get_connection_info().redis.db >= 0);

        let RedisTlsConfig {
            root_cert,
            client_cert,
            client_key,
        } = tls;
        let has_tls_material = root_cert.is_some() || client_cert.is_some() || client_key.is_some();
        anyhow::ensure!(uses_tls || !has_tls_material);

        if let Some(root_cert) = root_cert.as_deref() {
            let certificates = CertificateDer::pem_slice_iter(root_cert)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            anyhow::ensure!(!certificates.is_empty());
        }

        let client_tls = match (client_cert, client_key) {
            (None, None) => None,
            (Some(client_cert), Some(client_key)) => {
                let certificate_chain = CertificateDer::pem_slice_iter(&client_cert)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                anyhow::ensure!(!certificate_chain.is_empty());
                let private_key = PrivateKeyDer::from_pem_slice(&client_key)?;
                CertifiedKey::from_der(
                    certificate_chain,
                    private_key,
                    &rustls::crypto::ring::default_provider(),
                )?;
                Some(redis::ClientTlsConfig {
                    client_cert,
                    client_key,
                })
            }
            _ => anyhow::bail!(INVALID_CONNECTION),
        };

        let client = if has_tls_material {
            redis::Client::build_with_tls(
                normalized.as_str(),
                redis::TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )?
        } else {
            parsed_client
        };

        Ok(Self { client, uses_tls })
    }

    /// Return a clone of the validated Redis client.
    pub(crate) fn client(&self) -> redis::Client {
        self.client.clone()
    }

    /// Return whether the Redis DSN uses TLS.
    pub fn uses_tls(&self) -> bool {
        self.uses_tls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_and_key(name: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (
            certificate.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn normalizes_legacy_addresses_without_network_io() {
        for input in [
            "localhost",
            "localhost:6380",
            "127.0.0.1:6379",
            "[::1]:6379",
        ] {
            let config = ValidatedRedisConnection::new(input, RedisTlsConfig::default()).unwrap();
            assert!(!config.uses_tls());
        }
    }

    #[test]
    fn accepts_full_safe_url_semantics() {
        for input in [
            "redis://:p%40ss@localhost:6379/7",
            "redis://default:p%2Fss@[::1]:6379/4",
            "rediss://default:secret@localhost:6380/2",
        ] {
            ValidatedRedisConnection::new(input, RedisTlsConfig::default()).unwrap();
        }
    }

    #[test]
    fn rejects_semantics_that_must_not_be_discarded() {
        for input in [
            "",
            "http://localhost:6379",
            "redis://",
            "redis://user@localhost:6379",
            "redis://localhost:6379/-1",
            "redis://localhost:6379/0?x=1",
            "rediss://localhost:6380/0#insecure",
            "::1:6379",
        ] {
            let error =
                ValidatedRedisConnection::new(input, RedisTlsConfig::default()).unwrap_err();
            assert_eq!(error.to_string(), "invalid Redis connection configuration");
        }
    }

    #[test]
    fn debug_and_errors_never_expose_connection_material() {
        let sentinel = "user:sentinel-password@secret-host.invalid:6380/7";
        let config = ValidatedRedisConnection::new(
            &format!("rediss://{sentinel}"),
            RedisTlsConfig::default(),
        )
        .unwrap();
        let rendered = format!("{config:?}");
        for forbidden in ["sentinel-password", "secret-host", "user", "/7"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn validates_complete_tls_material_without_network_io() {
        let (certificate, key) = certificate_and_key("client.example");
        let connection = ValidatedRedisConnection::new(
            "rediss://localhost:6380/3",
            RedisTlsConfig {
                root_cert: Some(certificate.clone()),
                client_cert: Some(certificate),
                client_key: Some(key),
            },
        )
        .unwrap();

        assert!(connection.uses_tls());
    }

    #[test]
    fn rejects_tls_material_for_plaintext_connections() {
        let (certificate, _) = certificate_and_key("root.example");
        let error = ValidatedRedisConnection::new(
            "redis://localhost:6379/0",
            RedisTlsConfig {
                root_cert: Some(certificate),
                ..RedisTlsConfig::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "invalid Redis connection configuration");
    }

    #[test]
    fn rejects_incomplete_client_identity_pairs() {
        let (certificate, key) = certificate_and_key("client.example");
        for tls in [
            RedisTlsConfig {
                client_cert: Some(certificate),
                ..RedisTlsConfig::default()
            },
            RedisTlsConfig {
                client_key: Some(key),
                ..RedisTlsConfig::default()
            },
        ] {
            let error =
                ValidatedRedisConnection::new("rediss://localhost:6380/0", tls).unwrap_err();
            assert_eq!(error.to_string(), "invalid Redis connection configuration");
        }
    }

    #[test]
    fn rejects_empty_or_invalid_certificate_material() {
        for tls in [
            RedisTlsConfig {
                root_cert: Some(Vec::new()),
                ..RedisTlsConfig::default()
            },
            RedisTlsConfig {
                root_cert: Some(b"not a PEM certificate".to_vec()),
                ..RedisTlsConfig::default()
            },
            RedisTlsConfig {
                client_cert: Some(Vec::new()),
                client_key: Some(b"not a PEM private key".to_vec()),
                ..RedisTlsConfig::default()
            },
        ] {
            let error =
                ValidatedRedisConnection::new("rediss://localhost:6380/0", tls).unwrap_err();
            assert_eq!(error.to_string(), "invalid Redis connection configuration");
        }
    }

    #[test]
    fn rejects_mismatched_client_certificate_and_key() {
        let (certificate, _) = certificate_and_key("client.example");
        let (_, other_key) = certificate_and_key("other.example");
        let error = ValidatedRedisConnection::new(
            "rediss://localhost:6380/0",
            RedisTlsConfig {
                client_cert: Some(certificate),
                client_key: Some(other_key),
                ..RedisTlsConfig::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "invalid Redis connection configuration");
    }

    #[test]
    fn tls_config_debug_shows_only_material_presence() {
        let sentinel = b"sentinel-private-certificate-material".to_vec();
        let rendered = format!(
            "{:?}",
            RedisTlsConfig {
                root_cert: Some(sentinel.clone()),
                client_cert: Some(sentinel.clone()),
                client_key: Some(sentinel),
            }
        );

        assert!(!rendered.contains("sentinel"));
        assert_eq!(
            rendered,
            "RedisTlsConfig { root_cert: true, client_cert: true, client_key: true }"
        );
    }
}
