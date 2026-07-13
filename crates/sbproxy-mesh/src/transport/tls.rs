// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Mutual TLS for the mesh transport.
//!
//! Mesh peers connect to each other in both directions (each is a TLS server
//! for inbound RPC and a TLS client for outbound RPC), so peer connections use
//! mutual TLS: every node presents its own certificate and verifies the
//! peer's against a shared CA. Verification uses rustls's built-in
//! `WebPkiClientVerifier` / server verifier (X.509 path building via
//! rustls-webpki), the same engine the standalone [`crate::peer_auth`] check
//! wraps, so a node without a CA-signed cert cannot join an mTLS mesh.
//!
//! The crypto provider is pinned to `ring` to match the rest of the build
//! (the default would pull `aws-lc-rs`).

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// PEM material for mesh peer mTLS. `cert_pem` is this node's leaf certificate
/// (optionally followed by intermediates), `key_pem` its private key, and
/// `ca_pem` the certificate authority that signs every peer in the mesh.
#[derive(Debug, Clone)]
pub struct MeshTlsConfig {
    /// This node's certificate chain (leaf first), PEM-encoded.
    pub cert_pem: String,
    /// This node's private key, PEM-encoded.
    pub key_pem: String,
    /// The shared CA that signs all peers, PEM-encoded.
    pub ca_pem: String,
}

/// The pinned `ring` crypto provider, so config building never depends on a
/// process-global default being installed.
pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn load_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .context("parse certificate PEM")?;
    if chain.is_empty() {
        anyhow::bail!("no CERTIFICATE blocks in certificate PEM");
    }
    Ok(chain)
}

pub(crate) fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).context("parse private key PEM")
}

pub(crate) fn load_roots(ca_pem: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots
            .add(cert.context("parse CA PEM")?)
            .context("add CA root")?;
        count += 1;
    }
    if count == 0 {
        anyhow::bail!("no CERTIFICATE blocks in CA PEM");
    }
    Ok(roots)
}

/// Build the server-side acceptor: presents this node's certificate and
/// requires + verifies the connecting peer's client certificate against the
/// shared CA.
pub fn build_acceptor(cfg: &MeshTlsConfig) -> Result<TlsAcceptor> {
    build_acceptor_with_alpn(cfg, Vec::new())
}

/// Build a model-plane server acceptor that negotiates HTTP/2 only.
pub fn build_http2_acceptor(cfg: &MeshTlsConfig) -> Result<TlsAcceptor> {
    build_acceptor_with_alpn(cfg, vec![b"h2".to_vec()])
}

fn build_acceptor_with_alpn(
    cfg: &MeshTlsConfig,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor> {
    let roots = Arc::new(load_roots(&cfg.ca_pem)?);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider())
        .build()
        .context("build mesh client-cert verifier")?;
    let mut server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("select TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_chain(&cfg.cert_pem)?, load_key(&cfg.key_pem)?)
        .context("install mesh server certificate")?;
    server_config.alpn_protocols = alpn_protocols;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build the client-side connector: presents this node's certificate and
/// verifies the peer's server certificate against the shared CA. The caller
/// supplies the `ServerName` at connect time.
pub fn build_connector(cfg: &MeshTlsConfig) -> Result<TlsConnector> {
    build_connector_with_alpn(cfg, Vec::new())
}

/// Build a model-plane client connector that negotiates HTTP/2 only.
pub fn build_http2_connector(cfg: &MeshTlsConfig) -> Result<TlsConnector> {
    build_connector_with_alpn(cfg, vec![b"h2".to_vec()])
}

fn build_connector_with_alpn(
    cfg: &MeshTlsConfig,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsConnector> {
    let roots = load_roots(&cfg.ca_pem)?;
    let mut client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("select TLS protocol versions")?
        .with_root_certificates(roots)
        .with_client_auth_cert(load_chain(&cfg.cert_pem)?, load_key(&cfg.key_pem)?)
        .context("install mesh client certificate")?;
    client_config.alpn_protocols = alpn_protocols;
    Ok(TlsConnector::from(Arc::new(client_config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A CA plus a peer certificate (both `server_auth` and `client_auth`
    /// EKUs, SAN `localhost`) signed by it.
    struct TestPki {
        ca_pem: String,
        peer_cert_pem: String,
        peer_key_pem: String,
    }

    fn make_pki() -> TestPki {
        use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
        // CA.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Peer leaf signed by the CA, valid as both a TLS server and client.
        let peer_key = KeyPair::generate().unwrap();
        let mut peer_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        peer_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let peer_cert = peer_params.signed_by(&peer_key, &ca_cert, &ca_key).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            peer_cert_pem: peer_cert.pem(),
            peer_key_pem: peer_key.serialize_pem(),
        }
    }

    fn config_from(pki: &TestPki) -> MeshTlsConfig {
        MeshTlsConfig {
            cert_pem: pki.peer_cert_pem.clone(),
            key_pem: pki.peer_key_pem.clone(),
            ca_pem: pki.ca_pem.clone(),
        }
    }

    #[tokio::test]
    async fn mutual_handshake_succeeds_and_transfers_bytes() {
        let pki = make_pki();
        let acceptor = build_acceptor(&config_from(&pki)).unwrap();
        let connector = build_connector(&config_from(&pki)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.expect("server handshake");
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
            buf
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("client handshake");
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = [0u8; 4];
        tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");
        assert_eq!(&server.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn model_plane_tls_negotiates_h2_only() {
        let pki = make_pki();
        let acceptor = build_http2_acceptor(&config_from(&pki)).unwrap();
        let connector = build_http2_connector(&config_from(&pki)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.expect("server handshake");
            tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let tls = connector
            .connect(name, tcp)
            .await
            .expect("client handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(server.await.unwrap().as_deref(), Some(b"h2".as_slice()));
    }

    #[tokio::test]
    async fn untrusted_client_cert_is_rejected() {
        // The server trusts `pki`'s CA; the client presents a cert signed by a
        // different, untrusted CA, so the server must reject the handshake.
        let server_pki = make_pki();
        let rogue_pki = make_pki();
        let acceptor = build_acceptor(&config_from(&server_pki)).unwrap();
        let connector = build_connector(&config_from(&rogue_pki)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.is_ok()
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        // The client handshake fails (server rejects its untrusted cert), and
        // the server side never completes a session either.
        let client_ok = connector.connect(name, tcp).await.is_ok();
        let server_ok = server.await.unwrap();
        assert!(
            !(client_ok && server_ok),
            "an untrusted client cert must not yield a completed mutual handshake"
        );
    }
}
