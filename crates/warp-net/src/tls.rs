//! TLS utilities for QUIC connections

use crate::{Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| Error::Tls(format!("Failed to generate certificate: {}", e)))?;

    let cert_der = CertificateDer::from(cert.cert.der().clone());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| Error::Tls(format!("Failed to serialize private key: {}", e)))?;

    Ok((vec![cert_der], key_der))
}

/// Create server TLS configuration
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::Tls(format!("Failed to create server config: {}", e)))?;

    config.max_early_data_size = u32::MAX;
    config.alpn_protocols = vec![b"warp/1".to_vec()];

    Ok(config)
}

/// Create client TLS configuration that skips certificate verification
///
/// # Safety
///
/// This function disables all certificate validation and is vulnerable to MITM attacks.
/// ONLY use for testing or development with self-signed certificates.
/// NEVER use in production.
#[cfg(any(test, feature = "insecure-tls"))]
pub fn client_config_insecure() -> Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"warp/1".to_vec()];

    Ok(config)
}

/// Create client TLS configuration with root certificate store
pub fn client_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"warp/1".to_vec()];

    Ok(config)
}

/// Load certificate chain from PEM file
pub fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::Tls(format!("Failed to open cert file: {}", e)))?;
    let mut reader = std::io::BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("Failed to parse certificates: {}", e)))
}

/// Load private key from PEM file
pub fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::Tls(format!("Failed to open key file: {}", e)))?;
    let mut reader = std::io::BufReader::new(file);

    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::Tls(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| Error::Tls("No private key found in file".into()))?;

    Ok(key)
}

/// Certificate verifier that skips verification (for testing/self-signed certs)
///
/// # Safety
///
/// This verifier accepts ANY certificate without validation.
/// It is vulnerable to man-in-the-middle attacks and should NEVER be used in production.
#[cfg(any(test, feature = "insecure-tls"))]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(any(test, feature = "insecure-tls"))]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed() {
        let result = generate_self_signed();
        assert!(result.is_ok());
        let (certs, _key) = result.unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_server_config() {
        let (certs, key) = generate_self_signed().unwrap();
        let result = server_config(certs, key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_config_insecure() {
        let result = client_config_insecure();
        assert!(result.is_ok());
    }
}
