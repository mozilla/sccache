// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TLS/HTTPS support with self-signed certificates
//!
//! This module handles:
//! 1. Self-signed certificate generation (reusing existing OpenSSL logic)
//! 2. rustls configuration for HTTPS server
//! 3. Certificate management and distribution

use crate::errors::*;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Create HTTPS certificate and private key (reuses legacy OpenSSL logic)
///
/// This generates a self-signed RSA-2048 certificate with:
/// - CN = server address
/// - SAN = server IP
/// - EKU = serverAuth
/// - Valid for 365 days
/// - SHA-1 signature (legacy, but only used for self-signed cert pinning)
///
/// Returns: (cert_digest, cert_pem, privkey_pem)
pub fn create_https_cert_and_privkey(addr: SocketAddr) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Generate RSA key
    let rsa_key = openssl::rsa::Rsa::<openssl::pkey::Private>::generate(2048)
        .context("failed to generate rsa privkey")?;
    let privkey_pem = rsa_key
        .private_key_to_pem()
        .context("failed to create pem from rsa privkey")?;
    let privkey: openssl::pkey::PKey<openssl::pkey::Private> =
        openssl::pkey::PKey::from_rsa(rsa_key).context("failed to create openssl pkey from rsa privkey")?;

    let mut builder = openssl::x509::X509::builder().context("failed to create x509 builder")?;

    // Set version to v3
    builder
        .set_version(2)
        .context("failed to set x509 version")?;

    // Serial number
    let serial_number = openssl::bn::BigNum::from_u32(0)
        .and_then(|bn| bn.to_asn1_integer())
        .context("failed to create openssl asn1 0")?;
    builder
        .set_serial_number(serial_number.as_ref())
        .context("failed to set x509 serial number")?;

    // Validity period
    let not_before =
        openssl::asn1::Asn1Time::days_from_now(0).context("failed to create openssl not before asn1")?;
    builder
        .set_not_before(not_before.as_ref())
        .context("failed to set not before on x509")?;
    let not_after =
        openssl::asn1::Asn1Time::days_from_now(365).context("failed to create openssl not after asn1")?;
    builder
        .set_not_after(not_after.as_ref())
        .context("failed to set not after on x509")?;

    // Public key
    builder
        .set_pubkey(privkey.as_ref())
        .context("failed to set pubkey for x509")?;

    // Subject and Issuer (self-signed, so both are the same)
    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &addr.to_string())?;
    let name = name.build();

    builder
        .set_subject_name(&name)
        .context("failed to set subject name")?;
    builder
        .set_issuer_name(&name)
        .context("failed to set issuer name")?;

    // SubjectAlternativeName with IP
    let extension = openssl::x509::extension::SubjectAlternativeName::new()
        .ip(&addr.ip().to_string())
        .build(&builder.x509v3_context(None, None))
        .context("failed to build SAN extension for x509")?;
    builder
        .append_extension(extension)
        .context("failed to append SAN extension for x509")?;

    // ExtendedKeyUsage: serverAuth
    let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
        .server_auth()
        .build()
        .context("failed to build EKU extension for x509")?;
    builder
        .append_extension(ext_key_usage)
        .context("fails to append EKU extension for x509")?;

    // Sign with SHA-1 (legacy, but only for internal cert pinning)
    builder
        .sign(&privkey, openssl::hash::MessageDigest::sha1())
        .context("failed to sign x509 with sha1")?;

    let cert: openssl::x509::X509 = builder.build();
    let cert_pem = cert.to_pem().context("failed to create pem from x509")?;

    // Calculate SHA-256 digest of certificate for pinning
    let cert_digest = cert
        .digest(openssl::hash::MessageDigest::sha256())
        .context("failed to create digest of x509 certificate")?
        .as_ref()
        .to_owned();

    Ok((cert_digest, cert_pem, privkey_pem))
}

/// Create rustls ServerConfig from PEM-encoded certificate and key
pub fn create_rustls_config(cert_pem: &[u8], privkey_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    // Parse certificate
    let certs: Vec<CertificateDer<'_>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to parse certificate PEM")?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in PEM"));
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut &privkey_pem[..])
        .context("failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;

    // Create server config with no client authentication
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to create rustls server config")?;

    Ok(Arc::new(config))
}

/// HTTPS server builder
pub struct HttpsServer {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl HttpsServer {
    pub async fn bind(
        addr: SocketAddr,
        cert_pem: &[u8],
        privkey_pem: &[u8],
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .context("failed to bind TCP listener")?;

        let config = create_rustls_config(cert_pem, privkey_pem)?;
        let tls_acceptor = TlsAcceptor::from(config);

        Ok(Self {
            listener,
            tls_acceptor,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("failed to get local address")
    }

    pub async fn accept(&self) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let (stream, _peer_addr) = self
            .listener
            .accept()
            .await
            .context("failed to accept connection")?;

        let tls_stream = self
            .tls_acceptor
            .accept(stream)
            .await
            .context("TLS handshake failed")?;

        Ok(tls_stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_https_cert() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let result = create_https_cert_and_privkey(addr);
        assert!(result.is_ok());

        let (cert_digest, cert_pem, privkey_pem) = result.unwrap();
        assert!(!cert_digest.is_empty());
        assert!(!cert_pem.is_empty());
        assert!(!privkey_pem.is_empty());

        // Verify it can be parsed by rustls
        let config_result = create_rustls_config(&cert_pem, &privkey_pem);
        assert!(config_result.is_ok());
    }
}
