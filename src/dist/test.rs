#![cfg(feature = "dist-server")]

use super::*;

use crate::dist::http::server::create_https_cert_and_privkey_inner;
use chrono::{NaiveDateTime, Utc};
use picky::{key::PrivateKey, x509::Cert};

use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Replicates previous generation behaviour, but uses sha256 since sha1 is not included in some openssl distributions
fn create_https_cert_and_privkey_legacy_openssl(
    now: NaiveDateTime,
    sk: PrivateKey,
    addr: SocketAddr,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let der_sk = sk.to_pem()?;
    let rsa_key = openssl::rsa::Rsa::private_key_from_pem(der_sk.as_bytes())
        .context("failed to generate rsa privkey")?;
    let privkey_pem = rsa_key
        .private_key_to_pem()
        .context("failed to create pem from rsa privkey")?;
    let privkey = openssl::pkey::PKey::from_rsa(rsa_key)
        .context("failed to create openssl skey from rsa privkey")?;
    let mut builder = openssl::x509::X509::builder().context("failed to create x509 builder")?;

    // Populate the certificate with the necessary parts, mostly from mkcert in openssl
    builder
        .set_version(2)
        .context("failed to set x509 version")?;
    let serial_number = openssl::bn::BigNum::from_u32(0)
        .and_then(|bn| bn.to_asn1_integer())
        .context("failed to create openssl asn1 0")?;
    builder
        .set_serial_number(serial_number.as_ref())
        .context("failed to set x509 serial number")?;
    let not_before = openssl::asn1::Asn1Time::from_unix(now.and_utc().timestamp())
        .context("failed to create openssl not before asn1")?;
    builder
        .set_not_before(not_before.as_ref())
        .context("failed to set not before on x509")?;
    let not_after = openssl::asn1::Asn1Time::from_unix(
        now.checked_add_days(chrono::Days::new(365))
            .unwrap()
            .and_utc()
            .timestamp(),
    )
    .context("failed to create openssl not after asn1")?;
    builder
        .set_not_after(not_after.as_ref())
        .context("failed to set not after on x509")?;
    builder
        .set_pubkey(privkey.as_ref())
        .context("failed to set pubkey for x509")?;

    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &addr.to_string())?;
    let name = name.build();

    builder
        .set_subject_name(&name)
        .context("failed to set subject name")?;
    builder
        .set_issuer_name(&name)
        .context("failed to set issuer name")?;

    // Add the SubjectAlternativeName
    let extension = openssl::x509::extension::SubjectAlternativeName::new()
        .ip(&addr.ip().to_string())
        .build(&builder.x509v3_context(None, None))
        .context("failed to build SAN extension for x509")?;
    builder
        .append_extension(extension)
        .context("failed to append SAN extension for x509")?;

    // Add ExtendedKeyUsage
    let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
        .server_auth()
        .build()
        .context("failed to build EKU extension for x509")?;
    builder
        .append_extension(ext_key_usage)
        .context("fails to append EKU extension for x509")?;

    // Finish the certificate
    builder
        .sign(&privkey, openssl::hash::MessageDigest::sha256())
        .context("failed to sign x509 with sha1")?;
    let cert: openssl::x509::X509 = builder.build();
    let cert_pem = cert.to_pem().context("failed to create pem from x509")?;
    let cert_digest = cert
        .digest(openssl::hash::MessageDigest::sha256())
        .context("failed to create digest of x509 certificate")?
        .as_ref()
        .to_owned();
    Ok((cert_digest, cert_pem, privkey_pem))
}


/// The compatibility _cannot_ be tested, since the originally generated certificates were not valid
/// in regards to the spec, and hence `picky` will fail.
#[ignore]
#[test]
fn certificate_compatibility_assurance() {
    let now: NaiveDateTime = Utc::now().naive_utc();
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 32452));
    let rng = OsRng;
    //FlipperRng::default();

    fn parse<'a>(digest: &'a [u8], cert: &[u8], sk: &[u8]) -> Result<(&'a [u8], Cert, PrivateKey)> {
        eprintln!("PEM parsing start");
        let cert = picky::pem::parse_pem(cert)?;
        let sk = picky::pem::parse_pem(sk)?;

        let cert = picky::x509::Cert::from_pem(&cert)?;
        let sk = picky::key::PrivateKey::from_pem(&sk)?;
        eprintln!("PEM parsing end");
        Ok((digest, cert, sk))
    }

    eprintln!("picky start");
    let (digest, cert, sk) = create_https_cert_and_privkey_inner(rng, now, addr).unwrap();
    let (digest, cert, sk) = parse(&digest, &cert, &sk).unwrap();
    eprintln!("picky end");

    eprintln!("LEGACY start");
    let (legacy_digest, legacy_cert, legacy_sk) =
        create_https_cert_and_privkey_legacy_openssl(now, sk.clone(), addr).unwrap();
    let (legacy_digest, legacy_cert, legacy_sk) =
        parse(&legacy_digest, &legacy_cert, &legacy_sk).unwrap();
    eprintln!("LEGACY end");

    assert_eq!(dbg!(legacy_cert.extensions()), dbg!(cert.extensions()));

    assert_eq!(dbg!(legacy_cert), dbg!(cert));
    assert_eq!(dbg!(legacy_sk), dbg!(sk));

    // since the time varies, it's impossible these are identical
    dbg!(legacy_digest);
    dbg!(digest);
}
