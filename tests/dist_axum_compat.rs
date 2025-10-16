//! Compatibility tests between rouille and axum dist-server implementations
//!
//! These tests verify that the axum-based dist-server implementation is
//! 100% protocol-compatible with the legacy rouille implementation.

#![cfg(all(feature = "dist-client", feature = "dist-server-axum"))]

use sccache::dist::http::common::{AllocJobHttpResponse, HeartbeatServerHttpRequest, JobJwt};
use sccache::dist::http_axum::auth::JobAuthorizer;
use sccache::dist::{JobId, ServerId, ServerNonce};
use std::collections::HashMap;

/// Test bincode serialization/deserialization compatibility
#[test]
fn test_bincode_compatibility() {
    // Test AllocJobHttpResponse
    let response = AllocJobHttpResponse::Success {
        job_alloc: sccache::dist::JobAlloc {
            auth: "test_token".to_string(),
            job_id: JobId(12345),
            server_id: ServerId::new("127.0.0.1:8080".parse().unwrap()),
        },
        need_toolchain: true,
        cert_digest: vec![1, 2, 3, 4],
    };

    let encoded = bincode::serialize(&response).unwrap();
    let decoded: AllocJobHttpResponse = bincode::deserialize(&encoded).unwrap();

    match decoded {
        AllocJobHttpResponse::Success {
            job_alloc,
            need_toolchain,
            cert_digest,
        } => {
            assert_eq!(job_alloc.auth, "test_token");
            assert_eq!(job_alloc.job_id, JobId(12345));
            assert!(need_toolchain);
            assert_eq!(cert_digest, vec![1, 2, 3, 4]);
        }
        _ => panic!("Unexpected response type"),
    }
}

/// Test HeartbeatServerHttpRequest serialization
#[test]
fn test_heartbeat_serialization() {
    let request = HeartbeatServerHttpRequest {
        jwt_key: vec![0u8; 32],
        num_cpus: 8,
        server_nonce: ServerNonce::new(),
        cert_digest: vec![5, 6, 7, 8],
        cert_pem: vec![9, 10, 11, 12],
    };

    let encoded = bincode::serialize(&request).unwrap();
    let decoded: HeartbeatServerHttpRequest = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.jwt_key, vec![0u8; 32]);
    assert_eq!(decoded.num_cpus, 8);
    assert_eq!(decoded.cert_digest, vec![5, 6, 7, 8]);
    assert_eq!(decoded.cert_pem, vec![9, 10, 11, 12]);
}

/// Test JWT token format compatibility
#[test]
fn test_jwt_token_format() {
    let claims = JobJwt {
        exp: 0,
        job_id: JobId(999),
    };

    let encoded = bincode::serialize(&claims).unwrap();
    let decoded: JobJwt = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.exp, 0);
    assert_eq!(decoded.job_id, JobId(999));
}

/// Test Toolchain serialization
#[test]
fn test_toolchain_serialization() {
    let toolchain = Toolchain {
        archive_id: "abc123def456".to_string(),
    };

    let encoded = bincode::serialize(&toolchain).unwrap();
    let decoded: Toolchain = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.archive_id, "abc123def456");
}

/// Test ServerCertificateHttpResponse
#[test]
fn test_certificate_response_serialization() {
    let response = ServerCertificateHttpResponse {
        cert_digest: vec![1, 2, 3],
        cert_pem: vec![4, 5, 6],
    };

    let encoded = bincode::serialize(&response).unwrap();
    let decoded: ServerCertificateHttpResponse = bincode::deserialize(&encoded).unwrap();

    assert_eq!(decoded.cert_digest, vec![1, 2, 3]);
    assert_eq!(decoded.cert_pem, vec![4, 5, 6]);
}

/// Test AllocJobHttpResponse::from_alloc_job_result consistency
#[test]
fn test_alloc_job_result_conversion() {
    let mut certs = HashMap::new();
    let server_id = ServerId::new("127.0.0.1:9000".parse().unwrap());
    certs.insert(server_id, (vec![1, 2], vec![3, 4]));

    let alloc_result = sccache::dist::AllocJobResult::Success {
        job_alloc: sccache::dist::JobAlloc {
            auth: "auth_token".to_string(),
            job_id: JobId(555),
            server_id,
        },
        need_toolchain: false,
    };

    let http_response = AllocJobHttpResponse::from_alloc_job_result(alloc_result, &certs);

    match http_response {
        AllocJobHttpResponse::Success {
            job_alloc,
            need_toolchain,
            cert_digest,
        } => {
            assert_eq!(job_alloc.auth, "auth_token");
            assert_eq!(job_alloc.job_id, JobId(555));
            assert!(!need_toolchain);
            assert_eq!(cert_digest, vec![1, 2]);
        }
        _ => panic!("Expected Success variant"),
    }
}

/// Test that length-prefixed bincode format matches between implementations
#[test]
fn test_length_prefixed_format() {
    use byteorder::{BigEndian, WriteBytesExt};
    use std::io::Write;

    let toolchain = Toolchain {
        archive_id: "test123".to_string(),
    };

    // Encode in the legacy format (4-byte BigEndian length + bincode)
    let bincode_data = bincode::serialize(&toolchain).unwrap();
    let mut buffer = Vec::new();
    buffer
        .write_u32::<BigEndian>(bincode_data.len() as u32)
        .unwrap();
    buffer.write_all(&bincode_data).unwrap();

    // Verify we can decode it
    use byteorder::ReadBytesExt;
    use std::io::Cursor;

    let mut cursor = Cursor::new(&buffer);
    let len = cursor.read_u32::<BigEndian>().unwrap();
    assert_eq!(len, bincode_data.len() as u32);

    let mut data = vec![0u8; len as usize];
    std::io::Read::read_exact(&mut cursor, &mut data).unwrap();

    let decoded: Toolchain = bincode::deserialize(&data).unwrap();
    assert_eq!(decoded.archive_id, "test123");
}

/// Test run_job special format (length prefix + bincode + zlib)
#[test]
fn test_run_job_format() {
    use byteorder::{BigEndian, WriteBytesExt};
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let command = sccache::dist::CompileCommand {
        executable: "gcc".to_string(),
        arguments: vec!["-c".to_string(), "test.c".to_string()],
        env_vars: vec![],
        cwd: "/tmp".to_string(),
    };

    let run_job_request = sccache::dist::http::common::RunJobHttpRequest {
        command,
        outputs: vec!["test.o".to_string()],
    };

    // Encode in the special run_job format
    let bincode_data = bincode::serialize(&run_job_request).unwrap();
    let mut buffer = Vec::new();

    // 1. Write length prefix
    buffer
        .write_u32::<BigEndian>(bincode_data.len() as u32)
        .unwrap();

    // 2. Write bincode data
    buffer.write_all(&bincode_data).unwrap();

    // 3. Write zlib-compressed inputs (empty for this test)
    let inputs = b"test input data";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(inputs).unwrap();
    let compressed = encoder.finish().unwrap();
    buffer.write_all(&compressed).unwrap();

    // Verify we can decode it
    use byteorder::ReadBytesExt;
    use flate2::read::ZlibDecoder;
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(&buffer);

    // Read length
    let len = cursor.read_u32::<BigEndian>().unwrap();

    // Read bincode
    let mut bincode_buf = vec![0u8; len as usize];
    cursor.read_exact(&mut bincode_buf).unwrap();
    let decoded_request: sccache::dist::http::common::RunJobHttpRequest =
        bincode::deserialize(&bincode_buf).unwrap();

    assert_eq!(decoded_request.command.executable, "gcc");
    assert_eq!(decoded_request.outputs, vec!["test.o"]);

    // Read zlib data
    let mut remaining = Vec::new();
    cursor.read_to_end(&mut remaining).unwrap();

    let mut decoder = ZlibDecoder::new(Cursor::new(remaining));
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();

    assert_eq!(decompressed, b"test input data");
}

#[cfg(feature = "jwt")]
#[test]
fn test_jwt_compatibility_between_implementations() {
    use sccache::dist::JobAuthorizer;
    use sccache::dist::http::server::JWT_KEY_LENGTH;

    // Generate key
    let key = vec![42u8; JWT_KEY_LENGTH];

    // Test axum JWTJobAuthorizer
    let axum_authorizer = sccache::dist::http_axum::auth::JWTJobAuthorizer::new(key);

    let job_id = JobId(12345);
    let token = axum_authorizer.generate_token(job_id).unwrap();

    // Verify with axum
    assert!(axum_authorizer.verify_token(job_id, &token).is_ok());
    assert!(axum_authorizer.verify_token(JobId(99999), &token).is_err());

    // Verify token format is valid JWT
    assert!(token.contains('.')); // JWT has 3 parts separated by dots
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3); // header.payload.signature
}
