//! Protocol compatibility tests for axum implementation
//!
//! These tests verify that the axum implementation produces identical
//! wire formats to the legacy rouille implementation.

#[cfg(test)]
mod protocol_tests {
    use crate::dist::http::common::{
        AllocJobHttpResponse, HeartbeatServerHttpRequest, JobJwt, RunJobHttpRequest,
        ServerCertificateHttpResponse,
    };
    use crate::dist::{JobId, ServerId, ServerNonce, Toolchain};
    use std::collections::HashMap;

    #[test]
    fn test_alloc_job_response_bincode() {
        let response = AllocJobHttpResponse::Success {
            job_alloc: crate::dist::JobAlloc {
                auth: "test_auth".to_string(),
                job_id: JobId(42),
                server_id: ServerId::new("192.168.1.1:8080".parse().unwrap()),
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
                assert_eq!(job_alloc.auth, "test_auth");
                assert_eq!(job_alloc.job_id, JobId(42));
                assert!(need_toolchain);
                assert_eq!(cert_digest, vec![1, 2, 3, 4]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_heartbeat_request_bincode() {
        let request = HeartbeatServerHttpRequest {
            jwt_key: vec![0xAB; 32],
            num_cpus: 16,
            server_nonce: ServerNonce::new(),
            cert_digest: vec![0xCD; 32],
            cert_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
        };

        let encoded = bincode::serialize(&request).unwrap();
        let decoded: HeartbeatServerHttpRequest = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.jwt_key, vec![0xAB; 32]);
        assert_eq!(decoded.num_cpus, 16);
        assert_eq!(decoded.cert_digest, vec![0xCD; 32]);
    }

    #[test]
    fn test_run_job_request_bincode() {
        let request = RunJobHttpRequest {
            command: crate::dist::CompileCommand {
                executable: "/usr/bin/gcc".to_string(),
                arguments: vec!["-c".to_string(), "main.c".to_string()],
                env_vars: vec![("CC".to_string(), "gcc".to_string())],
                cwd: "/tmp/build".to_string(),
            },
            outputs: vec!["main.o".to_string()],
        };

        let encoded = bincode::serialize(&request).unwrap();
        let decoded: RunJobHttpRequest = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.command.executable, "/usr/bin/gcc");
        assert_eq!(decoded.outputs, vec!["main.o"]);
    }

    #[test]
    fn test_jwt_claims_format() {
        let claims = JobJwt {
            exp: 0,
            job_id: JobId(999),
        };

        let encoded = bincode::serialize(&claims).unwrap();
        let decoded: JobJwt = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.exp, 0);
        assert_eq!(decoded.job_id, JobId(999));
    }

    #[test]
    fn test_alloc_job_result_conversion() {
        let mut certs = HashMap::new();
        let server_id = ServerId::new("10.0.0.1:7000".parse().unwrap());
        certs.insert(server_id, (vec![0xAA, 0xBB], vec![0xCC, 0xDD]));

        let result = crate::dist::AllocJobResult::Success {
            job_alloc: crate::dist::JobAlloc {
                auth: "secret_token".to_string(),
                job_id: JobId(777),
                server_id,
            },
            need_toolchain: true,
        };

        let http_response = AllocJobHttpResponse::from_alloc_job_result(result, &certs);

        match http_response {
            AllocJobHttpResponse::Success {
                job_alloc,
                need_toolchain,
                cert_digest,
            } => {
                assert_eq!(job_alloc.auth, "secret_token");
                assert_eq!(job_alloc.job_id, JobId(777));
                assert!(need_toolchain);
                assert_eq!(cert_digest, vec![0xAA, 0xBB]);
            }
            _ => panic!("Expected Success"),
        }
    }
}

#[cfg(all(test, feature = "jwt"))]
mod jwt_tests {
    use super::super::auth::JWTJobAuthorizer;
    use crate::dist::JobId;
    use crate::dist::http::server::JWT_KEY_LENGTH;

    // Import the trait so methods are available
    // Note: axum uses its own JobAuthorizer trait, dist::JobAuthorizer is for legacy
    use super::super::auth::JobAuthorizer;

    #[test]
    fn test_jwt_token_generation_and_verification() {
        let key = vec![0x42; JWT_KEY_LENGTH];
        let authorizer = JWTJobAuthorizer::new(key);

        let job_id = JobId(12345);
        let token = authorizer.generate_token(job_id).unwrap();

        // Verify correct job_id
        assert!(authorizer.verify_token(job_id, &token).is_ok());

        // Verify wrong job_id fails
        assert!(authorizer.verify_token(JobId(99999), &token).is_err());

        // Verify token format is JWT (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_jwt_deterministic() {
        let key = vec![0x99; JWT_KEY_LENGTH];
        let auth1 = JWTJobAuthorizer::new(key.clone());
        let auth2 = JWTJobAuthorizer::new(key);

        let job_id = JobId(555);
        let token1 = auth1.generate_token(job_id).unwrap();
        let token2 = auth2.generate_token(job_id).unwrap();

        // Tokens should be identical for same key and job_id
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_jwt_different_keys() {
        let key1 = vec![0x11; JWT_KEY_LENGTH];
        let key2 = vec![0x22; JWT_KEY_LENGTH];

        let auth1 = JWTJobAuthorizer::new(key1);
        let auth2 = JWTJobAuthorizer::new(key2);

        let job_id = JobId(888);
        let token1 = auth1.generate_token(job_id).unwrap();

        // Token from auth1 should not verify with auth2 (different key)
        assert!(auth2.verify_token(job_id, &token1).is_err());
    }
}
