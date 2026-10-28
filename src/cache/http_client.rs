use opendal::HttpTransporter;
use opendal_http_transport_reqwest::ReqwestTransport;

use crate::util::new_reqwest_client_builder;

/// Build an HTTP transport with a custom user agent (helps with monitoring on
/// the server side).
pub(super) fn new_http_transport() -> reqwest::Result<HttpTransporter> {
    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client = new_reqwest_client_builder()?
        .user_agent(user_agent)
        .build()?;
    Ok(HttpTransporter::new(ReqwestTransport::new(client)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::new_http_transport;

    #[test]
    #[serial_test::serial(reqwest_tls_env)]
    fn http_transport_builds_with_invalid_native_ca_paths() -> reqwest::Result<()> {
        temp_env::with_vars(
            [
                ("SSL_CERT_FILE", Some("/sccache-test-no-cert-file.crt")),
                ("SSL_CERT_DIR", Some("/sccache-test-no-cert-dir")),
            ],
            || {
                assert!(
                    reqwest::Client::builder().build().is_err(),
                    "test environment must reproduce the empty native trust-store failure"
                );
                new_http_transport().map(drop)
            },
        )
    }
}
