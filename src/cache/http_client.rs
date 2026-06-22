use opendal::HttpTransporter;
use opendal_http_transport_reqwest::ReqwestTransport;
use reqwest::ClientBuilder;

/// Build an HTTP transport with a custom user agent (helps with monitoring on
/// the server side).
///
/// Since opendal removed `HttpClientLayer`, a custom HTTP client is now supplied
/// as an [`HttpTransporter`] via `OperationContext::with_http_transport`.
pub fn set_user_agent() -> HttpTransporter {
    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client = ClientBuilder::new().user_agent(user_agent).build().unwrap();
    HttpTransporter::new(ReqwestTransport::new(client))
}
