use futures_03::channel::oneshot;
use futures_03::compat::Future01CompatExt;
use futures_03::prelude::*;
use http::StatusCode;
use hyper::body::HttpBody;
use hyper::server::conn::AddrIncoming;
use hyper::service::Service;
use hyper::{Body, Request, Response, Server};
use hyperx::header::{ContentLength, ContentType};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::io;
use std::marker::PhantomData;
use std::net::{TcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::sync::mpsc;
use std::time::Duration;
use tokio_02::runtime::Runtime;
use url::Url;
use uuid::Uuid;

use crate::util::RequestExt;

use crate::errors::*;

// These (arbitrary) ports need to be registered as valid redirect urls in the oauth provider you're using
pub const VALID_PORTS: &[u16] = &[12731, 32492, 56909];
// If token is valid for under this amount of time, print a warning
const MIN_TOKEN_VALIDITY: Duration = Duration::from_secs(2 * 24 * 60 * 60);
const MIN_TOKEN_VALIDITY_WARNING: &str = "two days";

trait ServeFn<R>: FnOnce(Request<Body>) -> R + Copy + Send + 'static
where
    R: 'static + Send + futures_03::Future<Output = result::Result<Response<Body>, hyper::Error>>,
{
}

impl<T, R> ServeFn<R> for T
where
    R: 'static + Send + futures_03::Future<Output = result::Result<Response<Body>, hyper::Error>>,
    T: FnOnce(Request<Body>) -> R + Copy + Send + Sized + 'static,
{
}

fn query_pairs(url: &str) -> Result<HashMap<String, String>> {
    // Url::parse operates on absolute URLs, so ensure there's a prefix
    let url = Url::parse("http://unused_base")
        .expect("Failed to parse fake url prefix")
        .join(url)
        .context("Failed to parse url while extracting query params")?;
    Ok(url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect())
}

fn html_response(body: &'static str) -> Response<Body> {
    Response::builder()
        .set_header(ContentType::html())
        .set_header(ContentLength(body.len() as u64))
        .body(body.into())
        .unwrap()
}

fn json_response<T: Serialize>(data: &T) -> Result<Response<Body>> {
    let body = serde_json::to_vec(data).context("Failed to serialize to JSON")?;
    let len = body.len();
    Ok(Response::builder()
        .set_header(ContentType::json())
        .set_header(ContentLength(len as u64))
        .body(body.into())
        .unwrap())
}

const REDIRECT_WITH_AUTH_JSON: &str = r##"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body>
    <script>
    function writemsg(m) {
        document.body.appendChild(document.createTextNode(m.toString()));
        document.body.appendChild(document.createElement('br'));
    }
    function go() {
        writemsg('Retrieving details of authenticator...');
        fetch('/auth_detail.json').then(function (response) {
            if (!response.ok) {
                throw 'Error during retrieval - ' + response.status + ': ' + response.statusText;
            }
            writemsg('Using details to redirect to authentication page...');
            return response.json()
        }).then(function (auth_url) {
            window.location.href = auth_url;
        }).catch(writemsg);
    }
    go();
    </script>
</body>
</html>
"##;

mod code_grant_pkce {
    use super::{
        html_response, json_response, query_pairs, MIN_TOKEN_VALIDITY, MIN_TOKEN_VALIDITY_WARNING,
        REDIRECT_WITH_AUTH_JSON,
    };
    use futures::future;
    use futures_03::channel::oneshot;
    use hyper::{Body, Method, Request, Response, StatusCode};
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::*;

    // Code request - https://tools.ietf.org/html/rfc7636#section-4.3
    const CLIENT_ID_PARAM: &str = "client_id";
    const CODE_CHALLENGE_PARAM: &str = "code_challenge";
    const CODE_CHALLENGE_METHOD_PARAM: &str = "code_challenge_method";
    const CODE_CHALLENGE_METHOD_VALUE: &str = "S256";
    const REDIRECT_PARAM: &str = "redirect_uri";
    const RESPONSE_TYPE_PARAM: &str = "response_type";
    const RESPONSE_TYPE_PARAM_VALUE: &str = "code";
    const STATE_PARAM: &str = "state";
    // Code response - https://tools.ietf.org/html/rfc6749#section-4.1.2
    const CODE_RESULT_PARAM: &str = "code";
    const STATE_RESULT_PARAM: &str = "state";
    // Token request - https://tools.ietf.org/html/rfc7636#section-4.5
    #[derive(Serialize)]
    struct TokenRequest<'a> {
        client_id: &'a str,
        code_verifier: &'a str,
        code: &'a str,
        grant_type: &'a str,
        redirect_uri: &'a str,
    }
    const GRANT_TYPE_PARAM_VALUE: &str = "authorization_code";
    // Token response - https://tools.ietf.org/html/rfc6749#section-5.1
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        token_type: String,
        expires_in: u64, // Technically not required by the spec
    }
    const TOKEN_TYPE_RESULT_PARAM_VALUE: &str = "bearer"; // case-insensitive

    const NUM_CODE_VERIFIER_BYTES: usize = 256 / 8;

    pub struct State {
        pub auth_url: String,
        pub auth_state_value: String,
        pub code_tx: mpsc::SyncSender<String>,
        pub shutdown_tx: Option<oneshot::Sender<()>>,
    }

    lazy_static! {
        pub static ref STATE: Mutex<Option<State>> = Mutex::new(None);
    }

    pub fn generate_verifier_and_challenge() -> Result<(String, String)> {
        let mut code_verifier_bytes = vec![0; NUM_CODE_VERIFIER_BYTES];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut code_verifier_bytes);
        let code_verifier = base64::encode_config(&code_verifier_bytes, base64::URL_SAFE_NO_PAD);
        let mut hasher = Sha256::new();
        hasher.update(&code_verifier);
        let code_challenge = base64::encode_config(&hasher.finalize(), base64::URL_SAFE_NO_PAD);
        Ok((code_verifier, code_challenge))
    }

    pub fn finish_url(
        client_id: &str,
        url: &mut Url,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(CODE_CHALLENGE_PARAM, code_challenge)
            .append_pair(CODE_CHALLENGE_METHOD_PARAM, CODE_CHALLENGE_METHOD_VALUE)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    fn handle_code_response(params: HashMap<String, String>) -> Result<(String, String)> {
        let code = params
            .get(CODE_RESULT_PARAM)
            .context("No code found in response")?;
        let state = params
            .get(STATE_RESULT_PARAM)
            .context("No state found in response")?;
        Ok((code.to_owned(), state.to_owned()))
    }

    fn handle_token_response(res: TokenResponse) -> Result<(String, Instant)> {
        let token = res.access_token;
        if res.token_type.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!(
                "Token type in response is not {}",
                TOKEN_TYPE_RESULT_PARAM_VALUE
            )
        }
        // Calculate ASAP the actual time at which the token will expire
        let expires_at = Instant::now() + Duration::from_secs(res.expires_in);
        Ok((token, expires_at))
    }

    const SUCCESS_AFTER_REDIRECT: &str = r##"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>In-browser step of authentication complete, you can now close this page!</body>
    </html>
    "##;

    pub async fn serve(req: Request<Body>) -> Result<Response<Body>> {
        let mut state = STATE.lock().unwrap();
        let state = state.as_mut().unwrap();
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => html_response(REDIRECT_WITH_AUTH_JSON),
            (&Method::GET, "/auth_detail.json") => json_response(&state.auth_url)?,
            (&Method::GET, "/redirect") => {
                let query_pairs = query_pairs(&req.uri().to_string())?;
                let (code, auth_state) = handle_code_response(query_pairs)
                    .context("Failed to handle response from redirect")?;
                if auth_state != state.auth_state_value {
                    return Err(anyhow!("Mismatched auth states after redirect"));
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state.code_tx.send(code).unwrap();
                state.shutdown_tx.take().unwrap().send(()).unwrap();
                html_response(SUCCESS_AFTER_REDIRECT)
            }
            _ => {
                warn!("Route not found");
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body("".into())?
            }
        };

        Ok(response)
    }

    use futures_03::task as task_03;
    use std::result;

    pub struct CodeGrant;

    impl hyper::service::Service<Request<Body>> for CodeGrant {
        type Response = Response<Body>;
        type Error = anyhow::Error;
        type Future = std::pin::Pin<
            Box<dyn futures_03::Future<Output = result::Result<Self::Response, Self::Error>>>,
        >;

        fn poll_ready(
            &mut self,
            cx: &mut task_03::Context<'_>,
        ) -> task_03::Poll<result::Result<(), Self::Error>> {
            task_03::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let fut = async move { serve(req).await };
            Box::pin(fut)
        }
    }

    pub fn code_to_token(
        token_url: &str,
        client_id: &str,
        code_verifier: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String> {
        let token_request = TokenRequest {
            client_id,
            code_verifier,
            code,
            grant_type: GRANT_TYPE_PARAM_VALUE,
            redirect_uri,
        };
        let client = reqwest::blocking::Client::new();
        let mut res = client.post(token_url).json(&token_request).send()?;
        if !res.status().is_success() {
            bail!(
                "Sending code to {} failed, HTTP error: {}",
                token_url,
                res.status()
            )
        }

        let (token, expires_at) = handle_token_response(
            res.json()
                .context("Failed to parse token response as JSON")?,
        )?;
        if expires_at - Instant::now() < MIN_TOKEN_VALIDITY {
            warn!(
                "Token retrieved expires in under {}",
                MIN_TOKEN_VALIDITY_WARNING
            );
            eprintln!(
                "sccache: Token retrieved expires in under {}",
                MIN_TOKEN_VALIDITY_WARNING
            );
        }
        Ok(token)
    }
}

mod implicit {
    use super::{
        html_response, json_response, query_pairs, MIN_TOKEN_VALIDITY, MIN_TOKEN_VALIDITY_WARNING,
        REDIRECT_WITH_AUTH_JSON,
    };
    use futures::future;
    use futures::sync::oneshot;
    use hyper::{Body, Method, Request, Response, StatusCode};
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use url::Url;

    use crate::errors::*;

    // Request - https://tools.ietf.org/html/rfc6749#section-4.2.1
    const CLIENT_ID_PARAM: &str = "client_id";
    const REDIRECT_PARAM: &str = "redirect_uri";
    const RESPONSE_TYPE_PARAM: &str = "response_type";
    const RESPONSE_TYPE_PARAM_VALUE: &str = "token";
    const STATE_PARAM: &str = "state";
    // Response - https://tools.ietf.org/html/rfc6749#section-4.2.2
    const TOKEN_RESULT_PARAM: &str = "access_token";
    const TOKEN_TYPE_RESULT_PARAM: &str = "token_type";
    const TOKEN_TYPE_RESULT_PARAM_VALUE: &str = "bearer"; // case-insensitive
    const EXPIRES_IN_RESULT_PARAM: &str = "expires_in"; // Technically not required by the spec
    const STATE_RESULT_PARAM: &str = "state";

    pub struct State {
        pub auth_url: String,
        pub auth_state_value: String,
        pub token_tx: mpsc::SyncSender<String>,
        pub shutdown_tx: Option<oneshot::Sender<()>>,
    }

    lazy_static! {
        pub static ref STATE: Mutex<Option<State>> = Mutex::new(None);
    }

    pub fn finish_url(client_id: &str, url: &mut Url, redirect_uri: &str, state: &str) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    fn handle_response(params: HashMap<String, String>) -> Result<(String, Instant, String)> {
        let token = params
            .get(TOKEN_RESULT_PARAM)
            .context("No token found in response")?;
        let bearer = params
            .get(TOKEN_TYPE_RESULT_PARAM)
            .context("No token type found in response")?;
        if bearer.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!(
                "Token type in response is not {}",
                TOKEN_TYPE_RESULT_PARAM_VALUE
            )
        }
        let expires_in = params
            .get(EXPIRES_IN_RESULT_PARAM)
            .context("No expiry found in response")?;
        // Calculate ASAP the actual time at which the token will expire
        let expires_at = Instant::now()
            + Duration::from_secs(
                expires_in
                    .parse()
                    .map_err(|_| anyhow!("Failed to parse expiry as integer"))?,
            );
        let state = params
            .get(STATE_RESULT_PARAM)
            .context("No state found in response")?;
        Ok((token.to_owned(), expires_at, state.to_owned()))
    }

    const SAVE_AUTH_AFTER_REDIRECT: &str = r##"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>
        <script>
        function writemsg(m) {
            document.body.appendChild(document.createTextNode(m.toString()));
            document.body.appendChild(document.createElement('br'));
        }
        function go() {
            writemsg('Saving authentication details...');
            var qs = window.location.hash.slice(1);
            if (qs.length === 0) {
                writemsg("ERROR: No URL hash returned from authorizer");
                return
            }
            fetch('/save_auth?' + qs, { method: 'POST' }).then(function (response) {
                if (!response.ok) {
                    throw 'Error during saving authentication - ' + response.status + ': ' + response.statusText;
                }
                writemsg('Authentication complete, you can now close this page!');
            }).catch(writemsg);
        }
        go();
        </script>
    </body>
    </html>
    "##;

    pub async fn serve(req: Request<Body>) -> Result<Response<Body>> {
        let mut state = STATE.lock().unwrap();
        let state = state.as_mut().unwrap();
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => html_response(REDIRECT_WITH_AUTH_JSON),
            (&Method::GET, "/auth_detail.json") => json_response(&state.auth_url)?,
            (&Method::GET, "/redirect") => html_response(SAVE_AUTH_AFTER_REDIRECT),
            (&Method::POST, "/save_auth") => {
                let query_pairs = query_pairs(&req.uri().to_string())?;
                let (token, expires_at, auth_state) =
                    handle_response(query_pairs).context("Failed to save auth after redirect")?;
                if auth_state != state.auth_state_value {
                    return Err(anyhow!("Mismatched auth states after redirect"));
                }
                if expires_at - Instant::now() < MIN_TOKEN_VALIDITY {
                    warn!(
                        "Token retrieved expires in under {}",
                        MIN_TOKEN_VALIDITY_WARNING
                    );
                    eprintln!(
                        "sccache: Token retrieved expires in under {}",
                        MIN_TOKEN_VALIDITY_WARNING
                    );
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state.token_tx.send(token).unwrap();
                state.shutdown_tx.take().unwrap().send(()).unwrap();
                json_response(&"")?
            }
            _ => {
                warn!("Route not found");
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body("".into())
                    .unwrap()
            }
        };

        Ok(response)
    }
}

use futures_03::task as task_03;
use std::error;
use std::fmt;
use std::result;

/// a better idea
pub struct ServiceFnWrapper<F, R> {
    f: F,
    _phantom: std::marker::PhantomData<R>,
}

impl<F, R> ServiceFnWrapper<F, R> {
    pub fn new(f: F) -> Self {
        Self {
            f,
            _phantom: Default::default(),
        }
    }
}

impl<R, F: ServeFn<R>> Service<Request<Body>> for ServiceFnWrapper<F, R>
where
    R: 'static + Send + futures_03::Future<Output = result::Result<Self::Response, Self::Error>>,
{
    type Error = hyper::Error;
    type Response = hyper::Response<hyper::Body>;
    type Future = Pin<
        Box<
            dyn 'static
                + Send
                + futures_03::Future<Output = result::Result<Self::Response, Self::Error>>,
        >,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut task_03::Context<'_>,
    ) -> task_03::Poll<result::Result<(), Self::Error>> {
        task_03::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let serve = self.f;
        // make it gracious

        let fut = async move {
            let uri = req.uri().to_owned();
            let res = serve(req).await;
            res.or_else(|e| {
                // `{:?}` prints the full cause chain and backtrace.
                let body = format!("{:?}", e);
                eprintln!(
                    "sccache: Error during a request to {} on the client auth web server\n{}",
                    uri, body
                );
                let len = body.len();
                let builder = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR);
                let res = builder
                    .set_header(ContentType::text())
                    .set_header(ContentLength(len as u64))
                    .body(body.into())
                    .unwrap();
                Ok::<Self::Response, Self::Error>(res)
            })
        };

        Box::pin(fut)
    }
}
use hyper::server::conn::AddrStream;

/// A service to spawn other services
///
/// Needed to reduce the shit generic surface of Fn
struct ServiceSpawner<F, R> {
    spawn: Box<
        dyn 'static
            + Send
            + for<'t> Fn(
                &'t AddrStream,
            ) -> Pin<
                Box<
                    dyn 'static
                        + Send
                        + futures_03::Future<
                            Output = result::Result<ServiceFnWrapper<F, R>, hyper::Error>,
                        >,
                >,
            >,
    >,
    _phantom: std::marker::PhantomData<R>,
}

impl<F, R> ServiceSpawner<F, R> {
    fn new<G>(spawn: G) -> Self
    where
        G: 'static
            + Send
            + for<'t> Fn(
                &'t AddrStream,
            ) -> Pin<
                Box<
                    dyn 'static
                        + Send
                        + futures_03::Future<
                            Output = result::Result<ServiceFnWrapper<F, R>, hyper::Error>,
                        >,
                >,
            >,
    {
        Self {
            spawn: Box::new(spawn),
            _phantom: Default::default(),
        }
    }
}

impl<'t, F, R> Service<&'t AddrStream> for ServiceSpawner<F, R>
where
    F: ServeFn<R>,
    R: Send,
{
    type Error = hyper::Error;
    type Response = ServiceFnWrapper<F, R>;
    type Future = Pin<
        Box<
            dyn 'static
                + Send
                + futures_03::Future<Output = result::Result<Self::Response, Self::Error>>,
        >,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut task_03::Context<'_>,
    ) -> task_03::Poll<result::Result<(), Self::Error>> {
        task_03::Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: &'t AddrStream) -> Self::Future {
        let fut = (self.spawn)(target);
        fut
    }
}

fn try_serve<'t, R, F: ServeFn<R>>(serve: F) -> Result<Server<AddrIncoming, ServiceSpawner<F, R>>> {
    // Try all the valid ports
    for &port in VALID_PORTS {
        let mut addrs = ("localhost", port)
            .to_socket_addrs()
            .expect("Failed to interpret localhost address to listen on");
        let addr = addrs
            .next()
            .expect("Expected at least one address in parsed socket address");

        // Hyper binds with reuseaddr and reuseport so binding won't fail as you'd expect on Linux
        match TcpStream::connect(addr) {
            // Already open
            Ok(_) => continue,
            // Doesn't seem to be open
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => (),
            Err(e) => {
                return Err(e).context(format!("Failed to check {} is available for binding", addr))
            }
        }

        let spawner = ServiceSpawner::new(move |addr: &AddrStream| {
            Box::pin(async move {
                let new_service = ServiceFnWrapper::new(serve);
                Ok(new_service)
            })
        });

        match Server::try_bind(&addr) {
            Ok(s) => return Ok(s.serve(spawner)),
            Err(ref err)
                if err
                    .source()
                    .and_then(|err| err.downcast_ref::<io::Error>())
                    .map(|err| err.kind() == io::ErrorKind::AddrInUse)
                    .unwrap_or(false) =>
            {
                continue
            }
            Err(e) => return Err(e).context(format!("Failed to bind to {}", addr)),
        }
    }
    bail!("Could not bind to any valid port: ({:?})", VALID_PORTS)
}

// https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce
pub fn get_token_oauth2_code_grant_pkce(
    client_id: &str,
    mut auth_url: Url,
    token_url: &str,
) -> Result<String> {
    let server = try_serve(code_grant_pkce::serve)?;
    let port = server.local_addr().port();

    let redirect_uri = format!("http://localhost:{}/redirect", port);
    let auth_state_value = Uuid::new_v4().to_simple_ref().to_string();
    let (verifier, challenge) = code_grant_pkce::generate_verifier_and_challenge()?;
    code_grant_pkce::finish_url(
        client_id,
        &mut auth_url,
        &redirect_uri,
        &auth_state_value,
        &challenge,
    );

    info!("Listening on http://localhost:{} with 1 thread.", port);
    println!(
        "sccache: Please visit http://localhost:{} in your browser",
        port
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (code_tx, code_rx) = mpsc::sync_channel(1);
    let state = code_grant_pkce::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        code_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    *code_grant_pkce::STATE.lock().unwrap() = Some(state);
    let shutdown_signal = shutdown_rx;

    let mut runtime = Runtime::new()?;
    runtime
        .block_on(server.with_graceful_shutdown(async move { 
            let x = shutdown_signal.await;
            let _ = x;
        } ))
        // .map_err(|e| {
        //     warn!(
        //         "Something went wrong while waiting for auth server shutdown: {}",
        //         e
        //     )
        // })?
        ;

    info!("Server finished, using code to request token");
    let code = code_rx
        .try_recv()
        .expect("Hyper shutdown but code not available - internal error");
    code_grant_pkce::code_to_token(token_url, client_id, &verifier, &code, &redirect_uri)
        .context("Failed to convert oauth2 code into a token")
}

// https://auth0.com/docs/api-auth/tutorials/implicit-grant
pub fn get_token_oauth2_implicit(client_id: &str, mut auth_url: Url) -> Result<String> {
    let server = try_serve(implicit::serve)?;
    let port = server.local_addr().port();

    let redirect_uri = format!("http://localhost:{}/redirect", port);
    let auth_state_value = Uuid::new_v4().to_simple_ref().to_string();
    implicit::finish_url(client_id, &mut auth_url, &redirect_uri, &auth_state_value);

    info!("Listening on http://localhost:{} with 1 thread.", port);
    println!(
        "sccache: Please visit http://localhost:{} in your browser",
        port
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (token_tx, token_rx) = mpsc::sync_channel(1);
    let state = implicit::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        token_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    *implicit::STATE.lock().unwrap() = Some(state);
    let shutdown_signal = shutdown_rx.map_err(|e| {
        warn!(
            "Something went wrong while waiting for auth server shutdown: {}",
            e
        )
    });

    let mut runtime = Runtime::new()?;
    runtime.block_on(server.with_graceful_shutdown(shutdown_signal))?;

    info!("Server finished, returning token");
    Ok(token_rx
        .try_recv()
        .expect("Hyper shutdown but token not available - internal error"))
}
