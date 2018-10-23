use futures::sync::oneshot;
use futures::Future;
use hyper;
use hyper::{Body, Request, Response, Server};
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, NewService, const_service, service_fn};
use serde::Serialize;
use serde_json;
use std::io;
use std::net::{ToSocketAddrs, TcpStream};
use std::sync::mpsc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use errors::*;

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

// These (arbitrary) ports need to be registered as valid redirect urls in the oauth provider you're using
pub const VALID_PORTS: &[u16] = &[12731, 32492, 56909];
// Warn if the token will expire in under this amount of time
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn html_response(body: &'static str) -> Response {
    Response::new()
        .with_body(body)
        .with_header(ContentType::html())
        .with_header(ContentLength(body.len() as u64))
}

fn json_response<T: Serialize>(data: &T) -> Response {
    let body = serde_json::to_vec(data).unwrap();
    let len = body.len();
    Response::new()
        .with_body(body)
        .with_header(ContentType::json())
        .with_header(ContentLength(len as u64))
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
    use base64;
    use crypto;
    use crypto::digest::Digest;
    use futures::future;
    use futures::sync::oneshot;
    use hyper::{Body, Method, Request, Response, StatusCode};
    use rand::{self, RngCore};
    use reqwest;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use super::{ONE_DAY, REDIRECT_WITH_AUTH_JSON, BoxFut, html_response, json_response};
    use url::Url;

    use errors::*;

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

    const NUM_CODE_VERIFIER_BYTES: usize = 256/8;
    type HASHER = crypto::sha2::Sha256;

    pub struct State {
        pub auth_url: String,
        pub auth_state_value: String,
        pub code_tx: mpsc::SyncSender<String>,
        pub shutdown_tx: Option<oneshot::Sender<()>>,
    }

    lazy_static! {
        pub static ref STATE: Mutex<Option<State>> = Mutex::new(None);
    }

    pub fn generate_verifier_and_challenge() -> (String, String) {
        let mut code_verifier_bytes = vec![0; NUM_CODE_VERIFIER_BYTES];
        let mut rng = rand::OsRng::new().unwrap();
        rng.fill_bytes(&mut code_verifier_bytes);
        let code_verifier = base64::encode_config(&code_verifier_bytes, base64::URL_SAFE_NO_PAD);
        let mut hasher = HASHER::new();
        hasher.input_str(&code_verifier);
        let mut code_challenge_bytes = vec![0; hasher.output_bytes()];
        hasher.result(&mut code_challenge_bytes);
        let code_challenge = base64::encode_config(&code_challenge_bytes, base64::URL_SAFE_NO_PAD);
        (code_verifier, code_challenge)
    }

    pub fn finish_url(client_id: &str, url: &mut Url, redirect_uri: &str, state: &str, code_challenge: &str) {
        url.query_pairs_mut()
            .append_pair(CLIENT_ID_PARAM, client_id)
            .append_pair(CODE_CHALLENGE_PARAM, code_challenge)
            .append_pair(CODE_CHALLENGE_METHOD_PARAM, CODE_CHALLENGE_METHOD_VALUE)
            .append_pair(REDIRECT_PARAM, redirect_uri)
            .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
            .append_pair(STATE_PARAM, state);
    }

    fn handle_code_response(params: HashMap<String, String>) -> Result<(String, String)> {
        let code = params.get(CODE_RESULT_PARAM).ok_or("No code found in response")?;
        let state = params.get(STATE_RESULT_PARAM).ok_or("No state found in response")?;
        Ok((code.to_owned(), state.to_owned()))
    }

    fn handle_token_response(res: TokenResponse) -> Result<(String, Instant)> {
        let token = res.access_token;
        if res.token_type.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!("Token type in response is not {}", TOKEN_TYPE_RESULT_PARAM_VALUE)
        }
        // Calculate ASAP the actual time at which the token will expire
        let expires_at = Instant::now() + Duration::from_secs(res.expires_in);
        Ok((token.to_owned(), expires_at))
    }

    const SUCCESS_AFTER_REDIRECT: &str = r##"<!doctype html>
    <html lang="en">
    <head><meta charset="utf-8"></head>
    <body>In-browser step of authentication complete, you can now close this page!</body>
    </html>
    "##;

    pub fn serve(req: Request<Body>) -> BoxFut {
        let mut state = STATE.lock().unwrap();
        let state = state.as_mut().unwrap();
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::Get, "/") => {
                html_response(REDIRECT_WITH_AUTH_JSON)
            },
            (&Method::Get, "/auth_detail.json") => {
                json_response(&state.auth_url)
            },
            (&Method::Get, "/redirect") => {
                let url = Url::parse("http://unused_base").unwrap().join(req.uri().as_ref()).unwrap();
                let query_pairs = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
                let (code, auth_state) = handle_code_response(query_pairs).unwrap();
                if auth_state != state.auth_state_value {
                    panic!("Mismatched auth states")
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state.code_tx.send(code).unwrap();
                state.shutdown_tx.take().unwrap().send(()).unwrap();
                html_response(SUCCESS_AFTER_REDIRECT)
            },
            _ => {
                warn!("Route not found");
                Response::new().with_status(StatusCode::NotFound)
            },
        };

        Box::new(future::ok(response))
    }

    pub fn code_to_token(token_url: &str, client_id: &str, code_verifier: &str, code: &str, redirect_uri: &str) -> Result<String> {
        let token_request = TokenRequest { client_id, code_verifier, code, grant_type: GRANT_TYPE_PARAM_VALUE, redirect_uri };
        let client = reqwest::Client::new();
        let mut res = client.post(token_url).json(&token_request).send()?;
        if !res.status().is_success() {
            bail!("Sending code to {} failed, HTTP error: {}", token_url, res.status())
        }

        let (token, expires_at) = handle_token_response(res.json().unwrap())?;
        if expires_at - Instant::now() < ONE_DAY  {
            warn!("Token retrieved expires in under one day")
        }
        Ok(token)
    }
}

mod implicit {
    use futures::future;
    use futures::sync::oneshot;
    use hyper::{Body, Method, Request, Response, StatusCode};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use super::{ONE_DAY, REDIRECT_WITH_AUTH_JSON, BoxFut, html_response, json_response};
    use url::Url;

    use errors::*;

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
        let token = params.get(TOKEN_RESULT_PARAM).ok_or("No token found in response")?;
        let bearer = params.get(TOKEN_TYPE_RESULT_PARAM).ok_or("No token type found in response")?;
        if bearer.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
            bail!("Token type in response is not {}", TOKEN_TYPE_RESULT_PARAM_VALUE)
        }
        let expires_in = params.get(EXPIRES_IN_RESULT_PARAM).ok_or("No expiry found in response")?;
        // Calculate ASAP the actual time at which the token will expire
        let expires_at = Instant::now() + Duration::from_secs(expires_in.parse().map_err(|_| "Failed to parse expiry as integer")?);
        let state = params.get(STATE_RESULT_PARAM).ok_or("No state found in response")?;
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

    pub fn serve(req: Request<Body>) -> BoxFut {
        let mut state = STATE.lock().unwrap();
        let state = state.as_mut().unwrap();
        debug!("Handling {} {}", req.method(), req.uri());
        let response = match (req.method(), req.uri().path()) {
            (&Method::Get, "/") => {
                html_response(REDIRECT_WITH_AUTH_JSON)
            },
            (&Method::Get, "/auth_detail.json") => {
                json_response(&state.auth_url)
            },
            (&Method::Get, "/redirect") => {
                html_response(SAVE_AUTH_AFTER_REDIRECT)
            },
            (&Method::Post, "/save_auth") => {
                let url = Url::parse("http://unused_base").unwrap().join(req.uri().as_ref()).unwrap();
                let query_pairs = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
                let (token, expires_at, auth_state) = handle_response(query_pairs).unwrap();
                if auth_state != state.auth_state_value {
                    panic!("Mismatched auth states")
                }
                if expires_at - Instant::now() < ONE_DAY  {
                    warn!("Token retrieved expires in under one day")
                }
                // Deliberately in reverse order for a 'happens-before' relationship
                state.token_tx.send(token).unwrap();
                state.shutdown_tx.take().unwrap().send(()).unwrap();
                json_response(&"")
            },
            _ => {
                warn!("Route not found");
                Response::new().with_status(StatusCode::NotFound)
            },
        };

        Box::new(future::ok(response))
    }
}

fn try_serve(serve: fn(Request<Body>) -> BoxFut) -> Result<Server<impl NewService<Request=Request, Response=Response<Body>, Error=hyper::error::Error> + 'static, Body>> {
    // Try all the valid ports
    for &port in VALID_PORTS {
        let mut addrs = ("localhost", port).to_socket_addrs().unwrap();
        let addr = addrs.next().unwrap();

        // Hyper binds with reuseaddr and reuseport so binding won't fail as you'd expect on Linux
        match TcpStream::connect(addr) {
            // Already open
            Ok(_) => continue,
            // Doesn't seem to be open
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => (),
            Err(e) => {
                return Err(Error::with_chain(e, format!("Failed to bind to {}", addr)))
            },
        }

        let new_service = const_service(service_fn(serve));
        match Http::new().bind(&addr, new_service) {
            Ok(s) => {
                return Ok(s)
            },
            Err(hyper::Error::Io(ref e)) if e.kind() == io::ErrorKind::AddrInUse => {
                continue
            },
            Err(e) => {
                return Err(Error::with_chain(e, format!("Failed to bind to {}", addr)))
            },
        }
    }
    bail!("Could not bind to any valid port: ({:?})", VALID_PORTS)
}

// https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce
pub fn get_token_oauth2_code_grant_pkce(client_id: &str, mut auth_url: Url, token_url: &str) -> Result<String> {
    let server = try_serve(code_grant_pkce::serve)?;
    let port = server.local_addr().unwrap().port();

    let redirect_uri = format!("http://localhost:{}/redirect", port);
    let auth_state_value = Uuid::new_v4().simple().to_string();
    let (verifier, challenge) = code_grant_pkce::generate_verifier_and_challenge();
    code_grant_pkce::finish_url(client_id, &mut auth_url, &redirect_uri, &auth_state_value, &challenge);

    info!("Listening on http://localhost:{} with 1 thread.", port);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (code_tx, code_rx) = mpsc::sync_channel(1);
    let state = code_grant_pkce::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        code_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    *code_grant_pkce::STATE.lock().unwrap() = Some(state);
    let shutdown_signal = shutdown_rx.map_err(|e| warn!("Something went wrong while waiting for auth server shutdown: {}", e));
    server.run_until(shutdown_signal)?;

    info!("Server finished, using code to request token");
    let code = code_rx.try_recv().expect("Hyper shutdown but code not available - internal error");
    code_grant_pkce::code_to_token(token_url, client_id, &verifier, &code, &redirect_uri)
        .chain_err(|| "Failed to convert oauth2 code into a token")
}

// https://auth0.com/docs/api-auth/tutorials/implicit-grant
pub fn get_token_oauth2_implicit(client_id: &str, mut auth_url: Url) -> Result<String> {
    let server = try_serve(implicit::serve)?;
    let port = server.local_addr().unwrap().port();

    let redirect_uri = format!("http://localhost:{}/redirect", port);
    let auth_state_value = Uuid::new_v4().simple().to_string();
    implicit::finish_url(client_id, &mut auth_url, &redirect_uri, &auth_state_value);

    info!("Listening on http://localhost:{} with 1 thread.", port);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (token_tx, token_rx) = mpsc::sync_channel(1);
    let state = implicit::State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        token_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    *implicit::STATE.lock().unwrap() = Some(state);
    let shutdown_signal = shutdown_rx.map_err(|e| warn!("Something went wrong while waiting for auth server shutdown: {}", e));
    server.run_until(shutdown_signal)?;

    info!("Server finished, returning token");
    Ok(token_rx.try_recv().expect("Hyper shutdown but token not available - internal error"))
}
