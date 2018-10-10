use futures::future;
use futures::sync::oneshot;
use futures::Future;
use hyper;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, const_service, service_fn};
use serde::Serialize;
use serde_json;
use std::collections::HashMap;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

use errors::*;

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

// These ports need to be registered as valid callback urls in the oauth provider you're using
const VALID_PORTS: &[u16] = &[12731, 32492, 56909];

// Implicit grant request - https://tools.ietf.org/html/rfc6749#section-4.2.1
const CALLBACK_PARAM: &str = "redirect_uri";
const RESPONSE_TYPE_PARAM: &str = "response_type";
const RESPONSE_TYPE_PARAM_VALUE: &str = "token";
const STATE_PARAM: &str = "state";
// Implicit grant response - https://tools.ietf.org/html/rfc6749#section-4.2.2
const TOKEN_RESULT_PARAM: &str = "access_token";
const TOKEN_TYPE_RESULT_PARAM: &str = "token_type";
const TOKEN_TYPE_RESULT_PARAM_VALUE: &str = "bearer"; // case-insensitive
const EXPIRES_IN_RESULT_PARAM: &str = "expires_in"; // Technically not required by the spec
const STATE_RESULT_PARAM: &str = "state";

fn finish_implicit_grant_url(url: &mut Url, callback_url: &str, state: &str) {
    url.query_pairs_mut()
        .append_pair(CALLBACK_PARAM, callback_url)
        .append_pair(RESPONSE_TYPE_PARAM, RESPONSE_TYPE_PARAM_VALUE)
        .append_pair(STATE_PARAM, state);
}
fn handle_implicit_grant_response(params: HashMap<String, String>) -> Result<(String, Instant, String)> {
    let token = params.get(TOKEN_RESULT_PARAM).ok_or("No token found in response")?;
    let bearer = params.get(TOKEN_TYPE_RESULT_PARAM).ok_or("No token type found in response")?;
    if bearer.to_lowercase() != TOKEN_TYPE_RESULT_PARAM_VALUE {
        bail!("Token type in response is not {}", TOKEN_TYPE_RESULT_PARAM_VALUE)
    }
    let expires_in = params.get(EXPIRES_IN_RESULT_PARAM).ok_or("No expiry found in response")?;
    // Calculate ASAP the actual time at which the token will expire
    let expires_at = Instant::now() + Duration::new(expires_in.parse().map_err(|_| "Failed to parse expiry as integer")?, 0);
    let state = params.get(STATE_RESULT_PARAM).ok_or("No state found in response")?;
    Ok((token.to_owned(), expires_at, state.to_owned()))
}

struct State {
    auth_url: String,
    auth_state_value: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    token_tx: mpsc::SyncSender<String>,
}

lazy_static! {
    static ref STATE: Mutex<Option<State>> = Mutex::new(None);
}

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

const ROOT: &str = r##"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
</head>
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

const CALLBACK: &str = r##"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
</head>
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

fn serve(req: Request<Body>) -> BoxFut {
    let mut state = STATE.lock().unwrap();
    let state = state.as_mut().unwrap();
    debug!("Handling {} {}", req.method(), req.uri());
    let response = match (req.method(), req.uri().path()) {
        (&Method::Get, "/") => {
            html_response(ROOT)
        },
        (&Method::Get, "/auth_detail.json") => {
            json_response(&state.auth_url)
        },
        (&Method::Get, "/callback") => {
            html_response(CALLBACK)
        },
        (&Method::Post, "/save_auth") => {
            let url = Url::parse("http://unused_base").unwrap().join(req.uri().as_ref()).unwrap();
            let query_pairs = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
            let (token, expires_at, auth_state) = handle_implicit_grant_response(query_pairs).unwrap();
            if auth_state != state.auth_state_value {
                panic!("Mismatched auth states")
            }
            if expires_at - Instant::now() < Duration::from_secs(24 * 60 * 60)  {
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

pub fn get_token_oauth2_implicit(mut auth_url: Url) -> Result<String> {
    // Try all the valid ports
    let mut server = None;
    for &port in VALID_PORTS {
        let mut addrs = ("localhost", port).to_socket_addrs().unwrap();
        let addr = addrs.next().unwrap();

        let new_service = const_service(service_fn(serve));
        match Http::new().bind(&addr, new_service) {
            Ok(s) => {
                server = Some(s);
                break
            },
            Err(hyper::Error::Io(ref e)) if e.kind() == io::ErrorKind::AddrInUse => {
                continue
            },
            Err(e) => {
                return Err(Error::with_chain(e, format!("Failed to bind to {}", addr)))
            },
        }
    }

    let server = match server {
        Some(s) => s,
        None => bail!("Could not bind to any valid port: ({:?})", VALID_PORTS),
    };
    let port = server.local_addr().unwrap().port();

    let callback_url = format!("http://localhost:{}/callback", port);
    let auth_state_value = Uuid::new_v4().simple().to_string();
    finish_implicit_grant_url(&mut auth_url, &callback_url, &auth_state_value);

    info!("Listening on http://localhost:{} with 1 thread.", port);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (token_tx, token_rx) = mpsc::sync_channel(1);
    let state = State {
        auth_url: auth_url.to_string(),
        auth_state_value,
        token_tx,
        shutdown_tx: Some(shutdown_tx),
    };
    *STATE.lock().unwrap() = Some(state);
    let shutdown_signal = shutdown_rx.map_err(|e| warn!("Something went wrong while waiting for auth server shutdown: {}", e));
    server.run_until(shutdown_signal)?;

    info!("Server finished, returning token");
    Ok(token_rx.try_recv().expect("Hyper shutdown but token not available - internal error"))
}
