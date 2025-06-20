#![deny(rust_2018_idioms)]
#![cfg(feature = "dist-client")]

use fs_err as fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thirtyfour_sync::prelude::*;

const LOCAL_AUTH_BASE_URL: &str = "http://localhost:12731/";

const USERNAME_SELECTOR: &str = ".auth0-lock-input-email .auth0-lock-input";
const PASSWORD_SELECTOR: &str = ".auth0-lock-input-password .auth0-lock-input";
const LOGIN_SELECTOR: &str = ".auth0-lock-submit";

const BROWSER_RETRY_WAIT: Duration = Duration::from_secs(1);
const BROWSER_MAX_WAIT: Duration = Duration::from_secs(10);

// The configuration below is for the sccache-test tenant under aidanhs' auth0 account. There
// is one user, one api and two applications. There is a rule ensuring that oauth access is
// never granted to the built-in auth0 tenant management API (though the worst that could happen
// is tests start failing because someone deliberately messes up the configuration).

const TEST_USERNAME: &str = "test@example.com";
const TEST_PASSWORD: &str = "test1234";

fn generate_code_grant_pkce_auth_config() -> sccache::config::DistAuth {
    sccache::config::DistAuth::Oauth2CodeGrantPKCE {
        client_id: "Xmbl6zRW1o1tJ5LQOz0p65NwY47aMO7A".to_owned(),
        auth_url:
            "https://sccache-test.auth0.com/authorize?audience=https://sccache-dist-test-api/"
                .to_owned(),
        token_url: "https://sccache-test.auth0.com/oauth/token".to_owned(),
    }
}
fn generate_implicit_auth_config() -> sccache::config::DistAuth {
    sccache::config::DistAuth::Oauth2Implicit {
        client_id: "TTborSAyjBnSi1W11201ZzNu9gSg63bq".to_owned(),
        auth_url:
            "https://sccache-test.auth0.com/authorize?audience=https://sccache-dist-test-api/"
                .to_owned(),
    }
}

fn config_with_dist_auth(
    tmpdir: &Path,
    auth_config: sccache::config::DistAuth,
) -> sccache::config::FileConfig {
    sccache::config::FileConfig {
        cache: Default::default(),
        dist: sccache::config::DistConfig {
            auth: auth_config,
            scheduler_url: None,
            cache_dir: tmpdir.join("unused-cache"),
            toolchains: vec![],
            toolchain_cache_size: 0,
            rewrite_includes_only: true,
        },
        server_startup_timeout_ms: None,
    }
}

fn sccache_command() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin("sccache"))
}

fn retry<F: FnMut() -> Option<T>, T>(interval: Duration, until: Duration, mut f: F) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < until {
        if let Some(res) = f() {
            return Some(res);
        } else {
            thread::sleep(interval)
        }
    }
    None
}

trait DriverExt {
    fn wait_for_element(&self, selector: &str) -> Result<(), ()>;
    fn wait_on_url<F: Fn(&str) -> bool>(&self, condition: F) -> Result<(), ()>;
}
impl DriverExt for WebDriver {
    fn wait_for_element(&self, selector: &str) -> Result<(), ()> {
        retry(BROWSER_RETRY_WAIT, BROWSER_MAX_WAIT, || {
            self.find_element(By::Css(selector)).ok()
        })
        .map(|_| ())
        .ok_or(())
    }
    fn wait_on_url<F: Fn(&str) -> bool>(&self, condition: F) -> Result<(), ()> {
        let start = Instant::now();
        while start.elapsed() < BROWSER_MAX_WAIT {
            match self.current_url() {
                Ok(ref url) if condition(url) => return Ok(()),
                Ok(_) | Err(_) => thread::sleep(BROWSER_RETRY_WAIT),
            }
        }
        Err(())
    }
}

// With reference to https://github.com/mozilla-iam/cis_tests/blob/ef7740b/pages/auth0.py
fn auth0_login(driver: &WebDriver, email: &str, password: &str) {
    driver.wait_for_element(USERNAME_SELECTOR).unwrap();
    thread::sleep(Duration::from_secs(1)); // Give the element time to get ready
    driver
        .find_element(By::Css(USERNAME_SELECTOR))
        .unwrap()
        .send_keys(email)
        .unwrap();
    driver
        .find_element(By::Css(PASSWORD_SELECTOR))
        .unwrap()
        .send_keys(password)
        .unwrap();
    driver
        .find_element(By::Css(LOGIN_SELECTOR))
        .unwrap()
        .click()
        .unwrap();
}

struct SeleniumContainer {
    cid: String,
}

fn check_output(output: &Output) {
    if !output.status.success() {
        println!(
            "===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        panic!()
    }
}

impl SeleniumContainer {
    fn new() -> Self {
        // https://github.com/SeleniumHQ/docker-selenium#running-the-images
        let cid = {
            // It's important to use net=host so that selenium can see pages hosted on localhost
            let args = &[
                "run",
                "--rm",
                "-d",
                "-v",
                "/dev/shm:/dev/shm",
                "--net",
                "host",
                "-e",
                "SE_OPTS=-debug",
                "selenium/standalone-chrome-debug:3.14.0",
            ];
            let output = Command::new("docker").args(args).output().unwrap();
            check_output(&output);
            let stdout = String::from_utf8(output.stdout).unwrap();
            stdout.trim().to_owned()
        };
        SeleniumContainer { cid }
    }
}

impl Drop for SeleniumContainer {
    fn drop(&mut self) {
        let Output { stdout, stderr, .. } = Command::new("docker")
            .args(["logs", &self.cid])
            .output()
            .unwrap();
        let output = Command::new("docker")
            .args(["kill", &self.cid])
            .output()
            .unwrap();

        println!(
            "====\n> selenium container <:\n## STDOUT\n{}\n\n## STDERR\n{}\n====",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        check_output(&output)
    }
}

#[test]
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64", feature = "dist-tests")),
    ignore
)]
fn test_auth() {
    // Make sure the client auth port isn't in use, as sccache will gracefully fall back
    let client_auth_port = sccache::dist::client_auth::VALID_PORTS[0];
    assert_eq!(
        TcpStream::connect(("localhost", client_auth_port))
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionRefused
    );

    // NOTE: if you want to debug selenium, you can comment out the three lines below and just use a local
    // selenium instance (download the standalone server and the chrome driver, running the former and putting the
    // latter on the PATH). Alternatively, because we use the '-debug' image you can use vnc with the password 'secret'.
    assert_eq!(
        TcpStream::connect(("localhost", 4444)).unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    let _selenium = SeleniumContainer::new();
    thread::sleep(Duration::from_secs(3));

    // Code grant PKCE
    println!("Testing code grant pkce auth");
    test_auth_with_config(generate_code_grant_pkce_auth_config());

    // Implicit
    println!("Testing implicit auth");
    test_auth_with_config(generate_implicit_auth_config());
}

fn test_auth_with_config(dist_auth: sccache::config::DistAuth) {
    let conf_dir = tempfile::Builder::new()
        .prefix("sccache-test-conf")
        .tempdir()
        .unwrap();
    let sccache_config = config_with_dist_auth(conf_dir.path(), dist_auth);
    let sccache_config_path = conf_dir.path().join("sccache-config.json");
    fs::File::create(&sccache_config_path)
        .unwrap()
        .write_all(&serde_json::to_vec(&sccache_config).unwrap())
        .unwrap();
    let sccache_cached_config_path = conf_dir.path().join("sccache-cached-config");
    let envs = vec![
        ("SCCACHE_LOG", "sccache=trace".into()),
        ("SCCACHE_CONF", sccache_config_path.into_os_string()),
        (
            "SCCACHE_CACHED_CONF",
            sccache_cached_config_path.clone().into_os_string(),
        ),
    ];

    println!("Starting sccache --dist-auth");
    let mut sccache_process = sccache_command()
        .arg("--dist-auth")
        .envs(envs)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(1)); // let the http server start up
    println!("Beginning in-browser auth");
    login();
    let status = retry(Duration::from_secs(1), Duration::from_secs(10), || {
        sccache_process.try_wait().unwrap()
    });
    match status {
        Some(s) => assert!(s.success()),
        None => {
            sccache_process.kill().unwrap();
            panic!("Waited too long for process to exit")
        }
    }
    println!("Validating cached config");
    let mut cached_config_string = String::new();
    fs::File::open(sccache_cached_config_path)
        .unwrap()
        .read_to_string(&mut cached_config_string)
        .unwrap();
    let cached_config: sccache::config::CachedFileConfig =
        toml::from_str(&cached_config_string).unwrap();
    assert_eq!(cached_config.dist.auth_tokens.len(), 1);
}

fn login() {
    let caps = DesiredCapabilities::chrome();
    let driver = WebDriver::new("http://localhost:4444/wd/hub", &caps).unwrap();
    println!("Started browser session");

    driver.get(LOCAL_AUTH_BASE_URL).unwrap();
    driver
        .wait_on_url(|url| url != LOCAL_AUTH_BASE_URL)
        .unwrap();
    auth0_login(&driver, TEST_USERNAME, TEST_PASSWORD);
    driver
        .wait_on_url(|url| url.starts_with(LOCAL_AUTH_BASE_URL))
        .unwrap();
    // Let any final JS complete
    thread::sleep(Duration::from_secs(1));

    let _ = driver.quit();
}
