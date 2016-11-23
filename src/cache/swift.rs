
use cache::{
    Cache,
    CacheRead,
    CacheWrite,
    CacheWriteFuture,
    CacheWriteWriter,
    Storage,
};
use futures::{self,Future};

use rust_swiftclient::auth::sessions::KeystoneAuthV2;
use rust_swiftclient::auth::request::{
    RunSwiftRequest, SwiftConnection
};

use std::env;
use std::io::{
    self,
    Error,
    ErrorKind,
    Read,
};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// A cache that stores entries in Amazon S3.
#[derive(Clone)]
pub struct SwiftCache {
    /// Authentication provider
    swift: Arc<SwiftConnection<KeystoneAuthV2>>,
    swift_url: String
}

fn get_env_var(name: &str) -> String {
    match env::var(name) {
        Ok(val) => {return val;}
        Err(e) => {panic!("Missig environment variable: {} {}", name, e);}
    }
}

impl SwiftCache {
    pub fn new(swift_url: &str) -> io::Result<SwiftCache> {
        let auth_url = get_env_var("OS_AUTH_URL");
        let tenant_id = get_env_var("OS_TENANT_ID");
        let username = get_env_var("OS_USERNAME");
        let password = get_env_var("OS_PASSWORD");
        let region = Some(get_env_var("OS_REGION_NAME"));

        let ksauth = KeystoneAuthV2::new(username, password, tenant_id, auth_url, region);
        Ok(SwiftCache {
            swift: Arc::new(SwiftConnection::new(ksauth)),
            swift_url: String::from(swift_url),
        })
    }
}

impl Storage for SwiftCache {
    fn get(&self, key: &str) -> Cache {
        let r = self.swift.get_object(String::from(key));
        match r.run_request() {
            Ok(mut resp) => {
                let mut data = String::new();
                match resp.read_to_string(&mut data) {
                    Ok(_) => {
                        CacheRead::from(io::Cursor::new(data))
                            .map(Cache::Hit)
                            .unwrap_or_else(Cache::Error)
                    }
                    Err(e) => {
                        warn!("Error reading Swift response: {:?}", e);
                        Cache::Miss
                    }
                }
            }
            Err(e) => {
                warn!("Got Swift error: {:?}", e);
                Cache::Miss
            }
        }
    }

    fn start_put(&self, _key: &str) -> io::Result<CacheWrite> {
        // Just hand back an in-memory buffer.
        Ok(CacheWrite::new(io::Cursor::new(vec!())))
    }

    fn finish_put(&self, key: &str, entry: CacheWrite) -> CacheWriteFuture {
        let (complete, promise) = futures::oneshot();
        let swift = self.swift.clone();
        let key = key.to_owned();
        thread::spawn(move || {
            let start = Instant::now();
            complete.complete(
                entry.finish().and_then(|writer| {
                    match writer {
                        // This should never happen.
                        CacheWriteWriter::File(_) => Err(Error::new(ErrorKind::Other, "Bad CacheWrite?")),
                        CacheWriteWriter::Cursor(c) => {
                            let data = c.into_inner();
                            let r = swift.put_object(String::from(key), data);
                            match r.run_request() {
                                Ok(_) => {
                                    Ok(start.elapsed())
                                }
                                Err(e) => {
                                    Err(Error::new(ErrorKind::Other, format!("Error putting cache entry to swift: {:?}", e)))
                                }
                            }
                        }
                    }
                }).map_err(|e| format!("{}", e)));
        });
        promise.boxed()
    }

    fn get_location(&self) -> String {
        format!("Swift, url: {}", self.swift_url)
    }
}
