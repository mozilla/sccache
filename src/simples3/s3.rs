// Originally from https://github.com/rust-lang/crates.io/blob/master/src/s3/lib.rs
//#![deny(warnings)]

use std::ascii::AsciiExt;
use std::fmt;
use std::io::prelude::*;
use std::io;

use simples3::credential::*;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use hyper::{self,header};
use rustc_serialize::base64::{ToBase64, STANDARD};
use time;


#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
/// Whether or not to use SSL.
pub enum Ssl {
    /// Use SSL.
    Yes,
    /// Do not use SSL.
    No,
}

fn base_url(bucket_name: &str, ssl: Ssl, region: Option<&str>) -> String {
    format!("{}://{}.s3{}.amazonaws.com/",
            match ssl {
                Ssl::Yes => "https",
                Ssl::No => "http",
            },
            bucket_name,
            match region {
                Some(ref r) => format!("-{}", r),
                None => String::new(),
            })
}

fn hmac<D: Digest>(d: D, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(d, key);
    hmac.input(data);
    hmac.result().code().iter().map(|b| *b).collect::<Vec<u8>>()
}

fn signature(string_to_sign: &str, signing_key: &str) -> String {
    hmac(Sha1::new(), signing_key.as_bytes(), string_to_sign.as_bytes()).to_base64(STANDARD)
}

/// An S3 bucket.
pub struct Bucket {
    name: String,
    base_url: String,
    client: hyper::Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bucket(name={}, base_url={})", self.name, self.base_url)
    }
}

/// Errors from making S3 requests.
#[derive(Debug)]
pub enum S3Error {
    HyperError(hyper::Error),
    IOError(io::Error),
    BadHTTPStatus(hyper::status::StatusCode),
}

impl Bucket {
    pub fn new(name: &str, ssl: Ssl) -> Bucket {
        let base_url = base_url(&name, ssl, None);
        Bucket {
            name: name.to_owned(),
            base_url: base_url,
            client: hyper::Client::new(),
        }
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let url = format!("{}{}", self.base_url, key);
        debug!("GET {}", url);
        match self.client.get(&url).send() {
            Err(e) => Err(S3Error::HyperError(e)),
            Ok(mut res) => {
                if res.status.class() == hyper::status::StatusClass::Success {
                    let mut body = vec!();
                    res.read_to_end(&mut body)
                        .or_else(|e| Err(S3Error::IOError(e)))
                        .map(|_| body)
                } else {
                    Err(S3Error::BadHTTPStatus(res.status))
                }
            }
        }
    }

    pub fn put(&self, key: &str, content: &[u8],
               creds: &AwsCredentials)
               -> Result<(), S3Error> {
        let content_type = "application/octet-stream";
        let date = time::now().rfc822z().to_string();
        let mut headers = header::Headers::new();
        let mut canonical_headers = String::new();
        let token = creds.token().as_ref().map(|s| s.as_str());
        // Keep the list of header values sorted!
        for (header, maybe_value) in vec![
            ("x-amz-security-token", token),
            ("x-amz-storage-class", Some("REDUCED_REDUNDANCY")),
            ] {
            if let Some(ref value) = maybe_value {
                headers.set_raw(header, vec!(value.as_bytes().to_vec()));
                canonical_headers.push_str(format!("{}:{}\n", header.to_ascii_lowercase(), value).as_ref());
            }
        }
        let auth = self.auth("PUT", &date, key, "", &canonical_headers, content_type, creds);
        headers.set_raw("Date", vec!(date.into_bytes()));
        headers.set(header::ContentType(content_type.parse().unwrap()));
        headers.set(header::CacheControl(vec![
            // Two weeks
            header::CacheDirective::MaxAge(1296000)
                ]));
        headers.set_raw("Authorization", vec!(auth.into_bytes()));
        let url = format!("{}{}", self.base_url, key);
        debug!("PUT {}", url);

        match self.client.put(&url)
            .body(content)
            .headers(headers)
            .send() {
                Err(e) => {
                    trace!("PUT failed with error: {:?}", e);
                    Err(S3Error::HyperError(e))
                }
                Ok(res) => {
                    if res.status.class() == hyper::status::StatusClass::Success {
                        trace!("PUT succeeded");
                        Ok(())
                    } else {
                        trace!("PUT failed with HTTP status: {}", res.status);
                        Err(S3Error::BadHTTPStatus(res.status))
                    }
                }
            }
    }

    // http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    fn auth(&self, verb: &str, date: &str, path: &str,
            md5: &str, headers: &str, content_type: &str, creds: &AwsCredentials) -> String {
        let string = format!("{verb}\n{md5}\n{ty}\n{date}\n{headers}{resource}",
                             verb = verb,
                             md5 = md5,
                             ty = content_type,
                             date = date,
                             headers = headers,
                             resource = format!("/{}/{}", self.name, path));
        let signature = signature(&string, creds.aws_secret_access_key());
        format!("AWS {}:{}", creds.aws_access_key_id(), signature)
    }
}
