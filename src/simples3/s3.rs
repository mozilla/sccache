// Originally from https://github.com/rust-lang/crates.io/blob/master/src/s3/lib.rs
//#![deny(warnings)]

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt;

use crate::simples3::credential::*;
use hmac::{Hmac, Mac};
use hyper::header::HeaderValue;
use hyper::Method;
use hyperx::header;
use reqwest::{Client, Request};
use sha1::Sha1;

use crate::errors::*;
use crate::util::{DateTimeExt, HeadersExt};

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
/// Whether or not to use SSL.
pub enum Ssl {
    /// Use SSL.
    Yes,
    /// Do not use SSL.
    No,
}

fn base_url(endpoint: &str, ssl: Ssl) -> String {
    format!(
        "{}://{}/",
        match ssl {
            Ssl::Yes => "https",
            Ssl::No => "http",
        },
        endpoint
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
    hmac.update(data);
    hmac.finalize().into_bytes().as_slice().to_vec()
}

fn signature(string_to_sign: &str, signing_key: &str) -> String {
    let s = hmac(signing_key.as_bytes(), string_to_sign.as_bytes());
    base64::encode_config(&s, base64::STANDARD)
}

/// An S3 bucket.
pub struct Bucket {
    name: String,
    base_url: String,
    client: Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={}, base_url={})", self.name, self.base_url)
    }
}

impl Bucket {
    pub fn new(name: &str, endpoint: &str, ssl: Ssl) -> Result<Bucket> {
        let base_url = base_url(endpoint, ssl);
        Ok(Bucket {
            name: name.to_owned(),
            base_url,
            client: Client::new(),
        })
    }

    pub async fn get(&self, key: &str, creds: Option<&AwsCredentials>) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, key);
        debug!("GET {}", url);
        let url2 = url.clone();
        let mut request = Request::new(Method::GET, url.parse().unwrap());
        if let Some(creds) = creds {
            let mut canonical_headers = String::new();

            if let Some(token) = creds.token().as_ref().map(|s| s.as_str()) {
                request.headers_mut().insert(
                    "x-amz-security-token",
                    HeaderValue::from_str(token).expect("Invalid `x-amz-security-token` header"),
                );
                canonical_headers
                    .push_str(format!("{}:{}\n", "x-amz-security-token", token).as_ref());
            }
            let date = chrono::offset::Utc::now().to_rfc7231();
            let auth = self.auth("GET", &date, key, "", &canonical_headers, "", creds);
            request.headers_mut().insert(
                "Date",
                HeaderValue::from_str(&date).expect("Invalid date header"),
            );
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&auth).expect("Invalid authentication"),
            );
        }

        let res = self
            .client
            .execute(request)
            .await
            .with_context(move || format!("failed GET: {}", url))?;

        if res.status().is_success() {
            let body = res.bytes().await.context("failed to read HTTP body")?;
            info!("Read {} bytes from {}", body.len(), url2);

            Ok(body.into_iter().collect())
        } else {
            Err(BadHttpStatusError(res.status()).into())
        }
    }

    pub async fn put(&self, key: &str, content: Vec<u8>, creds: &AwsCredentials) -> Result<()> {
        let url = format!("{}{}", self.base_url, key);
        debug!("PUT {}", url);
        let mut request = Request::new(Method::PUT, url.parse().unwrap());

        let content_type = "application/octet-stream";
        let date = chrono::offset::Utc::now().to_rfc7231();
        let mut canonical_headers = String::new();
        let token = creds.token().as_ref().map(|s| s.as_str());
        // Keep the list of header values sorted!
        for (header, maybe_value) in &[("x-amz-security-token", token)] {
            if let Some(ref value) = maybe_value {
                request.headers_mut().insert(
                    *header,
                    HeaderValue::from_str(value)
                        .unwrap_or_else(|_| panic!("Invalid `{}` header", header)),
                );
                canonical_headers
                    .push_str(format!("{}:{}\n", header.to_ascii_lowercase(), value).as_ref());
            }
        }
        let auth = self.auth(
            "PUT",
            &date,
            key,
            "",
            &canonical_headers,
            content_type,
            creds,
        );
        request.headers_mut().insert(
            "Date",
            HeaderValue::from_str(&date).expect("Invalid date header"),
        );
        request
            .headers_mut()
            .set(header::ContentType(content_type.parse().unwrap()));
        request
            .headers_mut()
            .set(header::ContentLength(content.len() as u64));
        request.headers_mut().set(header::CacheControl(vec![
            // Two weeks
            header::CacheDirective::MaxAge(1_296_000),
        ]));
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&auth).expect("Invalid authentication"),
        );
        *request.body_mut() = Some(content.into());

        match self.client.execute(request).await {
            Ok(res) => {
                if res.status().is_success() {
                    trace!("PUT succeeded");
                    Ok(())
                } else {
                    trace!("PUT failed with HTTP status: {}", res.status());
                    Err(BadHttpStatusError(res.status()).into())
                }
            }
            Err(e) => {
                trace!("PUT failed with error: {:?}", e);
                Err(e.into())
            }
        }
    }

    // http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    #[allow(clippy::too_many_arguments)]
    fn auth(
        &self,
        verb: &str,
        date: &str,
        path: &str,
        md5: &str,
        headers: &str,
        content_type: &str,
        creds: &AwsCredentials,
    ) -> String {
        let string = format!(
            "{verb}\n{md5}\n{ty}\n{date}\n{headers}/{name}/{path}",
            verb = verb,
            md5 = md5,
            ty = content_type,
            date = date,
            headers = headers,
            name = self.name,
            path = path,
        );
        let signature = signature(&string, creds.aws_secret_access_key());
        format!("AWS {}:{}", creds.aws_access_key_id(), signature)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signature() {
        assert_eq!(
            signature("/foo/bar\nbar", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "mwbstmHPMEJjTe2ksXi5H5f0c8U="
        );

        assert_eq!(
            signature("/bar/foo\nbaz", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "F9gZMso3+P+QTEyRKQ6qhZ1YM6o="
        );
    }
}
