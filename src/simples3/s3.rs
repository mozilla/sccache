//#![deny(warnings)]

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt;

use rusoto_core::HttpClient;
use rusoto_core::credential::AwsCredentials;
use futures::Future as _;
use rusoto_core::request::DispatchSignedRequest as _;

use crate::errors::*;

/// An S3 bucket.
pub struct Bucket {
    name: String,
    base_url: String,
    client: HttpClient,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={}, base_url={})", self.name, self.base_url)
    }
}

impl Bucket {
    pub fn new(name: &str, endpoint: &str) -> Result<Bucket> {
        Ok(Bucket {
            name: name.to_owned(),
            base_url: endpoint.to_string(),
            client: HttpClient::new()?,
        })
    }

    pub fn get(&self, key: &str, creds: &Option<AwsCredentials>) -> SFuture<Vec<u8>> {
        let key = format!("/{}/{}", self.name, key);
        let mut request = rusoto_core::signature::SignedRequest::new(
            "GET",
            "s3",
            &rusoto_core::region::Region::UsEast1,
            &key,
        );
        request.set_hostname(Some(self.base_url.clone()));
        request.scheme = Some("http".to_string());
        if let Some(creds) = creds {
            request.sign(creds);
        }

        Box::new(
            self.client
                .dispatch(request, None)
                .map_err(crate::errors::Error::from)
                .and_then(|res| res.buffer().map_err(crate::errors::Error::from))
                .and_then(|res| {
                    if res.status.is_success() {
                        Ok(res.body.to_vec())
                    } else {
                        warn!("{}", String::from_utf8_lossy(&res.body));
                        Err(ErrorKind::BadHTTPStatus(res.status.into()).into())
                    }
                })
        )
    }

    pub fn put(&self, key: &str, content: Vec<u8>, creds: &Option<AwsCredentials>) -> SFuture<()> {
        let key = format!("/{}/{}", self.name, key);
        let mut request = rusoto_core::signature::SignedRequest::new(
            "PUT",
            "s3",
            &rusoto_core::region::Region::UsEast1,
            &key,
        );
        request.set_hostname(Some(self.base_url.clone()));
        request.set_payload(Some(content));
        request.scheme = Some("http".to_string());
        if let Some(creds) = creds {
            request.sign(creds);
        }

        Box::new(
            self.client
                .dispatch(request, None)
                .map_err(crate::errors::Error::from)
                .and_then(|res| res.buffer().map_err(crate::errors::Error::from))
                .and_then(|res| {
                    if res.status.is_success() {
                        Ok(())
                    } else {
                        warn!("{}", String::from_utf8_lossy(&res.body));
                        Err(ErrorKind::BadHTTPStatus(res.status.into()).into())
                    }
        }))
    }
}
