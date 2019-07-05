// Originally from https://github.com/rust-lang/crates.io/blob/master/src/s3/lib.rs
//#![deny(warnings)]

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt;

use futures::{Future, Stream};
use rusoto_s3::S3;

use crate::errors::*;

/// An S3 bucket.
pub struct Bucket {
    bucket_name: String,
    client: rusoto_s3::S3Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={})", self.bucket_name)
    }
}

impl Bucket {
    pub fn new(bucket_name: &str, region: &rusoto_core::Region) -> Result<Bucket> {
        Ok(Bucket {
            bucket_name: bucket_name.to_owned(),
            client: rusoto_s3::S3Client::new(region.clone()),
        })
    }

    pub fn get(&self, key: &str) -> SFuture<Vec<u8>> {
        Box::new(
            self.client
                .get_object(rusoto_s3::GetObjectRequest {
                    bucket: self.bucket_name.clone(),
                    key: key.into(),
                    ..Default::default()
                })
                .map_err(|err| err.to_string().into())
                .and_then(|response| {
                    response
                        .body
                        .expect("Missing body when fetching from S3")
                        .map_err(|err| err.to_string().into())
                        .fold(Vec::new(), |mut out, item| -> Result<_> {
                            out.extend(item);
                            Ok(out)
                        })
                }),
        )
    }

    pub fn put(&self, key: &str, content: Vec<u8>) -> SFuture<()> {
        Box::new(
            self.client
                .put_object(rusoto_s3::PutObjectRequest {
                    bucket: self.bucket_name.clone(),
                    key: key.into(),
                    content_length: Some(content.len() as i64),
                    content_type: Some("application/octet-stream".into()),
                    cache_control: Some("max-age=1296000".into()),
                    body: Some(content.into()),
                    ..Default::default()
                })
                .map_err(|err| err.to_string().into())
                .map(|_| ()),
        )
    }
}
