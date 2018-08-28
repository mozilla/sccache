// Copyright 2018 Benjamin Bader
// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use azure::credentials::*;
use base64;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use futures::{Future, Stream};
use hyper::{header, Method};
use url::Url;
use reqwest;
use reqwest::unstable::async::{Request, Client};
use std::fmt;
use std::str::FromStr;
use time;
use tokio_core::reactor::Handle;

use errors::*;

const BLOB_API_VERSION: &str = "2017-04-17";

fn hmac<D: Digest>(digest: D, data: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(digest, secret);
    hmac.input(data);
    hmac.result().code().iter().map(|b| *b).collect::<Vec<u8>>()
}

fn signature(to_sign: &str, secret: &str) -> String {
    let decoded_secret = base64::decode_config(secret.as_bytes(), base64::STANDARD).unwrap();
    let sig = hmac(Sha256::new(), to_sign.as_bytes(), &decoded_secret);
    base64::encode_config::<Vec<u8>>(&sig, base64::STANDARD)
}

fn md5(data: &[u8]) -> String {
    let mut result: Vec<u8> = vec![0; 16]; // md5 digest is 16 bytes long.
    let mut digest = Md5::new();
    digest.input(data);
    digest.result(&mut result);

    base64::encode_config::<Vec<u8>>(&result, base64::STANDARD)
}

pub struct BlobContainer {
    url: String,
    client: Client,
}

impl fmt::Display for BlobContainer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlobContainer(url={})", self.url)
    }
}

impl BlobContainer {
    pub fn new(base_url: &str, container_name: &Option<String>, handle: &Handle) -> Result<BlobContainer> {
        let container_url = match container_name {
            &Some(ref name) => format!("{}{}/", base_url, name), // base_url is assumed to end in a trailing slash
            &None           => base_url.to_owned()
        };

        Ok(BlobContainer {
            url: container_url,
            client: Client::new(handle),
        })
    }

    pub fn get(&self, key: &str, creds: &AzureCredentials) -> SFuture<Vec<u8>> {
        let url_string = format!("{}{}", self.url, key);
        let uri = Url::from_str(&url_string).unwrap();
        let date = time::now_utc().rfc822().to_string();

        let canonical_headers = format!("x-ms-date:{}\nx-ms-version:{}\n", date, BLOB_API_VERSION);

        let auth = compute_auth_header(
            "GET",
            "",    // content_length
            "",    // content_md5
            "",    // content_type
            &canonical_headers,
            &uri,
            creds);

        let uri_copy = uri.clone();
        let uri_second_copy = uri.clone();

        let mut request = Request::new(Method::Get, uri);
        request.headers_mut().set_raw("x-ms-date", date);
        request.headers_mut().set_raw("x-ms-version", BLOB_API_VERSION);
        request.headers_mut().set_raw("Authorization", auth);

        Box::new(self.client.execute(request).chain_err(move || {
            format!("failed GET: {}", uri_copy)
        }).and_then(|res| {
            if res.status().is_success() {
                let content_length = res.headers().get::<header::ContentLength>()
                    .map(|&header::ContentLength(len)| len);
                Ok((res.into_body(), content_length))
            } else {
                Err(ErrorKind::BadHTTPStatus(res.status().clone()).into())
            }
        }).and_then(|(body, content_length)| {
            body.fold(Vec::new(), |mut body, chunk| {
                body.extend_from_slice(&chunk);
                Ok::<_, reqwest::Error>(body)
            }).chain_err(|| {
                "failed to read HTTP body"
            }).and_then(move |bytes| {
                if let Some(len) = content_length {
                    if len != bytes.len() as u64 {
                        bail!(format!("Bad HTTP body size read: {}, expected {}", bytes.len(), len));
                    } else {
                        info!("Read {} bytes from {}", bytes.len(), uri_second_copy);
                    }
                }
                Ok(bytes)
            })
        }))
    }

    pub fn put(&self, key: &str, content: Vec<u8>, creds: &AzureCredentials) -> SFuture<()> {
        let url_string = format!("{}{}", self.url, key);
        let uri = Url::from_str(&url_string).unwrap();
        let date = time::now_utc().rfc822().to_string();
        let content_type = "application/octet-stream";
        let content_md5 = md5(&content);

        let content_length = if content.is_empty() {
            "".to_owned()
        } else {
            format!("{}", content.len())
        };

        let canonical_headers = format!("x-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:{}\n", date, BLOB_API_VERSION);

        let auth = compute_auth_header(
            "PUT",
            &content_length,
            &content_md5,
            content_type,
            &canonical_headers,
            &uri,
            creds);

        let mut request = Request::new(Method::Put, uri);
        request.headers_mut().set(header::ContentType(content_type.parse().unwrap()));
        request.headers_mut().set(header::ContentLength(content.len() as u64));
        request.headers_mut().set_raw("x-ms-blob-type", "BlockBlob");
        request.headers_mut().set_raw("x-ms-date", date);
        request.headers_mut().set_raw("x-ms-version", BLOB_API_VERSION);
        request.headers_mut().set_raw("Authorization", auth);
        request.headers_mut().set_raw("Content-MD5", content_md5);

        *request.body_mut() = Some(content.into());

        Box::new(self.client.execute(request).then(|result| {
            match result {
                Ok(res) => {
                    if res.status().is_success() {
                        trace!("PUT succeeded");
                        Ok(())
                    } else {
                        trace!("PUT failed with HTTP status: {}", res.status());
                        Err(ErrorKind::BadHTTPStatus(res.status().clone()).into())
                    }
                }
                Err(e) => {
                    trace!("PUT failed with error: {:?}", e);
                    Err(e.into())
                }
            }
        }))
    }
}

fn compute_auth_header(verb: &str, content_length: &str, md5: &str,
                       content_type: &str, canonical_headers: &str,
                       uri: &Url, creds: &AzureCredentials) -> String {
    /*
    Signature format taken from MSDN docs:
    https://docs.microsoft.com/en-us/azure/storage/common/storage-rest-api-auth

    Authorization: SharedKey [AccountName]:[Base64(HMAC(SHA-256, StringToSign))]

    StringToSign = VERB + "\n" +
           Content-Encoding + "\n" +
           Content-Language + "\n" +
           Content-Length + "\n" +
           Content-MD5 + "\n" +
           Content-Type + "\n" +
           Date + "\n" +
           If-Modified-Since + "\n" +
           If-Match + "\n" +
           If-None-Match + "\n" +
           If-Unmodified-Since + "\n" +
           Range + "\n" +
           CanonicalizedHeaders + // CanonicalizedHeaders is defined to end with "\n"
           CanonicalizedResource;
    */

    let canonical_resource = canonicalize_resource(uri, creds.azure_account_name());
    let string_to_sign = format!("{verb}\n\n\n{length}\n{md5}\n{type}\n\n\n\n\n\n\n{headers}{resource}",
                verb = verb,
                length = content_length,
                md5 = md5,
                type = content_type,
                headers = canonical_headers,
                resource = canonical_resource);

    format!("SharedKey {}:{}", creds.azure_account_name(), signature(&string_to_sign, creds.azure_account_key()))
}

fn canonicalize_resource(uri: &Url, account_name: &str) -> String {
    let mut canonical_resource = String::new();
    canonical_resource.push_str("/");
    canonical_resource.push_str(account_name);
    canonical_resource.push_str(uri.path());

    // Deliberately ignoring query params, because we aren't using them.

    canonical_resource
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::reactor::Core;

    #[test]
    fn test_signing() {
        // Test values copied from https://github.com/MindFlavor/AzureSDKForRust,
        // which we are treating as an oracle in this test.
        let string_to_sign = "53d7e14aee681a00340300032015-01-01T10:00:00.0000000".to_owned();
        let hmac_key = "pXeTVaaaaU9XxH6fPcPlq8Y9D9G3Cdo5Eh2nMSgKj/DWqeSFFXDdmpz5Trv+L2hQNM+nGa704Rf8Z22W9O1jdQ=="
            .to_owned();

        assert_eq!(
            signature(&string_to_sign, &hmac_key),
            "gZzaRaIkvC9jYRY123tq3xXZdsMAcgAbjKQo8y0p0Fs=".to_owned()
        );
    }

    #[test]
    fn test_canonicalize_resource() {
        let url = Url::from_str("https://testaccount.blob.core.windows.net/container/key").unwrap();
        let canon = canonicalize_resource(&url, "testaccount");

        assert_eq!("/testaccount/container/key", &canon);
    }

    #[test]
    #[ignore]
    fn test_put_blob() {
        /*
        NOTE:

        This test assumes that you are running a local storage emulator,
        such as azurite.  It will fail, perhaps hanging indefinitely, if
        you aren't!

        You may also replace the hardcoded constants with your own Azure
        credentials, if you wish to run the test against an actual blob
        store.  If you do this, **don't check your credentials in**!

        Run this test with `cargo test --features azure -- --ignored`.
        */

        let blob_endpoint = "http://localhost:10000/devstoreaccount1/";
        let client_name = "devstoreaccount1";
        let client_key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

        let container_name = Some("sccache".to_owned());
        let creds = AzureCredentials::new(&blob_endpoint, &client_name, &client_key, container_name.clone());

        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let container = BlobContainer::new(creds.azure_blob_endpoint(), &container_name, &handle).unwrap();

        let put_future = container.put("foo", "barbell".as_bytes().to_vec(), &creds);
        core.run(put_future).unwrap();

        let get_future = container.get("foo", &creds);
        let result = core.run(get_future).unwrap();

        assert_eq!("barbell".as_bytes().to_vec(), result);
    }
}
