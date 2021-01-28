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

use crate::azure::credentials::*;
use futures::{Future, Stream};
use hmac::{Hmac, Mac, NewMac};
use hyper::header::HeaderValue;
use hyper::Method;
use hyperx::header;
use md5::{Digest, Md5};
use reqwest::r#async::{Client, Request};
use reqwest::Url;
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;

use crate::errors::*;
use crate::util::HeadersExt;

const BLOB_API_VERSION: &str = "2017-04-17";

fn hmac(data: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha256>::new_varkey(secret).expect("HMAC can take key of any size");
    hmac.update(data);
    hmac.finalize().into_bytes().as_slice().to_vec()
}

fn signature(to_sign: &str, secret: &str) -> String {
    let decoded_secret = base64::decode_config(secret.as_bytes(), base64::STANDARD).unwrap();
    let sig = hmac(to_sign.as_bytes(), &decoded_secret);
    base64::encode_config(&sig, base64::STANDARD)
}

fn md5(data: &[u8]) -> String {
    let mut digest = Md5::new();
    digest.update(data);
    base64::encode_config(&digest.finalize(), base64::STANDARD)
}

pub struct BlobContainer {
    url: String,
    client: Client,
}

impl fmt::Display for BlobContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobContainer(url={})", self.url)
    }
}

impl BlobContainer {
    pub fn new(base_url: &str, container_name: &str) -> Result<BlobContainer> {
        assert!(
            base_url.ends_with('/'),
            "base_url is assumed to end in a trailing slash"
        );
        Ok(BlobContainer {
            url: format!("{}{}/", base_url, container_name),
            client: Client::new(),
        })
    }

    pub fn get(&self, key: &str, creds: &AzureCredentials) -> SFuture<Vec<u8>> {
        let url_string = format!("{}{}", self.url, key);
        let uri = Url::from_str(&url_string).unwrap();
        let dt = chrono::Utc::now();
        let date = format!("{}", dt.format("%a, %d %b %Y %T GMT"));

        let canonical_headers = format!("x-ms-date:{}\nx-ms-version:{}\n", date, BLOB_API_VERSION);

        let auth = compute_auth_header(
            "GET",
            "", // content_length
            "", // content_md5
            "", // content_type
            &canonical_headers,
            &uri,
            creds,
        );

        let uri_copy = uri.clone();
        let uri_second_copy = uri.clone();

        let mut request = Request::new(Method::GET, uri);
        request.headers_mut().insert(
            "x-ms-date",
            HeaderValue::from_str(&date).expect("Date is an invalid header value"),
        );
        request
            .headers_mut()
            .insert("x-ms-version", HeaderValue::from_static(BLOB_API_VERSION));
        if let Some(auth) = auth {
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&auth).expect("Authorization is an invalid header value"),
            );
        }

        Box::new(
            self.client
                .execute(request)
                .fwith_context(move || format!("failed GET: {}", uri_copy))
                .and_then(|res| {
                    if res.status().is_success() {
                        let content_length = res
                            .headers()
                            .get_hyperx::<header::ContentLength>()
                            .map(|header::ContentLength(len)| len);
                        Ok((res.into_body(), content_length))
                    } else {
                        Err(BadHttpStatusError(res.status()).into())
                    }
                })
                .and_then(|(body, content_length)| {
                    body.fold(Vec::new(), |mut body, chunk| {
                        body.extend_from_slice(&chunk);
                        Ok::<_, reqwest::Error>(body)
                    })
                    .fcontext("failed to read HTTP body")
                    .and_then(move |bytes| {
                        if let Some(len) = content_length {
                            if len != bytes.len() as u64 {
                                bail!(format!(
                                    "Bad HTTP body size read: {}, expected {}",
                                    bytes.len(),
                                    len
                                ));
                            } else {
                                info!("Read {} bytes from {}", bytes.len(), uri_second_copy);
                            }
                        }
                        Ok(bytes)
                    })
                }),
        )
    }

    pub fn put(&self, key: &str, content: Vec<u8>, creds: &AzureCredentials) -> SFuture<()> {
        let url_string = format!("{}{}", self.url, key);
        let uri = Url::from_str(&url_string).unwrap();
        let dt = chrono::Utc::now();
        let date = format!("{}", dt.format("%a, %d %b %Y %T GMT"));
        let content_type = "application/octet-stream";
        let content_md5 = md5(&content);

        let content_length = if content.is_empty() {
            "".to_owned()
        } else {
            format!("{}", content.len())
        };

        let canonical_headers = format!(
            "x-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:{}\n",
            date, BLOB_API_VERSION
        );

        let auth = compute_auth_header(
            "PUT",
            &content_length,
            &content_md5,
            content_type,
            &canonical_headers,
            &uri,
            creds,
        );

        let mut request = Request::new(Method::PUT, uri);
        request
            .headers_mut()
            .set(header::ContentType(content_type.parse().unwrap()));
        request
            .headers_mut()
            .set(header::ContentLength(content.len() as u64));
        request
            .headers_mut()
            .insert("x-ms-blob-type", HeaderValue::from_static("BlockBlob"));
        request.headers_mut().insert(
            "x-ms-date",
            HeaderValue::from_str(&date).expect("Invalid x-ms-date header"),
        );
        request
            .headers_mut()
            .insert("x-ms-version", HeaderValue::from_static(BLOB_API_VERSION));
        if let Some(auth) = auth {
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&auth).expect("Invalid Authorization header"),
            );
        }
        request.headers_mut().insert(
            "Content-MD5",
            HeaderValue::from_str(&content_md5).expect("Invalid Content-MD5 header"),
        );

        *request.body_mut() = Some(content.into());

        Box::new(self.client.execute(request).then(|result| match result {
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
        }))
    }
}

fn compute_auth_header(
    verb: &str,
    content_length: &str,
    md5: &str,
    content_type: &str,
    canonical_headers: &str,
    uri: &Url,
    creds: &AzureCredentials,
) -> Option<String> {
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
    creds.azure_account_key().as_ref().map(|account_key| {
        let canonical_resource = canonicalize_resource(uri, creds.azure_account_name());
        let string_to_sign = format!("{verb}\n\n\n{length}\n{md5}\n{type}\n\n\n\n\n\n\n{headers}{resource}",
                  verb = verb,
                  length = content_length,
                  md5 = md5,
                  type = content_type,
                  headers = canonical_headers,
                  resource = canonical_resource);
        format!(
            "SharedKey {}:{}",
            creds.azure_account_name(),
            signature(&string_to_sign, &account_key)
        )
    })
}

fn canonicalize_resource(uri: &Url, account_name: &str) -> String {
    let mut canonical_resource = String::new();
    canonical_resource.push('/');
    canonical_resource.push_str(account_name);
    canonical_resource.push_str(uri.path());

    // Deliberately ignoring query params, because we aren't using them.

    canonical_resource
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_compat::runtime::current_thread::Runtime;

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
        let client_key = Some("Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==".to_string());

        let container_name = "sccache";
        let creds = AzureCredentials::new(
            &blob_endpoint,
            &client_name,
            client_key,
            container_name.to_string(),
        );

        let mut runtime = Runtime::new().unwrap();

        let container = BlobContainer::new(creds.azure_blob_endpoint(), container_name).unwrap();

        let put_future = container.put("foo", b"barbell".to_vec(), &creds);
        runtime.block_on(put_future).unwrap();

        let get_future = container.get("foo", &creds);
        let result = runtime.block_on(get_future).unwrap();

        assert_eq!(b"barbell".to_vec(), result);
    }
}
