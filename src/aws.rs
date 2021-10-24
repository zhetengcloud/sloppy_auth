/**
 * fork of https://github.com/psnszsn/aws-sign-v4
 */
pub mod s3 {

    use crate::util::{uri_encode, Headers, LONG_DATETIME, SHORT_DATE};
    use chrono::{DateTime, Utc};
    use ring::{digest, hmac};
    use url::Url;

    pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
    pub const STREAM_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    pub struct Sign<'a, T>
    where
        T: Headers,
    {
        pub method: &'a str,
        pub url: Url,
        pub datetime: &'a DateTime<Utc>,
        pub region: &'a str,
        pub access_key: &'a str,
        pub secret_key: &'a str,
        pub headers: T,
        pub transfer_mode: Transfer,
    }

    impl<'a, T> Sign<'a, T>
    where
        T: Headers,
    {
        pub fn signed_header_string(&self) -> String {
            let mut keys = self
                .headers
                .clone()
                .into_iter()
                .map(|(key, _)| key.to_lowercase())
                .collect::<Vec<String>>();
            keys.sort();
            keys.join(";")
        }

        pub fn canonical_request(&self) -> String {
            let url: String = self.url.path().into();

            vec![
                self.method.to_string(),
                url,
                canonical_query_string(&self.url),
                self.headers.to_canonical(),
                self.signed_header_string(),
                self.transfer_mode.content_sha256().to_string(),
            ]
            .join("\n")
        }
        pub fn sign(&self) -> String {
            let canonical = self.canonical_request();
            let string_to_sign = string_to_sign(self.datetime, self.region, &canonical);
            let signing_key = signing_key(self.datetime, self.secret_key, self.region, "s3");
            let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key);
            let tag = hmac::sign(&key, string_to_sign.as_bytes());
            let signature = hex::encode(tag.as_ref());
            let signed_headers = self.signed_header_string();

            format!(
                "AWS4-HMAC-SHA256 Credential={access_key}/{scope},\
             SignedHeaders={signed_headers},Signature={signature}",
                access_key = self.access_key,
                scope = scope_string(self.datetime, self.region),
                signed_headers = signed_headers,
                signature = signature
            )
        }
    }

    pub fn canonical_query_string(uri: &Url) -> String {
        let mut keyvalues = uri
            .query_pairs()
            .map(|(key, value)| uri_encode(&key, true) + "=" + &uri_encode(&value, true))
            .collect::<Vec<String>>();
        keyvalues.sort();
        keyvalues.join("&")
    }

    pub fn scope_string(datetime: &DateTime<Utc>, region: &str) -> String {
        format!(
            "{date}/{region}/s3/aws4_request",
            date = datetime.format(SHORT_DATE),
            region = region
        )
    }

    pub fn string_to_sign(datetime: &DateTime<Utc>, region: &str, canonical_req: &str) -> String {
        let hash = digest::digest(&digest::SHA256, canonical_req.as_bytes());
        format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{hash}",
            timestamp = datetime.format(LONG_DATETIME),
            scope = scope_string(datetime, region),
            hash = hex::encode(hash.as_ref())
        )
    }

    pub fn signing_key(
        datetime: &DateTime<Utc>,
        secret_key: &str,
        region: &str,
        service: &str,
    ) -> Vec<u8> {
        let secret = String::from("AWS4") + secret_key;

        let date_key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let date_tag = hmac::sign(
            &date_key,
            datetime.format(SHORT_DATE).to_string().as_bytes(),
        );

        let region_key = hmac::Key::new(hmac::HMAC_SHA256, date_tag.as_ref());
        let region_tag = hmac::sign(&region_key, region.to_string().as_bytes());

        let service_key = hmac::Key::new(hmac::HMAC_SHA256, region_tag.as_ref());
        let service_tag = hmac::sign(&service_key, service.as_bytes());

        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, service_tag.as_ref());
        let signing_tag = hmac::sign(&signing_key, b"aws4_request");
        signing_tag.as_ref().to_vec()
    }

    #[derive(Debug, PartialEq, Clone)]
    pub enum Transfer {
        Single,
        Multiple,
    }

    impl Transfer {
        pub fn content_sha256(&self) -> &'static str {
            match self {
                Self::Single => UNSIGNED_PAYLOAD,
                Self::Multiple => STREAM_PAYLOAD,
            }
        }
    }

    pub mod api {
        use std::io::Read;

        pub struct Holder<T: Read> {
            pub buf_size: usize,
            pub reader: T,
            prev_signature: Option<String>,
        }

        impl<T: Read> Holder<T> {
            pub fn new(buf_size: usize, reader: T) -> Self {
                Self {
                    buf_size,
                    reader,
                    prev_signature: None,
                }
            }
        }

        impl<T: Read> Iterator for Holder<T> {
            type Item = Vec<u8>;

            fn next(&mut self) -> Option<Self::Item> {
                match self.prev_signature {
                    Some(_) => {
                        let mut buf = vec![0; self.buf_size];

                        match self.reader.read(&mut buf) {
                            Ok(_len) => {
                                //let current_chunk_data: Vec<u8> = buf.drain(0..len).collect();

                                Some(vec![])
                            }
                            Err(_) => None,
                        }
                    }
                    None => Some(vec![]),
                }
            }
        }
    }
}
