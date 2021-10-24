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

        //Authorization header
        pub fn sign(&self) -> String {
            format!(
                "AWS4-HMAC-SHA256 Credential={access_key}/{scope},\
             SignedHeaders={signed_headers},Signature={signature}",
                access_key = self.access_key,
                scope = scope_string(self.datetime, self.region),
                signed_headers = self.signed_header_string(),
                signature = self.calc_seed_signature()
            )
        }

        pub fn calc_seed_signature(&self) -> String {
            let canonical = self.canonical_request();
            let string_to_sign = string_to_sign(self.datetime, self.region, &canonical);
            let signing_key = signing_key(self.datetime, self.secret_key, self.region, "s3");
            let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key);
            let tag = hmac::sign(&key, string_to_sign.as_bytes());
            hex::encode(tag.as_ref())
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
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime.format(LONG_DATETIME),
            scope_string(datetime, region),
            hex::encode(hash.as_ref())
        )
    }

    pub fn signing_key(
        datetime: &DateTime<Utc>,
        secret_key: &str,
        region: &str,
        service: &str,
    ) -> Vec<u8> {
        use hmac::{sign, Key, HMAC_SHA256};

        let secret = format!("AWS4{}", secret_key);
        let date_key = Key::new(HMAC_SHA256, secret.as_bytes());
        let date_tag = sign(
            &date_key,
            datetime.format(SHORT_DATE).to_string().as_bytes(),
        );

        let region_key = Key::new(HMAC_SHA256, date_tag.as_ref());
        let region_tag = sign(&region_key, region.to_string().as_bytes());

        let service_key = Key::new(HMAC_SHA256, region_tag.as_ref());
        let service_tag = sign(&service_key, service.as_bytes());

        let signing_key = Key::new(HMAC_SHA256, service_tag.as_ref());
        let signing_tag = sign(&signing_key, b"aws4_request");
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use chrono::NaiveDateTime;
        use std::collections::HashMap;

        #[test]
        fn sign_seed_signature() {
            let host = "s3.amazonaws.com";
            let s3_buck = "examplebucket";
            let s3_key = "chunkObject.txt";
            let full_url = format!("http://{}/{}/{}", host, s3_buck, s3_key);
            let date_str = "20130524T000000Z";
            let n_date =
                NaiveDateTime::parse_from_str(date_str, LONG_DATETIME).expect("date parse failed");
            let date = DateTime::<Utc>::from_utc(n_date, Utc);
            let mut headers = HashMap::new();
            headers.insert("Host".to_string(), host.to_string());
            headers.insert(
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            );
            headers.insert(
                "x-amz-content-sha256".to_string(),
                STREAM_PAYLOAD.to_string(),
            );
            headers.insert("Content-Encoding".to_string(), "aws-chunked".to_string());
            headers.insert(
                "x-amz-decoded-content-length".to_string(),
                "66560".to_string(),
            );
            headers.insert("Content-Length".to_string(), "66824".to_string());

            let signer = Sign {
                method: "PUT",
                url: Url::parse(&full_url).expect("url parse failed"),
                datetime: &date,
                region: "us-east-1",
                access_key: "AKIAIOSFODNN7EXAMPLE",
                secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                headers,
                transfer_mode: Transfer::Multiple,
            };

            let expected_seed_sig =
                "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
            assert_eq!(signer.calc_seed_signature(), expected_seed_sig);
        }
    }

    pub mod api {
        use super::*;
        use std::io::Read;

        pub struct Holder<'a, T: Read, H: Headers> {
            pub buf_size: usize,
            pub reader: T,
            prev_signature: Option<String>,
            signer: Sign<'a, H>,
        }

        impl<'a, R: Read, H: Headers> Holder<'a, R, H> {
            pub fn new(buf_size: usize, reader: R, signer: Sign<'a, H>) -> Self {
                Self {
                    buf_size,
                    reader,
                    prev_signature: None,
                    signer,
                }
            }
        }

        impl<'a, R: Read, H: Headers> Iterator for Holder<'a, R, H> {
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
                    None => {
                        let data = self.signer.calc_seed_signature();
                        Some(data.as_bytes().to_vec())
                    }
                }
            }
        }
    }
}
