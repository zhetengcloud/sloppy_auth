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
    pub const AWS4_SHA256: &str = "AWS4-HMAC-SHA256";
    pub const AWS_SHA256_PAYLOAD: &str = "AWS4-HMAC-SHA256-PAYLOAD";

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
            hex_sha256(self.signing_key(), string_to_sign)
        }

        pub fn chunk_string_to_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
            let hash_empty = digest::digest(&digest::SHA256, b"");
            let hash_data = digest::digest(&digest::SHA256, data.as_slice());
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                AWS_SHA256_PAYLOAD,
                self.datetime.format(LONG_DATETIME),
                scope_string(self.datetime, self.region),
                prev_sig,
                hex::encode(hash_empty),
                hex::encode(hash_data),
            )
        }

        pub fn chunk_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
            hex_sha256(
                self.signing_key(),
                self.chunk_string_to_sign(prev_sig, data),
            )
        }

        pub fn signing_key(&self) -> Vec<u8> {
            use hmac::{sign, Key, HMAC_SHA256};

            let service = "s3";
            let secret = format!("AWS4{}", self.secret_key);
            let date_key = Key::new(HMAC_SHA256, secret.as_bytes());
            let date_tag = sign(
                &date_key,
                self.datetime.format(SHORT_DATE).to_string().as_bytes(),
            );

            let region_key = Key::new(HMAC_SHA256, date_tag.as_ref());
            let region_tag = sign(&region_key, self.region.as_bytes());

            let service_key = Key::new(HMAC_SHA256, region_tag.as_ref());
            let service_tag = sign(&service_key, service.as_bytes());

            let signing_key = Key::new(HMAC_SHA256, service_tag.as_ref());
            let signing_tag = sign(&signing_key, b"aws4_request");
            signing_tag.as_ref().to_vec()
        }
    }

    pub fn hex_sha256(key: Vec<u8>, s: String) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let tag = hmac::sign(&key, s.as_bytes());
        hex::encode(tag.as_ref())
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
        format!("{}/{}/s3/aws4_request", datetime.format(SHORT_DATE), region)
    }

    pub fn string_to_sign(datetime: &DateTime<Utc>, region: &str, canonical_req: &str) -> String {
        let hash = digest::digest(&digest::SHA256, canonical_req.as_bytes());
        format!(
            "{}\n{}\n{}\n{}",
            AWS4_SHA256,
            datetime.format(LONG_DATETIME),
            scope_string(datetime, region),
            hex::encode(hash.as_ref())
        )
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

        //https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
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
            headers.insert(
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            );
            headers.insert("x-amz-date".to_string(), date_str.to_string());

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

            //chunk
            let data1 = [97u8; 65536];
            let data1_str =
                signer.chunk_string_to_sign(expected_seed_sig.to_string(), data1.to_vec());
            let expect_str1 = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                "AWS4-HMAC-SHA256-PAYLOAD",
                "20130524T000000Z",
                "20130524/us-east-1/s3/aws4_request",
                "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a"
            );
            assert_eq!(data1_str, expect_str1);
            let data1_sign = signer.chunk_sign(expected_seed_sig.to_string(), data1.to_vec());
            assert_eq!(
                data1_sign,
                "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
            );

            let data2 = [97u8; 1024];
            let data2_sign = signer.chunk_sign(data1_sign, data2.to_vec());
            assert_eq!(
                data2_sign,
                "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
            );

            let data3_sign = signer.chunk_sign(data2_sign, vec![]);
            assert_eq!(
                data3_sign,
                "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"
            );
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
