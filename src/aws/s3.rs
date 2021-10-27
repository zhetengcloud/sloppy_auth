use crate::{
    aws::auth::Sign,
    util::{self, hex_sha256, Headers},
};
use std::io::Read;

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAM_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const AWS_SHA256_PAYLOAD: &str = "AWS4-HMAC-SHA256-PAYLOAD";

pub struct Holder<T: Read, H: Headers> {
    pub buf_size: usize,
    pub reader: T,
    prev_signature: Option<String>,
    signer: Sign<H>,
    state: State,
}

impl<R: Read, H: Headers> Holder<R, H> {
    pub fn new(buf_size: usize, reader: R, signer: Sign<H>) -> Self {
        Self {
            buf_size,
            reader,
            prev_signature: None,
            signer,
            state: State::Body,
        }
    }
}

enum State {
    Body,
    Final,
    Finished,
}

impl<R: Read, H: Headers> Iterator for Holder<R, H> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            State::Finished => None,
            State::Body => {
                let prev = match &self.prev_signature {
                    Some(s) => s.clone(),
                    None => self.signer.calc_seed_signature(),
                };

                let mut data = Vec::<u8>::with_capacity(self.buf_size);
                let mut buf = [0u8; 128 * 1204];
                loop {
                    match self.reader.read(&mut buf) {
                        Ok(len) => {
                            if len < 1 {
                                self.state = State::Final;
                                break;
                            } else {
                                data.extend_from_slice(&buf[0..len]);
                                if data.len() > self.buf_size {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            self.state = State::Final;
                            break;
                        }
                    }
                }

                let new_sign = self.signer.chunk_sign(prev, data.clone());
                self.prev_signature = Some(new_sign.clone());
                let chunk = util::concat_chunk(data, new_sign);
                Some(chunk)
            }
            State::Final => {
                self.state = State::Finished;
                if let Some(prev) = &self.prev_signature {
                    let data = vec![];
                    let new_sign = self.signer.chunk_sign(prev.clone(), data.clone());
                    self.prev_signature = Some(new_sign.clone());
                    let chunk = util::concat_chunk(data, new_sign);
                    Some(chunk)
                } else {
                    None
                }
            }
        }
    }
}

pub trait S3Chunk {
    fn chunk_sign(&self, prev_signature: String, data: Vec<u8>) -> String;
    fn chunk_string_to_sign(&self, prev_signature: String, data: Vec<u8>) -> String;
}

use ring::digest;

impl<T: Headers> S3Chunk for Sign<T> {
    fn chunk_string_to_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
        let hash_empty = digest::digest(&digest::SHA256, b"");
        let hash_data = digest::digest(&digest::SHA256, data.as_slice());
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            AWS_SHA256_PAYLOAD,
            self.datetime.format(util::LONG_DATETIME),
            self.scope_string(),
            prev_sig,
            hex::encode(hash_empty),
            hex::encode(hash_data),
        )
    }

    fn chunk_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
        hex_sha256(
            self.signing_key(),
            self.chunk_string_to_sign(prev_sig, data),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::LONG_DATETIME;
    use chrono::{DateTime, NaiveDateTime, Utc};
    use std::collections::HashMap;
    use url::Url;

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
            service: "s3".to_string(),
            method: "PUT".to_string(),
            url: Url::parse(&full_url).expect("url parse failed"),
            datetime: date,
            region: "us-east-1".to_string(),
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            headers,
            hash_request_payload: STREAM_PAYLOAD.to_string(),
        };

        let expected_seed_sig = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        assert_eq!(signer.calc_seed_signature(), expected_seed_sig);

        //chunk
        let data1 = [97u8; 65536];
        let data1_str = signer.chunk_string_to_sign(expected_seed_sig.to_string(), data1.to_vec());
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

pub mod client {
    use super::*;
    use crate::chunk;
    use std::collections::HashMap;
    use std::error::Error;
    use url::Url;

    type MHeader = HashMap<String, String>;

    pub struct Client {
        region: String,
    }

    pub struct PutObjectInput<T: Read> {
        pub bucket: String,
        pub key: String,
        pub content_len: String,
        pub data: T,
    }

    impl Client {
        pub fn new(region: String) -> Self {
            Client { region }
        }

        fn make_signer(
            &self,
            method: &str,
            bucket: &str,
            key: &str,
            mode: Transfer,
        ) -> (Sign<MHeader>, MHeader, String) {
            let access_key = std::env::var("AWS_ACCESS_KEY_ID").expect("access key empty");
            let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").expect("secret key empty");
            let access_token = std::env::var("AWS_SESSION_TOKEN");

            let date = chrono::Utc::now();

            let host = "s3.amazonaws.com";
            let host1 = format!("{}.{}", bucket, host);
            let full_url = format!("http://{}/{}", host1, key);

            let mut headers = HashMap::new();
            headers.insert("Host".to_string(), host1);
            headers.insert("x-amz-content-sha256".to_string(), mode.payload_hash());
            headers.insert(
                "x-amz-date".to_string(),
                date.format(util::LONG_DATETIME).to_string(),
            );
            headers.extend(mode.extra_headers());
            if let Ok(token) = access_token {
                headers.insert("X-Amz-Security-Token".to_string(), token);
            }

            let signer = Sign {
                service: "s3".to_string(),
                method: method.to_string(),
                url: Url::parse(&full_url).expect("url parse failed"),
                datetime: date,
                region: self.region.clone(),
                access_key,
                secret_key,
                headers: headers.clone(),
                hash_request_payload: mode.payload_hash(),
            };

            headers.insert("Authorization".to_string(), signer.sign());

            (signer, headers, full_url)
        }

        pub fn put_object<T: Read>(&self, input: PutObjectInput<T>) {}

        pub fn put_object_stream<T: Read>(
            &self,
            chunk_kb: usize,
            input: PutObjectInput<T>,
        ) -> Result<(), Box<dyn Error>> {
            let (signer, headers, full_url) = self.make_signer(
                "PUT",
                &input.bucket,
                &input.key,
                Transfer::Multiple(input.content_len),
            );
            let holder = Holder::new(chunk_kb * 1024, input.data, signer);
            let chunk = chunk::Chunk::new(holder);
            let mut request = ureq::put(&full_url);
            for (k, v) in headers {
                request = request.set(&k, &v);
            }

            request.send(chunk)?;

            Ok(())
        }
    }

    type ContentLength = String;
    enum Transfer {
        Single,
        Multiple(ContentLength),
    }

    impl Transfer {
        fn payload_hash(&self) -> String {
            match self {
                Self::Single => UNSIGNED_PAYLOAD.to_string(),
                Self::Multiple(_) => STREAM_PAYLOAD.to_string(),
            }
        }

        fn extra_headers(&self) -> MHeader {
            let mut headers = HashMap::new();
            match self {
                Self::Single => (),
                Self::Multiple(content_len) => {
                    headers.insert("Content-Encoding".to_string(), "aws-chunked".to_string());
                    headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
                    headers.insert(
                        "x-amz-decoded-content-length".to_string(),
                        content_len.clone(),
                    );
                }
            }
            headers
        }
    }
}
