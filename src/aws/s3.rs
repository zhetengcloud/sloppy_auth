use crate::{
    aws::auth::Sign,
    util::{self, hex_sha256, Headers},
};
use std::io::Read;

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAM_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const AWS_SHA256_PAYLOAD: &str = "AWS4-HMAC-SHA256-PAYLOAD";

pub struct Holder<'a, T: Read, H: Headers> {
    pub buf_size: usize,
    pub reader: T,
    prev_signature: Option<String>,
    signer: Sign<'a, H>,
    state: State,
}

impl<'a, R: Read, H: Headers> Holder<'a, R, H> {
    pub fn new(buf_size: usize, reader: R, signer: Sign<'a, H>) -> Self {
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

impl<'a, R: Read, H: Headers> Iterator for Holder<'a, R, H> {
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

impl<'a, T: Headers> S3Chunk for Sign<'a, T> {
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
            service: "s3",
            method: "PUT",
            url: Url::parse(&full_url).expect("url parse failed"),
            datetime: &date,
            region: "us-east-1",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            headers,
            hash_request_payload: STREAM_PAYLOAD,
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
