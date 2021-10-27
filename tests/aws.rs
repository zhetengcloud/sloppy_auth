mod util;

#[cfg(test)]
mod tests {
    use super::util as u2;
    use log::debug;
    use sloppy_auth::{
        aws::{auth, s3},
        chunk, util,
    };
    use std::collections::HashMap;
    use std::env;
    use url::Url;

    #[test]
    fn aws_s3_putobject_small() {
        u2::init_log();

        let access_key = env::var("aws_access_key").expect("access key empty");
        let access_secret = env::var("aws_access_secret").expect("access secret empty");
        let bucket = "sls11";
        let key = "test1.txt";
        let host = format!("{}.s3.amazonaws.com", bucket);
        let url1 = format!("http://{}", host);
        let url2 = format!("{}/{}", url1, key);
        let date = chrono::Utc::now();

        let mut headers = HashMap::new();
        headers.insert(
            "X-Amz-Date".to_string(),
            date.format(util::LONG_DATETIME).to_string(),
        );
        headers.insert(
            "X-Amz-Content-Sha256".to_string(),
            s3::UNSIGNED_PAYLOAD.to_string(),
        );
        headers.insert("Host".to_string(), host);

        let s3 = auth::Sign {
            service: "s3".to_string(),
            method: "PUT".to_string(),
            url: Url::parse(&url2).expect("url parse failed"),
            datetime: date,
            region: "us-east-1".to_string(),
            access_key: access_key,
            secret_key: access_secret,
            headers: headers.clone(),
            hash_request_payload: s3::UNSIGNED_PAYLOAD.to_string(),
        };

        let signature = s3.sign();
        debug!("signature {:?}", signature);

        headers.insert("Authorization".to_string(), signature);

        let mut request = ureq::put(&url2);
        for (k, v) in headers {
            request = request.set(&k, &v);
        }

        let body1 = "hello world 1";
        match request.send_string(body1) {
            Ok(resp) => {
                debug!(
                    "response status: {}, body: {}",
                    resp.status(),
                    resp.into_string().unwrap()
                )
            }
            Err(e) => {
                debug!("request failed {:?}", e);
            }
        }
    }

    #[test]
    fn aws_s3_putobject_stream() {
        use s3::Holder;
        u2::init_log();

        let access_key = env::var("aws_access_key").expect("access key empty");
        let access_secret = env::var("aws_access_secret").expect("access secret empty");
        let url1 = env::var("test_url1").expect("test url1 empty");

        let response1 = ureq::get(&url1).call().expect("get url1 failed");
        let content_len: String = response1
            .header("Content-Length")
            .expect("content length empty")
            .to_string();
        let rd1 = response1.into_reader();

        let host = "s3.amazonaws.com";
        let s3_buck = "sls11";
        let s3_key = "test1.mp3";
        let host1 = format!("{}.{}", s3_buck, host);
        let full_url = format!("http://{}/{}", host1, s3_key);
        let date = chrono::Utc::now();
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), host1);
        headers.insert(
            "x-amz-content-sha256".to_string(),
            s3::STREAM_PAYLOAD.to_string(),
        );
        headers.insert("Content-Encoding".to_string(), "aws-chunked".to_string());
        headers.insert("x-amz-decoded-content-length".to_string(), content_len);
        headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
        headers.insert(
            "x-amz-date".to_string(),
            date.format(util::LONG_DATETIME).to_string(),
        );

        let signer = auth::Sign {
            service: "s3".to_string(),
            method: "PUT".to_string(),
            url: Url::parse(&full_url).expect("url parse failed"),
            datetime: date,
            region: "us-east-1".to_string(),
            access_key: access_key,
            secret_key: access_secret,
            headers: headers.clone(),
            hash_request_payload: s3::STREAM_PAYLOAD.to_string(),
        };

        headers.insert("Authorization".to_string(), signer.sign());

        let holder = Holder::new(6 * 1024 * 1024, rd1, signer);
        let chunk = chunk::Chunk::new(holder);
        let mut request2 = ureq::put(&full_url);
        for (k, v) in headers {
            request2 = request2.set(&k, &v);
        }
        match request2.send(chunk) {
            Ok(resp) => {
                log::debug!("ok {}", resp.status());
            }
            Err(ureq::Error::Status(code, _response)) => {
                log::debug!("error code {}", code);
            }
            Err(ureq::Error::Transport(t)) => {
                log::debug!("transport {:?}", t);
            }
        }
    }

    #[test]
    fn aws_s3_client_putobject_stream() {
        u2::init_log();
        let client = s3::client::Client::new("us-east-1".to_string());

        let bytes_len = "20000";
        let url1 = format!("http://httpbin.org/bytes/{}", bytes_len);

        let response1 = ureq::get(&url1).call().expect("get url1 failed");

        let input = s3::client::PutObjectInput {
            bucket: "sls11".to_string(),
            key: "test3".to_string(),
            content_len: bytes_len.to_string(),
            data: response1.into_reader(),
        };
        client
            .put_object_stream(8 * 1024, input)
            .expect("put object stream failed");
    }

    #[test]
    fn aws_s3_client_putobject_single() {
        u2::init_log();
        let client = s3::client::Client::new("us-east-1".to_string());

        let data = "abcd";
        let input = s3::client::PutObjectInput {
            bucket: "sls11".to_string(),
            key: "test4".to_string(),
            content_len: data.len().to_string(),
            data: data.as_bytes(),
        };
        client.put_object(input).expect("put object single failed");
    }
}
