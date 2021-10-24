mod util;

#[cfg(test)]
mod tests {
    use super::util as u2;
    use log::debug;
    use sloppy_auth::{aws::s3, util};
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

        let s3 = s3::Sign {
            method: "PUT",
            url: Url::parse(&url2).expect("url parse failed"),
            datetime: &date,
            region: "us-east-1",
            access_key: &access_key,
            secret_key: &access_secret,
            headers: headers.clone(),
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
}
