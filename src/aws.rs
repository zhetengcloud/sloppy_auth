/**
 * fork of https://github.com/psnszsn/aws-sign-v4
 */
pub mod s3 {

    use crate::util::{Headers, LONG_DATETIME, SHORT_DATE};
    use chrono::{DateTime, Utc};
    use url::Url;

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
    }

    impl<'a, T> Sign<'a, T>
    where
        T: Headers,
    {
        pub fn canonical_header_string(&'a self) -> String {
            let mut keyvalues = self
                .headers
                .clone()
                .into_iter()
                .map(|(key, value)| key.to_lowercase() + ":" + value.trim())
                .collect::<Vec<String>>();
            keyvalues.sort();
            keyvalues.join("\n")
        }

        pub fn signed_header_string(&'a self) -> String {
            let mut keys = self
                .headers
                .clone()
                .into_iter()
                .map(|(key, _)| key.to_lowercase())
                .collect::<Vec<String>>();
            keys.sort();
            keys.join(";")
        }

        pub fn canonical_request(&'a self) -> String {
            let url: &str = self.url.path().into();
            let sha256 = "UNSIGNED-PAYLOAD";

            format!(
                "{method}\n{uri}\n{query_string}\n{headers}\n\n{signed}\n{sha256}",
                method = self.method,
                uri = url,
                query_string = canonical_query_string(&self.url),
                headers = self.canonical_header_string(),
                signed = self.signed_header_string(),
                sha256 = sha256
            )
        }
        pub fn sign(&'a self) -> String {
            let canonical = self.canonical_request();
            let string_to_sign = string_to_sign(self.datetime, self.region, &canonical);
            let signing_key = signing_key(self.datetime, self.secret_key, self.region, "s3");
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &signing_key.unwrap());
            let tag = ring::hmac::sign(&key, string_to_sign.as_bytes());
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

    pub fn uri_encode(string: &str, encode_slash: bool) -> String {
        let mut result = String::with_capacity(string.len() * 2);
        for c in string.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '~' | '.' => result.push(c),
                '/' if encode_slash => result.push_str("%2F"),
                '/' if !encode_slash => result.push('/'),
                _ => {
                    result.push('%');
                    result.push_str(
                        &format!("{}", c)
                            .bytes()
                            .map(|b| format!("{:02X}", b))
                            .collect::<String>(),
                    );
                }
            }
        }
        result
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
        let hash = ring::digest::digest(&ring::digest::SHA256, canonical_req.as_bytes());
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
    ) -> Result<Vec<u8>, String> {
        let secret = String::from("AWS4") + secret_key;

        let date_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let date_tag = ring::hmac::sign(
            &date_key,
            datetime.format(SHORT_DATE).to_string().as_bytes(),
        );

        let region_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, date_tag.as_ref());
        let region_tag = ring::hmac::sign(&region_key, region.to_string().as_bytes());

        let service_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, region_tag.as_ref());
        let service_tag = ring::hmac::sign(&service_key, service.as_bytes());

        let signing_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, service_tag.as_ref());
        let signing_tag = ring::hmac::sign(&signing_key, b"aws4_request");
        Ok(signing_tag.as_ref().to_vec())
    }
}
