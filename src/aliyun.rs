// https://help.aliyun.com/document_detail/100669.html
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};

fn sign_base64(key_secret: &str, body: &str) -> String {
    let mut mac = Hmac::new(Sha1::new(), key_secret.as_bytes());
    mac.input(body.as_bytes());
    base64::encode(mac.result().code())
}

pub mod oss {
    use super::sign_base64;
    use chrono::prelude::Utc;
    pub struct Client {
        pub verb: String,
        pub content: Vec<u8>,
        pub content_type: String,
        pub date: Option<String>,
        pub oss_headers: Vec<String>,
        pub bucket: String,
        pub key: String,
        pub key_id: String,
        pub key_secret: String,
    }

    impl Client {
        fn make_body(&self) -> Body {
            let Client {
                verb,
                content,
                content_type,
                date,
                oss_headers,
                bucket,
                key,
                ..
            } = self;

            let content_md5 = base64::encode(*md5::compute(&content));
            let date_str: String = match date {
                Some(t) => t.to_owned(),
                None => Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            };

            Body {
                verb: verb.to_owned(),
                content_md5,
                content_type: content_type.to_owned(),
                date: date_str,
                canonicalized_ossheaders: Headers(oss_headers.to_owned()).to_string(),
                canonicalized_resource: format!("/{}/{}", bucket, key),
            }
        }

        pub fn make_authorization(&self) -> String {
            let body = self.make_body();
            let sig: String = sign_base64(&self.key_secret, body.to_string().as_ref());
            format!("OSS {}:{}", self.key_id, sig)
        }
    }

    pub struct Body {
        pub verb: String,
        pub content_md5: String,
        pub content_type: String,
        pub date: String,
        pub canonicalized_ossheaders: String,
        pub canonicalized_resource: String,
    }

    impl ToString for Body {
        fn to_string(&self) -> String {
            format!(
                "{}\n{}\n{}\n{}\n{}{}",
                self.verb,
                self.content_md5,
                self.content_type,
                self.date,
                self.canonicalized_ossheaders,
                self.canonicalized_resource
            )
        }
    }

    // newtype of CanonicalizedOSSHeaders
    struct Headers(Vec<String>);

    impl ToString for Headers {
        fn to_string(&self) -> String {
            let mut list_to_sort = self
                .0
                .iter()
                .map(|x| x.to_lowercase())
                .collect::<Vec<String>>();
            list_to_sort.sort_by(|a, b| a.cmp(b));

            list_to_sort
                .iter()
                .map(|x| x.replace(" ", ""))
                .fold("".to_string(), |mut acc, x| {
                    acc.push_str(&x);
                    acc.push('\n');
                    acc
                })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn headers_test() {
            let headers1 = Headers(
                [
                    "X-OSS-Z-Name: val1".to_string(),
                    "X-OSS-OMeta-Name: val2".to_string(),
                    "X-OSS-Meta-a: CVal".to_string(),
                    "X-OSS-Meta-b: Eval".to_string(),
                    "X-OSS-Neta-a: DVal".to_string(),
                ]
                .to_vec(),
            );
            let expect1 = "x-oss-meta-a:cval\nx-oss-meta-b:eval\nx-oss-neta-a:dval\nx-oss-ometa-name:val2\nx-oss-z-name:val1\n";
            assert_eq!(headers1.to_string(), expect1);
            let headers2 = Headers([].to_vec());
            assert_eq!(headers2.to_string(), "");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        let key1 = "key1";
        let body1 = "body1";
        assert_eq!(sign_base64(key1, body1), "u3fznj0yiE48+1xlkideoCqhhdc=")
    }
}
