// https://help.aliyun.com/document_detail/100669.html
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};

fn sign_base64(key_secret: &str, body: &str) -> String {
    let mut mac = Hmac::new(Sha1::new(), key_secret.as_bytes());
    mac.input(body.as_bytes());
    base64::encode(mac.result().code())
}

pub mod oss {
    use super::sign_base64;
    use crate::util;

    type Heads = Vec<(String, String)>;

    pub struct Client {
        pub verb: String,
        pub content_md5: String,
        pub content_type: String,
        pub date: Option<String>,
        pub oss_headers: Heads,
        pub bucket: String,
        pub key: String,
        pub key_id: String,
        pub key_secret: String,
    }

    impl Client {
        fn make_body(&self) -> Body {
            let Client {
                verb,
                content_md5,
                content_type,
                date,
                oss_headers,
                bucket,
                key,
                key_id: _,
                key_secret: _,
            } = self;

            let date_str: String = match date {
                Some(t) => t.to_owned(),
                None => util::get_date(),
            };

            Body {
                verb: verb.to_owned(),
                content_md5: content_md5.clone(),
                content_type: content_type.clone(),
                date: date_str,
                canonicalized_ossheaders: Headers(oss_headers.to_vec()).to_string(),
                canonicalized_resource: format!("/{}/{}", bucket, key),
            }
        }

        pub fn make_authorization(&self) -> String {
            let body = self.make_body();
            let body_str = body.to_string();
            let sig: String = sign_base64(&self.key_secret, body_str.as_ref());
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
    struct Headers(Heads);

    impl ToString for Headers {
        fn to_string(&self) -> String {
            let mut list_to_sort = self
                .0
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v.clone()))
                .collect::<Heads>();
            list_to_sort.sort_by(|a, b| a.0.cmp(&(b.0)));

            list_to_sort.iter().fold("".to_string(), |mut acc, (k, v)| {
                acc.push_str(k);
                acc.push(':');
                acc.push_str(v);
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
            let headers1 = Headers(vec![
                ("X-OSS-Z-Name".to_string(), "Val1".to_string()),
                ("X-OSS-OMeta-Name".to_string(), "val2".to_string()),
                ("X-OSS-Meta-a".to_string(), "Cval".to_string()),
                ("X-OSS-Meta-b".to_string(), "Eval".to_string()),
                ("X-OSS-Neta-a".to_string(), "Dval".to_string()),
            ]);
            let expect1 = "x-oss-meta-a:Cval\nx-oss-meta-b:Eval\nx-oss-neta-a:Dval\nx-oss-ometa-name:val2\nx-oss-z-name:Val1\n";
            assert_eq!(headers1.to_string(), expect1);
            let headers2 = Headers([].to_vec());
            assert_eq!(headers2.to_string(), "");
        }

        #[test]
        fn base64() {
            let key1 = "key1";
            let body1 = "body1";
            assert_eq!(sign_base64(key1, body1), "u3fznj0yiE48+1xlkideoCqhhdc=")
        }
    }
}
