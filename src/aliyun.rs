// https://help.aliyun.com/document_detail/100669.html
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};

fn sign_base64(key_secret: &str, body: &str) -> String {
    let mut mac = Hmac::new(Sha1::new(), key_secret.as_bytes());
    mac.input(body.as_bytes());
    base64::encode(mac.result().code())
}

pub mod oss {
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

    fn concat_auth(key_id: &str, signature: &str) -> String {
        format!("OSS {}:{}", key_id, signature)
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
