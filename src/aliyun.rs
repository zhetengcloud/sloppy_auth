// https://help.aliyun.com/document_detail/100669.html

pub mod oss {
    use crate::util::{self, Headers};

    #[derive(Clone, Default)]
    pub struct Client<T>
    where
        T: Headers,
    {
        pub verb: String,
        pub content_md5: String,
        pub content_type: String,
        pub date: Option<String>,
        pub oss_headers: T,
        pub bucket: String,
        pub key: String,
        pub key_id: String,
        pub key_secret: String,
    }

    impl<T> Client<T>
    where
        T: Headers,
    {
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
                canonicalized_ossheaders: oss_headers.to_canonical(),
                canonicalized_resource: format!("/{}/{}", bucket, key),
            }
        }

        pub fn make_authorization(&self) -> String {
            let body = self.make_body();
            let body_str = body.to_string();
            let sig: String = util::sign_base64(&self.key_secret, body_str.as_ref());
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
}
