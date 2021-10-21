use chrono::prelude::Utc;
use ring::hmac::{self, HMAC_SHA1_FOR_LEGACY_USE_ONLY};

pub const SHORT_DATE: &str = "%Y%m%d";
pub const LONG_DATETIME: &str = "%Y%m%dT%H%M%SZ";
pub const GMT_DATETIME: &str = "%a, %d %b %Y %T GMT";

//aliyun date format
pub fn get_date_gmt() -> String {
    Utc::now().format(GMT_DATETIME).to_string()
}

pub fn get_date_long() -> String {
    Utc::now().format(LONG_DATETIME).to_string()
}

pub fn md5(content: Vec<u8>) -> String {
    base64::encode(*md5::compute(&content))
}

pub trait Headers: IntoIterator<Item = (String, String)> + Clone
where
    Self: std::marker::Sized,
{
    fn to_canonical(&self) -> String;
}

impl<T> Headers for T
where
    T: IntoIterator<Item = (String, String)> + Clone,
{
    fn to_canonical(&self) -> String {
        let mut list_to_sort = self
            .clone()
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect::<Vec<(String, String)>>();
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

pub fn sign_base64(key_secret: &str, body: &str) -> String {
    let key = hmac::Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, key_secret.as_bytes());
    let tag = hmac::sign(&key, body.as_bytes());
    base64::encode(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn util_headers() {
        let headers1 = vec![
            ("X-OSS-Z-Name".to_string(), "Val1".to_string()),
            ("X-OSS-OMeta-Name".to_string(), "val2".to_string()),
            ("X-OSS-Meta-a".to_string(), "Cval".to_string()),
            ("X-OSS-Meta-b".to_string(), "Eval".to_string()),
            ("X-OSS-Neta-a".to_string(), "Dval".to_string()),
        ];
        let expect1 = "x-oss-meta-a:Cval\nx-oss-meta-b:Eval\nx-oss-neta-a:Dval\nx-oss-ometa-name:val2\nx-oss-z-name:Val1\n";
        assert_eq!(headers1.to_canonical(), expect1);
        let headers2 = vec![];
        assert_eq!(headers2.to_canonical(), "");

        let mut map1: HashMap<String, String> = HashMap::new();
        map1.extend(headers1);
        assert_eq!(map1.to_canonical(), expect1);
    }

    #[test]
    fn util_base64() {
        let key1 = "key1";
        let body1 = "body1";
        assert_eq!(sign_base64(key1, body1), "u3fznj0yiE48+1xlkideoCqhhdc=")
    }
}
