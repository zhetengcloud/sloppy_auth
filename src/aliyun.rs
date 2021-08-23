// https://help.aliyun.com/document_detail/100669.html
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};

fn sign_base64(key_secret: &str, body: &str) -> String {
    let mut mac = Hmac::new(Sha1::new(), key_secret.as_bytes());
    mac.input(body.as_bytes());
    base64::encode(mac.result().code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        let key1 = "key1";
        let body1 = "body1";
        assert_eq!(sign_base64(key1,body1), "u3fznj0yiE48+1xlkideoCqhhdc=")
    }
}
