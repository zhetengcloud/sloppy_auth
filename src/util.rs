use chrono::prelude::Utc;
use md5::{Digest, Md5};

pub fn get_date() -> String {
    Utc::now().format("%a, %d %b %Y %T GMT").to_string()
}

pub fn content_md5(bytes: &Vec<u8>) -> String {
    let mut m = Md5::default();
    m.update(bytes);
    let digest = m.finalize();
    base64::encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_test() {
        let s = "0123456789";
        let expect = "eB5eJF1ptWaXm4bijSPyxw==";
        let calc = content_md5(&s.as_bytes().to_vec());
        assert_eq!(expect, calc);
    }
}
