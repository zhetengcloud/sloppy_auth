use chrono::prelude::Utc;

//aliyun date format
pub fn get_date() -> String {
    Utc::now().format("%a, %d %b %Y %T GMT").to_string()
}

pub fn md5(content: Vec<u8>) -> String {
    base64::encode(*md5::compute(&content))
}
