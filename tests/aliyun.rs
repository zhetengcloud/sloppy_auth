use curl::easy::{Easy, List};
use sloppy_auth::{aliyun, util};
use std::env;
use std::io::Read;

#[test]
fn putobject() {
    let key_id: String = env::var("ali_key_id").unwrap();
    let key_secret: String = env::var("ali_key_secret").unwrap();
    println!("Read env: id {}\nsecret {}", key_id, key_secret);

    let url1 = "oss-cn-shanghai.aliyuncs.com";
    let mut buf: Vec<u8> = Vec::new();
    let mut easy = Easy::new();
    let body1 = "hello rust body";

    let bucket = "podcast40".to_string();
    let key = "test1.txt".to_string();
    let host = format!("{}.{}", bucket, url1);

    easy.url(&format!("http://{}/{}", host, key)).unwrap();
    easy.verbose(true).unwrap();
    easy.put(true).unwrap();

    let mut headers = List::new();

    let format_date = util::get_date();

    let content_md5 = util::md5(body1.as_bytes().to_vec());
    let content_type = "text/plain".to_string();

    let h1 = "X-OSS-Meta-Author".to_string();
    let v1 = "foo@bar.com".to_string();
    let h2 = "X-OSS-TMa".to_string();
    let v2 = "foo123".to_string();
    let x_oss_1 = (h1.clone(), v1.clone());
    let x_oss_2 = (h2.clone(), v2.clone());

    let auth = aliyun::oss::Client {
        verb: "PUT".to_string(),
        content_md5: content_md5.clone(),
        content_type: content_type.clone(),
        oss_headers: vec![x_oss_1, x_oss_2],
        bucket,
        date: Some(format_date.clone()),
        key,
        key_id,
        key_secret,
    };

    headers
        .append(&format!("Authorization: {}", auth.make_authorization()))
        .unwrap();
    headers.append(&format!("Host: {}", host)).unwrap();
    headers
        .append(&format!("Content-Type: {}", content_type))
        .unwrap();
    headers
        .append(&format!("Content-Md5: {}", content_md5))
        .unwrap();
    headers
        .append(&format!("Date: {}", format_date.clone()))
        .unwrap();
    headers.append(&format!("{}: {}", h1, v1)).unwrap();
    headers.append(&format!("{}: {}", h2, v2)).unwrap();

    easy.http_headers(headers).unwrap();

    {
        let mut body2 = body1.as_bytes();
        let mut transfer = easy.transfer();
        transfer
            .read_function(|buf| Ok(body2.read(buf).unwrap_or(0)))
            .unwrap();
        transfer
            .write_function(|dt| {
                buf.extend_from_slice(dt);
                Ok(dt.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }
}
