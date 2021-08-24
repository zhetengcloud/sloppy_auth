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
    let mut body1 = "test body".as_bytes();

    let bucket = "podcast40".to_string();
    let key = "test1.txt".to_string();
    let host = format!("{}.{}", bucket, url1);

    easy.url(&format!("http://{}/{}", host, key)).unwrap();
    easy.put(true).unwrap();

    let mut headers = List::new();
    headers.append("key1: val1").unwrap();

    let format_date = util::get_date();

    println!("date {}",format_date);

    let auth = aliyun::oss::Client {
        verb: "PUT".to_string(),
        content: body1.to_vec(),
        oss_headers: [].to_vec(),
        bucket,
        content_type: "text/plain".to_string(),
        date: Some(format_date),
        key,
        key_id,
        key_secret,
    };

    headers
        .append(&format!("Authorization: {}", auth.make_authorization()))
        .unwrap();
    headers.append(&format!("Host: {}", host)).unwrap();

    easy.http_headers(headers).unwrap();

    {
        let mut transfer = easy.transfer();
        transfer
            .read_function(|buf| Ok(body1.read(buf).unwrap_or(0)))
            .unwrap();
        transfer
            .write_function(|dt| {
                buf.extend_from_slice(dt);
                Ok(dt.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    let res = String::from_utf8(buf).unwrap();
    println!("{}", res)
}
