use sloppy_auth::{aliyun, util};
use std::env;

#[test]
fn ali_putobject() {
    let key_id: String = env::var("ali_key_id").unwrap();
    let key_secret: String = env::var("ali_key_secret").unwrap();
    println!("Read env: id {}\nsecret {}", key_id, key_secret);

    let endpoint = "oss-cn-shanghai.aliyuncs.com";
    let body1 = "hello rust body";

    let bucket = "podcast40".to_string();
    let key = "test1.txt".to_string();
    let host = format!("{}.{}", bucket, endpoint);

    let url1 = format!("http://{}/{}", host, key);

    let format_date = util::get_date_gmt();

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

    let mut list = Vec::new();
    list.push(("Authorization".to_string(), auth.make_authorization()));
    list.push(("Host".to_string(), host));
    list.push(("Content-Type".to_string(), content_type));
    list.push(("Content-Md5".to_string(), content_md5));
    list.push(("Date".to_string(), format_date.clone()));
    list.push((h1, v1));
    list.push((h2, v2));

    let mut request = ureq::put(&url1);

    for (k, v) in list {
        request = request.set(&k, &v);
    }
    match request.send_string(body1) {
        Ok(resp) => {
            println!(
                "response status: {}, body: {}",
                resp.status(),
                resp.into_string().unwrap()
            )
        }
        Err(e) => {
            println!("request failed {:?}", e);
        }
    }
}
