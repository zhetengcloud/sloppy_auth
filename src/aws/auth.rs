use crate::util::{uri_encode, Headers, LONG_DATETIME, SHORT_DATE};
use chrono::{DateTime, Utc};
use ring::{digest, hmac};
use url::Url;

pub const AWS4_SHA256: &str = "AWS4-HMAC-SHA256";
pub const AWS_SHA256_PAYLOAD: &str = "AWS4-HMAC-SHA256-PAYLOAD";

pub struct Sign<'a, T>
where
    T: Headers,
{
    pub method: &'a str,
    pub url: Url,
    pub datetime: &'a DateTime<Utc>,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub headers: T,
    pub hash_request: String,
}

impl<'a, T> Sign<'a, T>
where
    T: Headers,
{
    pub fn signed_header_string(&self) -> String {
        let mut keys = self
            .headers
            .clone()
            .into_iter()
            .map(|(key, _)| key.to_lowercase())
            .collect::<Vec<String>>();
        keys.sort();
        keys.join(";")
    }

    pub fn canonical_request(&self) -> String {
        let url: String = self.url.path().into();

        vec![
            self.method.to_string(),
            url,
            canonical_query_string(&self.url),
            self.headers.to_canonical(),
            self.signed_header_string(),
            self.hash_request.clone(),
        ]
        .join("\n")
    }

    //Authorization header
    pub fn sign(&self) -> String {
        format!(
            "{} Credential={}/{},SignedHeaders={},Signature={}",
            AWS4_SHA256,
            self.access_key,
            scope_string(self.datetime, self.region),
            self.signed_header_string(),
            self.calc_seed_signature()
        )
    }

    pub fn calc_seed_signature(&self) -> String {
        let canonical = self.canonical_request();
        let string_to_sign = string_to_sign(self.datetime, self.region, &canonical);
        hex_sha256(self.signing_key(), string_to_sign)
    }

    pub fn chunk_string_to_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
        let hash_empty = digest::digest(&digest::SHA256, b"");
        let hash_data = digest::digest(&digest::SHA256, data.as_slice());
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            AWS_SHA256_PAYLOAD,
            self.datetime.format(LONG_DATETIME),
            scope_string(self.datetime, self.region),
            prev_sig,
            hex::encode(hash_empty),
            hex::encode(hash_data),
        )
    }

    pub fn chunk_sign(&self, prev_sig: String, data: Vec<u8>) -> String {
        hex_sha256(
            self.signing_key(),
            self.chunk_string_to_sign(prev_sig, data),
        )
    }

    pub fn signing_key(&self) -> Vec<u8> {
        use hmac::{sign, Key, HMAC_SHA256};

        let service = "s3";
        let secret = format!("AWS4{}", self.secret_key);
        let date_key = Key::new(HMAC_SHA256, secret.as_bytes());
        let date_tag = sign(
            &date_key,
            self.datetime.format(SHORT_DATE).to_string().as_bytes(),
        );

        let region_key = Key::new(HMAC_SHA256, date_tag.as_ref());
        let region_tag = sign(&region_key, self.region.as_bytes());

        let service_key = Key::new(HMAC_SHA256, region_tag.as_ref());
        let service_tag = sign(&service_key, service.as_bytes());

        let signing_key = Key::new(HMAC_SHA256, service_tag.as_ref());
        let signing_tag = sign(&signing_key, b"aws4_request");
        signing_tag.as_ref().to_vec()
    }
}

pub fn hex_sha256(key: Vec<u8>, s: String) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let tag = hmac::sign(&key, s.as_bytes());
    hex::encode(tag.as_ref())
}

pub fn canonical_query_string(uri: &Url) -> String {
    let mut keyvalues = uri
        .query_pairs()
        .map(|(key, value)| uri_encode(&key, true) + "=" + &uri_encode(&value, true))
        .collect::<Vec<String>>();
    keyvalues.sort();
    keyvalues.join("&")
}

pub fn scope_string(datetime: &DateTime<Utc>, region: &str) -> String {
    format!("{}/{}/s3/aws4_request", datetime.format(SHORT_DATE), region)
}

pub fn string_to_sign(datetime: &DateTime<Utc>, region: &str, canonical_req: &str) -> String {
    let hash = digest::digest(&digest::SHA256, canonical_req.as_bytes());
    format!(
        "{}\n{}\n{}\n{}",
        AWS4_SHA256,
        datetime.format(LONG_DATETIME),
        scope_string(datetime, region),
        hex::encode(hash.as_ref())
    )
}
