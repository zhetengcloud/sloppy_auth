use chrono::prelude::Utc;

pub fn get_date() -> String {
    Utc::now().format("%a, %d %b %Y %T GMT").to_string()
}
