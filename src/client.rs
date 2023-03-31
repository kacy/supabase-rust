use std::{env};
use reqwest::{Client};

use crate::Supabase;

impl Supabase {
    pub fn new(url: Option<&str>, api_key: Option<&str>) -> Self {
        let client: Client = Client::new();
        let url: String = url
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_URL").unwrap_or_else(|_| String::new()));
        let api_key: String = api_key
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_API_KEY").unwrap_or_else(|_| String::new()));

        Supabase {
            client,
            url: url.to_string(),
            api_key: api_key.to_string(),
        }
    }
}