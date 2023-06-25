use std::env;
use reqwest::{Client, Response, RequestBuilder};
use async_trait::async_trait;

use crate::Supabase;

#[async_trait]
pub trait Request {
    async fn post(&self, sub_uri: &str, request_body: serde_json::Value) -> Response;
    fn post_raw(&self, url: &str) -> RequestBuilder;
    async fn get(&self, sub_uri: &str) -> Response;
}

impl Supabase {
    /// Creates a new Supabase client. If no parameters are provided, it will attempt to read the
    /// environment variables `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET`.
    /// Create new `Data` instance.
    pub fn new(url: Option<&str>, api_key: Option<&str>, jwt: Option<&str>) -> Self {
        let client: Client = Client::new();
        let url: String = url
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_URL").unwrap_or_else(|_| String::new()));
        let api_key: String = api_key
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_API_KEY").unwrap_or_else(|_| String::new()));
        let jwt: String = jwt
            .map(String::from)
            .unwrap_or_else(|| env::var("SUPABASE_JWT_SECRET").unwrap_or_else(|_| String::new()));

        Supabase {
            client,
            url: url.to_string(),
            api_key: api_key.to_string(),
            jwt: jwt.to_string(),
            bearer_token: None,
        }
    }
}

#[async_trait]
impl Request for Supabase {
    async fn post(&self, url: &str, request_body: serde_json::Value) -> Response {
        self
            .client
            .post(url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .unwrap()
    }

    fn post_raw(&self, url: &str) -> RequestBuilder {
        self
            .client
            .post(url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
    }

    async fn get(&self, url: &str) -> Response {
        self.client
            .get(url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .send()
            .await
            .unwrap()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client() {
        let client: Supabase = Supabase::new(None, None, None);
        let url = client.url.clone();
        assert!(client.url == url);
    }
}
