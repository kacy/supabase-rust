use async_trait::async_trait;
use reqwest::{RequestBuilder, Response};

use crate::Supabase;

#[async_trait]
pub trait Request {
    async fn post(&self, sub_uri: &str, request_body: serde_json::Value) -> Response;
    fn post_raw(&self, url: &str) -> RequestBuilder;
    async fn get(&self, sub_uri: &str) -> Response;
}

#[async_trait]
impl Request for Supabase {
    async fn post(&self, url: &str, request_body: serde_json::Value) -> Response {
        self.client
            .post(url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .unwrap()
    }

    fn post_raw(&self, url: &str) -> RequestBuilder {
        self.client
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
