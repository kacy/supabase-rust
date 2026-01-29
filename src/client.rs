use std::env;

use reqwest::Client;

use crate::Supabase;

impl Supabase {
    /// Creates a new Supabase client.
    ///
    /// If no parameters are provided, it will attempt to read from environment
    /// variables: `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET`.
    pub fn new(url: Option<&str>, api_key: Option<&str>, jwt: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            url: url
                .map(Into::into)
                .unwrap_or_else(|| env::var("SUPABASE_URL").unwrap_or_default()),
            api_key: api_key
                .map(Into::into)
                .unwrap_or_else(|| env::var("SUPABASE_API_KEY").unwrap_or_default()),
            jwt: jwt
                .map(Into::into)
                .unwrap_or_else(|| env::var("SUPABASE_JWT_SECRET").unwrap_or_default()),
            bearer_token: None,
        }
    }

    /// Sets the bearer token for authenticated requests.
    pub fn set_bearer_token(&mut self, token: impl Into<String>) {
        self.bearer_token = Some(token.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Supabase::new(
            Some("https://example.supabase.co"),
            Some("test-key"),
            Some("test-jwt"),
        );
        assert_eq!(client.url, "https://example.supabase.co");
        assert_eq!(client.api_key, "test-key");
        assert_eq!(client.jwt, "test-jwt");
    }

    #[test]
    fn test_client_from_env() {
        // When env vars are not set, fields should be empty
        let client = Supabase::new(None, None, None);
        assert!(client.bearer_token.is_none());
    }

    #[test]
    fn test_set_bearer_token() {
        let mut client = Supabase::new(None, None, None);
        client.set_bearer_token("my-token");
        assert_eq!(client.bearer_token, Some("my-token".to_string()));
    }
}
