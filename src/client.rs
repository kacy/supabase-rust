use std::env;

use reqwest::Client;

use crate::Supabase;

impl Supabase {
    /// Creates a new Supabase client.
    ///
    /// `url` and `api_key` are required — they must be provided as arguments or
    /// set via the `SUPABASE_URL` and `SUPABASE_API_KEY` environment variables.
    /// Returns `Error::Config` if either value is missing or empty.
    ///
    /// `jwt` is optional and defaults to an empty string when not provided.
    pub fn new(
        url: Option<&str>,
        api_key: Option<&str>,
        jwt: Option<&str>,
    ) -> Result<Self, crate::Error> {
        let url = url
            .map(Into::into)
            .or_else(|| env::var("SUPABASE_URL").ok())
            .filter(|s: &String| !s.is_empty())
            .ok_or_else(|| {
                crate::Error::Config(
                    "missing SUPABASE_URL: provide as argument or set the environment variable"
                        .into(),
                )
            })?;

        let api_key = api_key
            .map(Into::into)
            .or_else(|| env::var("SUPABASE_API_KEY").ok())
            .filter(|s: &String| !s.is_empty())
            .ok_or_else(|| {
                crate::Error::Config(
                    "missing SUPABASE_API_KEY: provide as argument or set the environment variable"
                        .into(),
                )
            })?;

        let jwt = jwt
            .map(Into::into)
            .unwrap_or_else(|| env::var("SUPABASE_JWT_SECRET").unwrap_or_default());

        Ok(Self {
            client: Client::new(),
            url,
            api_key,
            jwt,
            bearer_token: None,
        })
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
        )
        .unwrap();
        assert_eq!(client.url, "https://example.supabase.co");
        assert_eq!(client.api_key, "test-key");
        assert_eq!(client.jwt, "test-jwt");
    }

    #[test]
    fn test_client_missing_url() {
        // When no URL is provided and env var is not set, should return Error::Config
        let result = Supabase::new(None, Some("key"), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));
    }

    #[test]
    fn test_client_missing_api_key() {
        let result = Supabase::new(Some("https://example.supabase.co"), None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));
    }

    #[test]
    fn test_client_empty_url() {
        let result = Supabase::new(Some(""), Some("key"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_empty_api_key() {
        let result = Supabase::new(Some("https://example.supabase.co"), Some(""), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_bearer_token() {
        let mut client = Supabase::new(
            Some("https://example.supabase.co"),
            Some("test-key"),
            None,
        )
        .unwrap();
        client.set_bearer_token("my-token");
        assert_eq!(client.bearer_token, Some("my-token".to_string()));
    }
}
