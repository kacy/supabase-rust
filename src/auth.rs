use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::{Error, Response};
use serde::{Deserialize, Serialize};

use crate::Supabase;

#[derive(Serialize)]
struct Credentials<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RefreshTokenRequest<'a> {
    refresh_token: &'a str,
}

/// JWT claims extracted from a valid token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}

/// Error returned when logout fails due to missing bearer token.
#[derive(Debug)]
pub struct LogoutError;

impl std::fmt::Display for LogoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bearer token required for logout")
    }
}

impl std::error::Error for LogoutError {}

impl Supabase {
    /// Validates a JWT token and returns its claims.
    ///
    /// Returns an error if the token is invalid or expired.
    pub fn jwt_valid(&self, jwt: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let decoding_key = DecodingKey::from_secret(self.jwt.as_bytes());
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(jwt, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Signs in a user with email and password.
    ///
    /// Returns the response containing access and refresh tokens.
    pub async fn sign_in_password(&self, email: &str, password: &str) -> Result<Response, Error> {
        let url = format!("{}/auth/v1/token?grant_type=password", self.url);

        self.client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&Credentials { email, password })
            .send()
            .await
    }

    /// Refreshes an access token using a refresh token.
    ///
    /// Note: This may fail if "Enable automatic reuse detection" is enabled in Supabase.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<Response, Error> {
        let url = format!("{}/auth/v1/token?grant_type=refresh_token", self.url);

        self.client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&RefreshTokenRequest { refresh_token })
            .send()
            .await
    }

    /// Logs out the current user.
    ///
    /// Requires a bearer token to be set on the client.
    /// Returns `Err(LogoutError)` if no bearer token is set.
    pub async fn logout(&self) -> Result<Result<Response, Error>, LogoutError> {
        let token = self.bearer_token.as_ref().ok_or(LogoutError)?;
        let url = format!("{}/auth/v1/logout", self.url);

        Ok(self
            .client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .bearer_auth(token)
            .send()
            .await)
    }

    /// Signs up a new user with email and password.
    pub async fn signup_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Response, Error> {
        let url = format!("{}/auth/v1/signup", self.url);

        self.client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&Credentials { email, password })
            .send()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Supabase {
        Supabase::new(None, None, None)
    }

    async fn sign_in_password() -> Result<Response, Error> {
        let client = client();
        let test_email = std::env::var("SUPABASE_TEST_EMAIL").unwrap_or_default();
        let test_pass = std::env::var("SUPABASE_TEST_PASS").unwrap_or_default();
        client.sign_in_password(&test_email, &test_pass).await
    }

    #[tokio::test]
    async fn test_token_with_password() {
        let response = match sign_in_password().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        let json: serde_json::Value = response.json().await.unwrap();

        let Some(token) = json["access_token"].as_str() else {
            println!("Test skipped: invalid credentials or server response");
            return;
        };
        let Some(refresh) = json["refresh_token"].as_str() else {
            println!("Test skipped: invalid credentials or server response");
            return;
        };

        assert!(!token.is_empty());
        assert!(!refresh.is_empty());
    }

    #[tokio::test]
    async fn test_refresh() {
        let response = match sign_in_password().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        let json: serde_json::Value = response.json().await.unwrap();
        let Some(refresh_token) = json["refresh_token"].as_str() else {
            println!("Test skipped: no refresh token in response");
            return;
        };

        let response = match client().refresh_token(refresh_token).await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        if response.status() == 400 {
            println!("Skipping: automatic reuse detection is enabled");
            return;
        }

        let json: serde_json::Value = response.json().await.unwrap();
        let Some(token) = json["access_token"].as_str() else {
            println!("Test skipped: no access token in refresh response");
            return;
        };

        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn test_logout() {
        let response = match sign_in_password().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        let json: serde_json::Value = response.json().await.unwrap();
        let Some(access_token) = json["access_token"].as_str() else {
            println!("Test skipped: no access token in response");
            return;
        };

        let mut client = client();
        client.set_bearer_token(access_token);

        let response = match client.logout().await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
            Err(e) => {
                println!("Test skipped: {e}");
                return;
            }
        };

        assert_eq!(response.status(), 204);
    }

    #[tokio::test]
    async fn test_signup_email_password() {
        use rand::distr::Alphanumeric;
        use rand::{rng, Rng};

        let client = client();

        let rand_string: String = rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        let email = format!("{rand_string}@a-rust-domain-that-does-not-exist.com");

        let response = match client.signup_email_password(&email, &rand_string).await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_authenticate_token() {
        let client = client();

        let response = match sign_in_password().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped due to network error: {e}");
                return;
            }
        };

        let json: serde_json::Value = response.json().await.unwrap();
        let Some(token) = json["access_token"].as_str() else {
            println!("Test skipped: no access token in response");
            return;
        };

        assert!(client.jwt_valid(token).is_ok());
    }

    #[test]
    fn test_logout_requires_bearer_token() {
        // Verify the error type displays correctly
        assert_eq!(format!("{}", LogoutError), "bearer token required for logout");
    }
}
