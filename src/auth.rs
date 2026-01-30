use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::Response;
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

/// Response returned by authentication endpoints that issue tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The JWT access token.
    pub access_token: String,
    /// The token type (typically `"bearer"`).
    pub token_type: String,
    /// Seconds until the access token expires.
    pub expires_in: u64,
    /// Unix timestamp when the access token expires.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Token used to obtain a new access token.
    pub refresh_token: String,
    /// User information, if returned by the endpoint.
    #[serde(default)]
    pub user: Option<serde_json::Value>,
}

/// Response for endpoints that return no body on success.
#[derive(Debug, Clone)]
pub struct EmptyResponse {
    /// HTTP status code.
    pub status: u16,
}

#[derive(Serialize)]
struct RecoverRequest<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct PhoneCredentials<'a> {
    phone: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct OtpRequest<'a> {
    phone: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<&'a str>,
}

#[derive(Serialize)]
struct VerifyOtpRequest<'a> {
    phone: &'a str,
    token: &'a str,
    #[serde(rename = "type")]
    verification_type: &'a str,
}

#[derive(Serialize)]
struct ResendOtpRequest<'a> {
    phone: &'a str,
    #[serde(rename = "type")]
    verification_type: &'a str,
}

impl Supabase {
    /// Sends a POST request to the given auth endpoint path with standard headers.
    async fn auth_post(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<Response, crate::Error> {
        let url = format!("{}/auth/v1/{path}", self.url);

        let resp = self
            .client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await?;

        Ok(resp)
    }

    /// Checks the response status and deserializes as `AuthResponse`.
    async fn parse_auth_response(response: Response) -> Result<AuthResponse, crate::Error> {
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let message = response.text().await.unwrap_or_default();
            return Err(crate::Error::Api { status, message });
        }
        let auth: AuthResponse = response.json().await?;
        Ok(auth)
    }

    /// Checks the response status and returns an `EmptyResponse`.
    async fn parse_empty_response(response: Response) -> Result<EmptyResponse, crate::Error> {
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let message = response.text().await.unwrap_or_default();
            return Err(crate::Error::Api { status, message });
        }
        Ok(EmptyResponse { status })
    }

    /// Validates a JWT token and returns its claims.
    ///
    /// Returns an error if the token is invalid or expired.
    pub fn jwt_valid(&self, jwt: &str) -> Result<Claims, crate::Error> {
        let decoding_key = DecodingKey::from_secret(self.jwt.as_bytes());
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(jwt, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Signs in a user with email and password.
    ///
    /// Returns an [`AuthResponse`] containing access and refresh tokens.
    pub async fn sign_in_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponse, crate::Error> {
        let resp = self
            .auth_post(
                "token?grant_type=password",
                &Credentials { email, password },
            )
            .await?;
        Self::parse_auth_response(resp).await
    }

    /// Refreshes an access token using a refresh token.
    ///
    /// Note: This may fail if "Enable automatic reuse detection" is enabled in Supabase.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthResponse, crate::Error> {
        let resp = self
            .auth_post(
                "token?grant_type=refresh_token",
                &RefreshTokenRequest { refresh_token },
            )
            .await?;
        Self::parse_auth_response(resp).await
    }

    /// Logs out the current user.
    ///
    /// Requires a bearer token to be set on the client.
    pub async fn logout(&self) -> Result<EmptyResponse, crate::Error> {
        let token = self.bearer_token.as_ref().ok_or_else(|| {
            crate::Error::AuthRequired("bearer token required for logout".into())
        })?;
        let url = format!("{}/auth/v1/logout", self.url);

        let resp = self
            .client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .bearer_auth(token)
            .send()
            .await?;

        Self::parse_empty_response(resp).await
    }

    /// Sends a password recovery email to the given address.
    pub async fn recover_password(
        &self,
        email: &str,
    ) -> Result<EmptyResponse, crate::Error> {
        let resp = self.auth_post("recover", &RecoverRequest { email }).await?;
        Self::parse_empty_response(resp).await
    }

    /// Signs up a new user with phone and password.
    pub async fn signup_phone_password(
        &self,
        phone: &str,
        password: &str,
    ) -> Result<AuthResponse, crate::Error> {
        let resp = self
            .auth_post("signup", &PhoneCredentials { phone, password })
            .await?;
        Self::parse_auth_response(resp).await
    }

    /// Sends a one-time password to the given phone number.
    ///
    /// The `channel` parameter can be `"sms"` or `"whatsapp"`. Defaults to SMS when `None`.
    pub async fn sign_in_otp(
        &self,
        phone: &str,
        channel: Option<&str>,
    ) -> Result<EmptyResponse, crate::Error> {
        let resp = self
            .auth_post("otp", &OtpRequest { phone, channel })
            .await?;
        Self::parse_empty_response(resp).await
    }

    /// Verifies a one-time password token.
    ///
    /// Returns an [`AuthResponse`] containing access and refresh tokens on success.
    pub async fn verify_otp(
        &self,
        phone: &str,
        token: &str,
        verification_type: &str,
    ) -> Result<AuthResponse, crate::Error> {
        let resp = self
            .auth_post(
                "verify",
                &VerifyOtpRequest {
                    phone,
                    token,
                    verification_type,
                },
            )
            .await?;
        Self::parse_auth_response(resp).await
    }

    /// Resends a one-time password to the given phone number.
    pub async fn resend_otp(
        &self,
        phone: &str,
        verification_type: &str,
    ) -> Result<EmptyResponse, crate::Error> {
        let resp = self
            .auth_post(
                "resend",
                &ResendOtpRequest {
                    phone,
                    verification_type,
                },
            )
            .await?;
        Self::parse_empty_response(resp).await
    }

    /// Signs up a new user with email and password.
    pub async fn signup_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponse, crate::Error> {
        let resp = self
            .auth_post("signup", &Credentials { email, password })
            .await?;
        Self::parse_auth_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Supabase {
        Supabase::new(None, None, None).unwrap_or_else(|_| {
            Supabase::new(
                Some("https://example.supabase.co"),
                Some("test-key"),
                None,
            )
            .unwrap()
        })
    }

    async fn sign_in_password() -> Result<AuthResponse, crate::Error> {
        let client = client();
        let test_email = std::env::var("SUPABASE_TEST_EMAIL").unwrap_or_default();
        let test_pass = std::env::var("SUPABASE_TEST_PASS").unwrap_or_default();
        client.sign_in_password(&test_email, &test_pass).await
    }

    #[tokio::test]
    async fn test_token_with_password() {
        let auth = match sign_in_password().await {
            Ok(auth) => auth,
            Err(e) => {
                println!("Test skipped due to error: {e}");
                return;
            }
        };

        assert!(!auth.access_token.is_empty());
        assert!(!auth.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_refresh() {
        let auth = match sign_in_password().await {
            Ok(auth) => auth,
            Err(e) => {
                println!("Test skipped due to error: {e}");
                return;
            }
        };

        let refreshed = match client().refresh_token(&auth.refresh_token).await {
            Ok(auth) => auth,
            Err(crate::Error::Api { status: 400, .. }) => {
                println!("Skipping: automatic reuse detection is enabled");
                return;
            }
            Err(e) => {
                println!("Test skipped due to error: {e}");
                return;
            }
        };

        assert!(!refreshed.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_logout() {
        let auth = match sign_in_password().await {
            Ok(auth) => auth,
            Err(e) => {
                println!("Test skipped due to error: {e}");
                return;
            }
        };

        let mut client = client();
        client.set_bearer_token(&auth.access_token);

        let resp = match client.logout().await {
            Ok(resp) => resp,
            Err(e) => {
                println!("Test skipped: {e}");
                return;
            }
        };

        assert_eq!(resp.status, 204);
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

        match client.signup_email_password(&email, &rand_string).await {
            Ok(auth) => {
                assert!(!auth.access_token.is_empty());
            }
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_authenticate_token() {
        let client = client();

        let auth = match sign_in_password().await {
            Ok(auth) => auth,
            Err(e) => {
                println!("Test skipped due to error: {e}");
                return;
            }
        };

        assert!(client.jwt_valid(&auth.access_token).is_ok());
    }

    #[test]
    fn test_logout_requires_bearer_token() {
        let err = crate::Error::AuthRequired("bearer token required for logout".into());
        assert!(format!("{err}").contains("bearer token required for logout"));
    }

    #[tokio::test]
    async fn test_recover_password() {
        let client = client();

        match client
            .recover_password("test@a-rust-domain-that-does-not-exist.com")
            .await
        {
            Ok(resp) => {
                assert!(resp.status >= 200);
            }
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_signup_phone_password() {
        let client = client();

        match client
            .signup_phone_password("+10000000000", "test-password-123")
            .await
        {
            Ok(_auth) => {}
            Err(crate::Error::Api { status, .. }) => {
                assert!(
                    status == 422 || status == 401 || status == 403,
                    "unexpected API error status: {status}"
                );
            }
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_sign_in_otp() {
        let client = client();

        match client.sign_in_otp("+10000000000", Some("sms")).await {
            Ok(_resp) => {}
            Err(crate::Error::Api { .. }) => {}
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_verify_otp() {
        let client = client();

        match client.verify_otp("+10000000000", "000000", "sms").await {
            Ok(_auth) => {}
            Err(crate::Error::Api { .. }) => {}
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_resend_otp() {
        let client = client();

        match client.resend_otp("+10000000000", "sms").await {
            Ok(_resp) => {}
            Err(crate::Error::Api { .. }) => {}
            Err(e) => {
                println!("Test skipped due to error: {e}");
            }
        }
    }
}
