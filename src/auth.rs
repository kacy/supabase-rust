use reqwest::{Error, Response};
use serde::{Deserialize, Serialize};

use crate::Supabase;

#[derive(Serialize, Deserialize)]
pub struct Password {
    email: String,
    password: String,
}

impl Supabase {
    pub async fn sign_in_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Response, Error> {
        let request_url: String = format!("{}/auth/v1/token?grant_type=password", self.url);
        let response: Response = self
            .client
            .post(&request_url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&Password {
                email: email.to_string(),
                password: password.to_string(),
            })
            .send()
            .await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client() {
        let client: Supabase = Supabase::new(None, None);
        let url = std::env::var("SUPABASE_URL").unwrap_or_else(|_| String::new());
        assert!(client.url == url);
    }

    #[tokio::test]
    async fn test_token_with_password() {
        // let client: Supabase = Supabase::new(Some(URL), Some(API_KEY));
        let client: Supabase = Supabase::new(None, None);

        let test_email: String = std::env::var("SUPABASE_TEST_EMAIL").unwrap_or_else(|_| String::new());
        let test_pass: String= std::env::var("SUPABASE_TEST_PASS").unwrap_or_else(|_| String::new());
        let response: Response = client.sign_in_password(&test_email, &test_pass).await.unwrap();

        let json_response: serde_json::Value = response.json().await.unwrap();
        let token: &str = json_response["access_token"].as_str().unwrap();
        let refresh_token: &str = json_response["refresh_token"].as_str().unwrap();

        assert!(token.len() > 0);
        assert!(refresh_token.len() > 0);
    }
}