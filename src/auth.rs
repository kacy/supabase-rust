use reqwest::{Error, Response};
use serde::{Deserialize, Serialize};

use crate::Supabase;

#[derive(Serialize, Deserialize)]
pub struct Password {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshToken {
    refresh_token: String,
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

    // This test will fail unless you disable "Enable automatic reuse detection" in Supabase
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<Response, Error> {
        let request_url: String = format!("{}/auth/v1/token?grant_type=refresh_token", self.url);
        let response: Response = self
            .client
            .post(&request_url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&RefreshToken {
                refresh_token: refresh_token.to_string(),
            })
            .send()
            .await?;
        Ok(response)
    }

    pub async fn logout(&self) -> Result<Response, Error> {
        let request_url: String = format!("{}/auth/v1/logout", self.url);
        let token = self.bearer_token.clone().unwrap();
        let response: Response = self
            .client
            .post(&request_url)
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .bearer_auth(token)
            .send()
            .await?;
        Ok(response)
    }

    pub async fn signup_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Response, Error> {
        let request_url: String = format!("{}/auth/v1/signup", self.url);
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

    async fn client() -> Supabase {
        Supabase::new(None, None)
    }

    async fn sign_in_password() -> Response {
        let client: Supabase = client().await;

        let test_email: String = std::env::var("SUPABASE_TEST_EMAIL").unwrap_or_else(|_| String::new());
        let test_pass: String= std::env::var("SUPABASE_TEST_PASS").unwrap_or_else(|_| String::new());
        client.sign_in_password(&test_email, &test_pass).await.unwrap()
    }

    #[tokio::test]
    async fn test_token_with_password() {
        let response: Response = sign_in_password().await;

        let json_response: serde_json::Value = response.json().await.unwrap();
        let token: &str = json_response["access_token"].as_str().unwrap();
        let refresh_token: &str = json_response["refresh_token"].as_str().unwrap();

        assert!(token.len() > 0);
        assert!(refresh_token.len() > 0);
    }

    #[tokio::test]
    async fn test_refresh() {
        let response: Response = sign_in_password().await;

        let json_response: serde_json::Value = response.json().await.unwrap();
        let refresh_token: &str = json_response["refresh_token"].as_str().unwrap();

        let response: Response = client().await.refresh_token(&refresh_token).await.unwrap();
        if response.status() == 400 {
            println!("Skipping test_refresh() because automatic reuse detection is enabled in Supabase");
            return;
        }
        
        let json_response: serde_json::Value = response.json().await.unwrap();
        let token: &str = json_response["access_token"].as_str().unwrap();

        assert!(token.len() > 0);
    }

    #[tokio::test]
    async fn test_logout() {
        let response: Response = sign_in_password().await;

        let json_response: serde_json::Value = response.json().await.unwrap();
        let access_token: &str = json_response["access_token"].as_str().unwrap();
        let mut client: Supabase = client().await;
        client.bearer_token = Some(access_token.to_string());

        let response: Response = client.logout().await.unwrap();
        print!("{:?}", response);

        assert!(response.status() == 204);
    }

        #[tokio::test]
    async fn test_signup_email_password() {
        use rand::{thread_rng, Rng, distributions::Alphanumeric};

        let client: Supabase = client().await;

        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        let random_email: String = format!("{}@a-rust-domain-that-does-not-exist.com", rand_string);
        let random_pass: String = rand_string;

        let test_email: String = random_email;
        let test_pass: String= random_pass;
        let response: Response = client.signup_email_password(&test_email, &test_pass).await.unwrap();
        print!("{:?}", response);

        assert!(response.status() == 200);
    }

}