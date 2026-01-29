use reqwest::Client;

pub mod auth;
mod client;
pub mod db;

#[derive(Clone, Debug)]
pub struct Supabase {
    client: Client,
    url: String,
    api_key: String,
    jwt: String,
    bearer_token: Option<String>,
}
