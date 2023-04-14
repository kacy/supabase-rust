use reqwest::{Client};

mod auth;
mod client;
mod db;

pub struct Supabase {
    client: Client,
    url: String,
    api_key: String,
    jwt: String,
    bearer_token: Option<String>,
}
