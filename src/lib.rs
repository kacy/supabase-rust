//! # supabase-rust
//!
//! An unofficial Rust client for [Supabase](https://supabase.com).
//!
//! Provides typed access to Supabase Auth and PostgREST (database) APIs.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use supabase_rust::{Supabase, AuthResponse, Error};
//!
//! # async fn run() -> Result<(), Error> {
//! let client = Supabase::new(
//!     Some("https://your-project.supabase.co"),
//!     Some("your-api-key"),
//!     None,
//! )?;
//!
//! // Sign in
//! let auth: AuthResponse = client
//!     .sign_in_password("user@example.com", "password")
//!     .await?;
//! println!("access token: {}", auth.access_token);
//!
//! // Query the database
//! let response = client
//!     .from("todos")
//!     .select("*")
//!     .eq("user_id", &auth.access_token)
//!     .execute()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use reqwest::Client;

pub mod auth;
pub mod db;
pub mod error;
mod client;

pub use auth::{AuthResponse, Claims};
pub use db::QueryBuilder;
pub use error::Error;

/// The Supabase client. Entry point for all operations.
#[derive(Clone, Debug)]
pub struct Supabase {
    client: Client,
    url: String,
    api_key: String,
    jwt: String,
    bearer_token: Option<String>,
}
