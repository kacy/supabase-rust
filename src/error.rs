/// Unified error type for all supabase-rust operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Missing or empty configuration value (URL or API key).
    #[error("configuration error: {0}")]
    Config(String),

    /// HTTP transport failure.
    #[error(transparent)]
    Request(#[from] reqwest::Error),

    /// JSON serialization or deserialization failure.
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    /// JWT validation failure.
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// An authenticated operation was attempted without a bearer token.
    #[error("authentication required: {0}")]
    AuthRequired(String),

    /// The Supabase API returned a non-2xx response.
    #[error("API error {status}: {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Error message from the response body.
        message: String,
    },
}
