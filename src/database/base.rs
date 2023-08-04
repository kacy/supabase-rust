use derive_more::Display;

use async_trait::async_trait;
use serde::Deserialize;

#[async_trait]
pub trait Client {
    async fn insert(&self, table: &str, data: &str) -> Result<(), ClientError>;
}


#[allow(dead_code)]
#[derive(Debug, Display)]
pub enum ClientError {
    #[display(fmt = "insert failed")]
    InsertFailed(OperationError),
    #[display(fmt = "operation failed")]
    OperationFailed(String),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct OperationError {
    code: String,
    details: String,
    hint: Option<String>,
    message: String,
}
