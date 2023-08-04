use async_trait::async_trait;
use postgrest::Postgrest;
use crate::config::SupabaseConfig;

use super::base::{ ClientError, Client, OperationError };


pub struct DatabaseClient {
    pub client: Postgrest,
}

impl DatabaseClient {
    pub fn new() -> Self {
        let config = SupabaseConfig::default();
        let client = Postgrest::new(&config.supabase_url_database)
            .insert_header(
                "apikey",
                &config.supabase_api_key);

        Self { client }
    }
}


#[async_trait]
impl Client for DatabaseClient {
    async fn insert(&self, table: &str, data: &str) -> Result<(), ClientError> {
        let result = self.client
            .from(table)
            .insert(data)
            .execute()
            .await
            .map_err(|value| ClientError::OperationFailed(value.to_string()))?;

            if let Ok(oe) = serde_json::from_str::<OperationError>(&result.text().await.unwrap()) {
                return Err(ClientError::InsertFailed(oe));
            }

            Ok(())
    }
}
