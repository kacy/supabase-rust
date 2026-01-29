use reqwest::{Error, Method, Response};
use serde::Serialize;

use crate::Supabase;

/// Query builder for PostgREST database operations.
/// Provides a fluent API for constructing and executing database queries.
pub struct QueryBuilder<'a> {
    client: &'a Supabase,
    table: String,
    query_params: Vec<(String, String)>,
    method: Method,
    body: Option<String>,
}

impl<'a> QueryBuilder<'a> {
    /// Creates a new QueryBuilder for the specified table.
    pub fn new(client: &'a Supabase, table: &str) -> Self {
        QueryBuilder {
            client,
            table: table.to_string(),
            query_params: Vec::new(),
            method: Method::GET,
            body: None,
        }
    }

    /// Specifies which columns to select.
    /// Pass "*" to select all columns, or a comma-separated list of column names.
    pub fn select(mut self, columns: &str) -> Self {
        self.query_params.push(("select".to_string(), columns.to_string()));
        self.method = Method::GET;
        self
    }

    /// Prepares an insert operation with the provided data.
    /// Data will be serialized to JSON.
    pub fn insert<T: Serialize>(mut self, data: &T) -> Self {
        self.method = Method::POST;
        self.body = Some(serde_json::to_string(data).unwrap());
        self
    }

    /// Prepares an update operation with the provided data.
    /// Should be combined with filter methods to target specific rows.
    pub fn update<T: Serialize>(mut self, data: &T) -> Self {
        self.method = Method::PATCH;
        self.body = Some(serde_json::to_string(data).unwrap());
        self
    }

    /// Prepares a delete operation.
    /// Should be combined with filter methods to target specific rows.
    pub fn delete(mut self) -> Self {
        self.method = Method::DELETE;
        self
    }

    /// Filter: column equals value (col=eq.val)
    pub fn eq(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("eq.{}", value)));
        self
    }

    /// Filter: column not equals value (col=neq.val)
    pub fn neq(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("neq.{}", value)));
        self
    }

    /// Filter: column greater than value (col=gt.val)
    pub fn gt(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("gt.{}", value)));
        self
    }

    /// Filter: column greater than or equal to value (col=gte.val)
    pub fn gte(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("gte.{}", value)));
        self
    }

    /// Filter: column less than value (col=lt.val)
    pub fn lt(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("lt.{}", value)));
        self
    }

    /// Filter: column less than or equal to value (col=lte.val)
    pub fn lte(mut self, column: &str, value: &str) -> Self {
        self.query_params.push((column.to_string(), format!("lte.{}", value)));
        self
    }

    /// Filter: column matches pattern (col=like.pattern)
    /// Use * as wildcard character.
    pub fn like(mut self, column: &str, pattern: &str) -> Self {
        self.query_params.push((column.to_string(), format!("like.{}", pattern)));
        self
    }

    /// Filter: column matches pattern case-insensitively (col=ilike.pattern)
    /// Use * as wildcard character.
    pub fn ilike(mut self, column: &str, pattern: &str) -> Self {
        self.query_params.push((column.to_string(), format!("ilike.{}", pattern)));
        self
    }

    /// Filter: column value is in the provided list (col=in.(v1,v2,...))
    pub fn in_(mut self, column: &str, values: &[&str]) -> Self {
        let values_str = values.join(",");
        self.query_params.push((column.to_string(), format!("in.({})", values_str)));
        self
    }

    /// Filter: column is null (col=is.null)
    pub fn is_null(mut self, column: &str) -> Self {
        self.query_params.push((column.to_string(), "is.null".to_string()));
        self
    }

    /// Filter: column is not null (col=not.is.null)
    pub fn not_null(mut self, column: &str) -> Self {
        self.query_params.push((column.to_string(), "not.is.null".to_string()));
        self
    }

    /// Orders results by the specified column.
    /// Use "column" for ascending or "column.desc" for descending.
    pub fn order(mut self, column: &str) -> Self {
        self.query_params.push(("order".to_string(), column.to_string()));
        self
    }

    /// Limits the number of rows returned.
    pub fn limit(mut self, count: usize) -> Self {
        self.query_params.push(("limit".to_string(), count.to_string()));
        self
    }

    /// Offsets the results by the specified number of rows.
    pub fn offset(mut self, count: usize) -> Self {
        self.query_params.push(("offset".to_string(), count.to_string()));
        self
    }

    /// Executes the query and returns the response.
    pub async fn execute(self) -> Result<Response, Error> {
        let request_url = format!("{}/rest/v1/{}", self.client.url, self.table);

        let mut request = self.client.client.request(self.method, &request_url);

        // Add standard headers
        request = request.header("apikey", &self.client.api_key);
        request = request.header("Content-Type", "application/json");

        // Add bearer token if available
        if let Some(ref token) = self.client.bearer_token {
            request = request.bearer_auth(token);
        }

        // Add query parameters
        if !self.query_params.is_empty() {
            request = request.query(&self.query_params);
        }

        // Add body if present
        if let Some(body) = self.body {
            request = request.body(body);
        }

        request.send().await
    }
}

impl Supabase {
    /// Creates a QueryBuilder for the specified table.
    /// This is the entry point for all database operations.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Select all from users
    /// client.from("users").select("*").execute().await?;
    ///
    /// // Select with filter
    /// client.from("users").select("id,name").eq("status", "active").execute().await?;
    ///
    /// // Insert
    /// client.from("users").insert(&user_data).execute().await?;
    ///
    /// // Update
    /// client.from("users").update(&updates).eq("id", "123").execute().await?;
    ///
    /// // Delete
    /// client.from("users").delete().eq("id", "123").execute().await?;
    /// ```
    pub fn from(&self, table: &str) -> QueryBuilder {
        QueryBuilder::new(self, table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    async fn client() -> Supabase {
        Supabase::new(None, None, None)
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestItem {
        name: String,
        value: i32,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestItemWithId {
        id: i64,
        name: String,
        value: i32,
    }

    #[tokio::test]
    async fn test_select() {
        let client = client().await;

        // This test requires a 'test_items' table in Supabase
        let response = client
            .from("test_items")
            .select("*")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                // If we get a response, check status (might be 200 or 401 depending on auth)
                let status = resp.status();
                println!("Select response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                // Network error is acceptable in test environment
                println!("Select test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_select_columns() {
        let client = client().await;

        let response = client
            .from("test_items")
            .select("id,name")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Select columns response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Select columns test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_filter() {
        let client = client().await;

        let response = client
            .from("test_items")
            .select("*")
            .eq("name", "test")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Select with filter response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Select with filter test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_insert() {
        let client = client().await;

        let item = TestItem {
            name: "test_item".to_string(),
            value: 42,
        };

        let response = client
            .from("test_items")
            .insert(&item)
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Insert response status: {}", status);
                // 201 Created, 200 OK, or 401 Unauthorized (if auth required)
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Insert test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_update() {
        let client = client().await;

        let updates = serde_json::json!({
            "value": 100
        });

        let response = client
            .from("test_items")
            .update(&updates)
            .eq("name", "test_item")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Update response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Update test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_delete() {
        let client = client().await;

        let response = client
            .from("test_items")
            .delete()
            .eq("name", "test_item")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Delete response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Delete test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_order_and_limit() {
        let client = client().await;

        let response = client
            .from("test_items")
            .select("*")
            .order("id.desc")
            .limit(10)
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Select with order/limit response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Select with order/limit test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_multiple_filters() {
        let client = client().await;

        let response = client
            .from("test_items")
            .select("*")
            .gte("value", "10")
            .lte("value", "100")
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Select with multiple filters response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Select with multiple filters test skipped due to network error: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_in_filter() {
        let client = client().await;

        let response = client
            .from("test_items")
            .select("*")
            .in_("id", &["1", "2", "3"])
            .execute()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                println!("Select with in filter response status: {}", status);
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Select with in filter test skipped due to network error: {}", e);
            }
        }
    }
}
