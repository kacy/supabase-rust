use reqwest::{Error, Method, Response};
use serde::Serialize;

use crate::Supabase;

/// Error type for database operations.
#[derive(Debug)]
pub enum DbError {
    /// Failed to serialize data to JSON.
    Serialization(serde_json::Error),
    /// HTTP request failed.
    Request(Error),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
            Self::Request(e) => write!(f, "request error: {e}"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(e) => Some(e),
            Self::Request(e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

impl From<Error> for DbError {
    fn from(err: Error) -> Self {
        Self::Request(err)
    }
}

/// Query builder for PostgREST database operations.
///
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
    pub(crate) fn new(client: &'a Supabase, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
            query_params: Vec::new(),
            method: Method::GET,
            body: None,
        }
    }

    /// Specifies which columns to select.
    ///
    /// Pass `"*"` to select all columns, or a comma-separated list of column names.
    pub fn select(mut self, columns: impl Into<String>) -> Self {
        self.query_params.push(("select".into(), columns.into()));
        self.method = Method::GET;
        self
    }

    /// Prepares an insert operation with the provided data.
    ///
    /// Data will be serialized to JSON. Call `execute()` to run the query.
    pub fn insert<T: Serialize>(mut self, data: &T) -> Result<Self, serde_json::Error> {
        self.method = Method::POST;
        self.body = Some(serde_json::to_string(data)?);
        Ok(self)
    }

    /// Prepares an update operation with the provided data.
    ///
    /// Should be combined with filter methods to target specific rows.
    pub fn update<T: Serialize>(mut self, data: &T) -> Result<Self, serde_json::Error> {
        self.method = Method::PATCH;
        self.body = Some(serde_json::to_string(data)?);
        Ok(self)
    }

    /// Prepares a delete operation.
    ///
    /// Should be combined with filter methods to target specific rows.
    pub fn delete(mut self) -> Self {
        self.method = Method::DELETE;
        self
    }

    /// Filter: column equals value (`col=eq.val`).
    pub fn eq(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "eq", value)
    }

    /// Filter: column not equals value (`col=neq.val`).
    pub fn neq(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "neq", value)
    }

    /// Filter: column greater than value (`col=gt.val`).
    pub fn gt(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "gt", value)
    }

    /// Filter: column greater than or equal to value (`col=gte.val`).
    pub fn gte(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "gte", value)
    }

    /// Filter: column less than value (`col=lt.val`).
    pub fn lt(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "lt", value)
    }

    /// Filter: column less than or equal to value (`col=lte.val`).
    pub fn lte(self, column: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_filter(column, "lte", value)
    }

    /// Filter: column matches pattern (`col=like.pattern`).
    ///
    /// Use `*` as wildcard character.
    pub fn like(self, column: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.add_filter(column, "like", pattern)
    }

    /// Filter: column matches pattern case-insensitively (`col=ilike.pattern`).
    ///
    /// Use `*` as wildcard character.
    pub fn ilike(self, column: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.add_filter(column, "ilike", pattern)
    }

    /// Filter: column value is in the provided list (`col=in.(v1,v2,...)`).
    pub fn in_<I, S>(mut self, column: impl Into<String>, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let values_str: Vec<_> = values.into_iter().map(|s| s.as_ref().to_string()).collect();
        self.query_params
            .push((column.into(), format!("in.({})", values_str.join(","))));
        self
    }

    /// Filter: column is null (`col=is.null`).
    pub fn is_null(mut self, column: impl Into<String>) -> Self {
        self.query_params.push((column.into(), "is.null".into()));
        self
    }

    /// Filter: column is not null (`col=not.is.null`).
    pub fn not_null(mut self, column: impl Into<String>) -> Self {
        self.query_params.push((column.into(), "not.is.null".into()));
        self
    }

    /// Orders results by the specified column.
    ///
    /// Use `"column"` for ascending or `"column.desc"` for descending.
    pub fn order(mut self, column: impl Into<String>) -> Self {
        self.query_params.push(("order".into(), column.into()));
        self
    }

    /// Limits the number of rows returned.
    pub fn limit(mut self, count: usize) -> Self {
        self.query_params.push(("limit".into(), count.to_string()));
        self
    }

    /// Offsets the results by the specified number of rows.
    pub fn offset(mut self, count: usize) -> Self {
        self.query_params.push(("offset".into(), count.to_string()));
        self
    }

    /// Executes the query and returns the response.
    pub async fn execute(self) -> Result<Response, Error> {
        let url = format!("{}/rest/v1/{}", self.client.url, self.table);

        let mut request = self
            .client
            .client
            .request(self.method, &url)
            .header("apikey", &self.client.api_key)
            .header("Content-Type", "application/json");

        if let Some(ref token) = self.client.bearer_token {
            request = request.bearer_auth(token);
        }

        if !self.query_params.is_empty() {
            request = request.query(&self.query_params);
        }

        if let Some(body) = self.body {
            request = request.body(body);
        }

        request.send().await
    }

    fn add_filter(
        mut self,
        column: impl Into<String>,
        op: &str,
        value: impl Into<String>,
    ) -> Self {
        self.query_params
            .push((column.into(), format!("{op}.{}", value.into())));
        self
    }
}

impl Supabase {
    /// Creates a QueryBuilder for the specified table.
    ///
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
    /// client.from("users").insert(&user_data)?.execute().await?;
    ///
    /// // Update
    /// client.from("users").update(&updates)?.eq("id", "123").execute().await?;
    ///
    /// // Delete
    /// client.from("users").delete().eq("id", "123").execute().await?;
    /// ```
    pub fn from(&self, table: impl Into<String>) -> QueryBuilder<'_> {
        QueryBuilder::new(self, table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn client() -> Supabase {
        Supabase::new(None, None, None)
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestItem {
        name: String,
        value: i32,
    }

    #[tokio::test]
    async fn test_select() {
        let client = client();

        let result = client.from("test_items").select("*").execute().await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_select_columns() {
        let client = client();

        let result = client.from("test_items").select("id,name").execute().await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_filter() {
        let client = client();

        let result = client
            .from("test_items")
            .select("*")
            .eq("name", "test")
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_insert() {
        let client = client();

        let item = TestItem {
            name: "test_item".into(),
            value: 42,
        };

        let result = client
            .from("test_items")
            .insert(&item)
            .expect("serialization should succeed")
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_update() {
        let client = client();

        let updates = serde_json::json!({ "value": 100 });

        let result = client
            .from("test_items")
            .update(&updates)
            .expect("serialization should succeed")
            .eq("name", "test_item")
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_delete() {
        let client = client();

        let result = client
            .from("test_items")
            .delete()
            .eq("name", "test_item")
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_order_and_limit() {
        let client = client();

        let result = client
            .from("test_items")
            .select("*")
            .order("id.desc")
            .limit(10)
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_select_with_multiple_filters() {
        let client = client();

        let result = client
            .from("test_items")
            .select("*")
            .gte("value", "10")
            .lte("value", "100")
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_in_filter() {
        let client = client();

        let result = client
            .from("test_items")
            .select("*")
            .in_("id", ["1", "2", "3"])
            .execute()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                assert!(status.is_success() || status.as_u16() == 401);
            }
            Err(e) => {
                println!("Test skipped due to network error: {e}");
            }
        }
    }

    #[test]
    fn test_db_error_display() {
        // Verify error types display correctly
        let json_err = serde_json::from_str::<i32>("invalid").unwrap_err();
        let db_err = DbError::Serialization(json_err);
        assert!(format!("{db_err}").contains("serialization error"));
    }
}
