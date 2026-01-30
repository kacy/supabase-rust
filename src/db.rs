use reqwest::{Method, Response};
use serde::{de::DeserializeOwned, Serialize};

use crate::Supabase;

/// Query builder for PostgREST database operations.
///
/// Provides a fluent API for constructing and executing database queries.
///
/// Use [`execute()`](Self::execute) to get the raw response, or
/// [`execute_and_parse()`](Self::execute_and_parse) to deserialize the JSON body.
#[must_use = "a QueryBuilder does nothing until .execute() or .execute_and_parse() is called"]
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
    pub fn insert<T: Serialize>(mut self, data: &T) -> Result<Self, crate::Error> {
        self.method = Method::POST;
        self.body = Some(serde_json::to_string(data)?);
        Ok(self)
    }

    /// Prepares an update operation with the provided data.
    ///
    /// Should be combined with filter methods to target specific rows.
    pub fn update<T: Serialize>(mut self, data: &T) -> Result<Self, crate::Error> {
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

    /// Executes the query and returns the raw response.
    ///
    /// Returns `Error::Api` if the server responds with a non-2xx status code.
    pub async fn execute(self) -> Result<Response, crate::Error> {
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

        let resp = request.send().await?;

        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let message = resp.text().await.unwrap_or_default();
            return Err(crate::Error::Api { status, message });
        }

        Ok(resp)
    }

    /// Executes the query and deserializes the JSON response body into `T`.
    ///
    /// This is a convenience wrapper around [`execute()`](Self::execute) that
    /// also parses the response body.
    pub async fn execute_and_parse<T: DeserializeOwned>(self) -> Result<T, crate::Error> {
        let resp = self.execute().await?;
        let body = resp.text().await?;
        let parsed: T = serde_json::from_str(&body)?;
        Ok(parsed)
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
        Supabase::new(None, None, None).unwrap_or_else(|_| {
            Supabase::new(
                Some("https://example.supabase.co"),
                Some("test-key"),
                None,
            )
            .unwrap()
        })
    }

    /// Helper: returns true if the error is acceptable for tests running without
    /// a real Supabase backend (network errors or 401 API errors).
    fn is_acceptable_error(err: &crate::Error) -> bool {
        matches!(
            err,
            crate::Error::Request(_) | crate::Error::Api { status: 401, .. }
        )
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestItem {
        name: String,
        value: i32,
    }

    #[tokio::test]
    async fn test_select() {
        let client = client();

        match client.from("test_items").select("*").execute().await {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_select_columns() {
        let client = client();

        match client.from("test_items").select("id,name").execute().await {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_select_with_filter() {
        let client = client();

        match client
            .from("test_items")
            .select("*")
            .eq("name", "test")
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_insert() {
        let client = client();

        let item = TestItem {
            name: "test_item".into(),
            value: 42,
        };

        match client
            .from("test_items")
            .insert(&item)
            .expect("serialization should succeed")
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_update() {
        let client = client();

        let updates = serde_json::json!({ "value": 100 });

        match client
            .from("test_items")
            .update(&updates)
            .expect("serialization should succeed")
            .eq("name", "test_item")
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_delete() {
        let client = client();

        match client
            .from("test_items")
            .delete()
            .eq("name", "test_item")
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_select_with_order_and_limit() {
        let client = client();

        match client
            .from("test_items")
            .select("*")
            .order("id.desc")
            .limit(10)
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_select_with_multiple_filters() {
        let client = client();

        match client
            .from("test_items")
            .select("*")
            .gte("value", "10")
            .lte("value", "100")
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_in_filter() {
        let client = client();

        match client
            .from("test_items")
            .select("*")
            .in_("id", ["1", "2", "3"])
            .execute()
            .await
        {
            Ok(_resp) => {}
            Err(e) if is_acceptable_error(&e) => {
                println!("Test skipped: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = crate::Error::Api {
            status: 400,
            message: "bad request".into(),
        };
        assert!(format!("{err}").contains("400"));
    }
}
