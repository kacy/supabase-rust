# 🦀 Supabase-rust

`supabase-rust` is a light [Rust](https://www.rust-lang.org/) wrapper around the [Supabase](https://supabase.com/) REST API.

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/supabase-rust.svg
[crates-url]: https://crates.io/crates/supabase-rust
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/kacy/supabase-rust/blob/master/LICENSE
[actions-badge]: https://github.com/kacy/supabase-rust/workflows/Rust/badge.svg
[actions-url]: https://github.com/kacy/supabase-rust/actions?query=workflow%3ARust+branch%3Amaster

## Features

- [x] Client creation with validation
- [x] Unified error type (`supabase_rust::Error`)
- [x] Sign-in email/pass (returns typed `AuthResponse`)
- [x] Signup email/pass
- [x] Signup phone/pass
- [x] Token refresh
- [x] Logout
- [x] Verify one-time token
- [ ] Authorize external OAuth provider
- [x] Password recovery
- [x] Resend one-time password over email or SMS
- [ ] Magic link authentication
- [x] One-time password authentication
- [ ] Retrieval of user's information
- [ ] Reauthentication of a password change
- [ ] Enrollment of MFA
- [ ] MFA challenge and verify
- [ ] OAuth callback
- [ ] All SSO
- [ ] All Admin
- [x] Database support (CRUD operations with fluent query builder)

## Quickstart

Add the following dependency to your `Cargo.toml`:
```toml
[dependencies]
supabase-rust = "0.3"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Client Initialization

You can initialize the client with explicit values or via environment variables.
`Supabase::new()` returns a `Result` and will return an error if the URL or API
key is missing.

```rust
use supabase_rust::Supabase;

// Option 1: Using environment variables
// Set SUPABASE_URL, SUPABASE_API_KEY, and optionally SUPABASE_JWT_SECRET
let client = Supabase::new(None, None, None)?;

// Option 2: Explicit configuration
let client = Supabase::new(
    Some("https://your-project.supabase.co"),
    Some("your-api-key"),
    Some("your-jwt-secret"),
)?;
```

## Usage

### Authentication

Auth methods return typed responses: `AuthResponse` (with `access_token`,
`refresh_token`, etc.) or `EmptyResponse` (with `status`). Non-2xx responses
are automatically converted to `Error::Api`.

```rust
use supabase_rust::{Supabase, AuthResponse, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Supabase::new(None, None, None)?;

    // Sign up a new user
    let auth: AuthResponse = client
        .signup_email_password("user@example.com", "password123")
        .await?;

    // Sign in with email and password
    let auth: AuthResponse = client
        .sign_in_password("user@example.com", "password123")
        .await?;

    // Access tokens directly from the typed response
    println!("Access token: {}", auth.access_token);
    println!("Refresh token: {}", auth.refresh_token);

    // Refresh an access token
    let refreshed: AuthResponse = client.refresh_token(&auth.refresh_token).await?;

    // Validate a JWT token (synchronous)
    let claims = client.jwt_valid(&auth.access_token)?;
    println!("User email: {}", claims.email);

    // Logout (requires a bearer token)
    let mut client = client;
    client.set_bearer_token(&auth.access_token);
    let resp = client.logout().await?;
    println!("Logged out with status: {}", resp.status);

    Ok(())
}
```

### Database Operations

The library provides a fluent query builder for PostgREST database operations.
The `QueryBuilder` is annotated with `#[must_use]` so the compiler will warn if
you forget to call `.execute()`.

```rust
use supabase_rust::{Supabase, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i64,
    name: String,
    email: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct NewUser {
    name: String,
    email: String,
    status: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let client = Supabase::new(None, None, None)?;

    // SELECT: Get all users (automatic JSON deserialization)
    let users: Vec<User> = client
        .from("users")
        .select("*")
        .execute_and_parse()
        .await?;

    // SELECT: Get specific columns with filters
    let response = client
        .from("users")
        .select("id,name,email")
        .eq("status", "active")
        .order("name")
        .limit(10)
        .execute()
        .await?;

    // INSERT: Create a new record
    let new_user = NewUser {
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
        status: "active".to_string(),
    };
    let response = client
        .from("users")
        .insert(&new_user)?
        .execute()
        .await?;

    // UPDATE: Modify existing records
    let updates = serde_json::json!({
        "status": "inactive"
    });
    let response = client
        .from("users")
        .update(&updates)?
        .eq("id", "123")
        .execute()
        .await?;

    // DELETE: Remove records
    let response = client
        .from("users")
        .delete()
        .eq("id", "123")
        .execute()
        .await?;

    Ok(())
}
```

### Available Filter Methods

| Method | Description | PostgREST Equivalent |
|--------|-------------|---------------------|
| `eq(col, val)` | Equal | `col=eq.val` |
| `neq(col, val)` | Not equal | `col=neq.val` |
| `gt(col, val)` | Greater than | `col=gt.val` |
| `gte(col, val)` | Greater than or equal | `col=gte.val` |
| `lt(col, val)` | Less than | `col=lt.val` |
| `lte(col, val)` | Less than or equal | `col=lte.val` |
| `like(col, pattern)` | Pattern match (use `*` as wildcard) | `col=like.pattern` |
| `ilike(col, pattern)` | Case-insensitive pattern match | `col=ilike.pattern` |
| `in_(col, &[vals])` | Value in list | `col=in.(v1,v2,v3)` |
| `is_null(col)` | Is null | `col=is.null` |
| `not_null(col)` | Is not null | `col=not.is.null` |

### Query Modifiers

| Method | Description |
|--------|-------------|
| `order(col)` | Order by column (use `col.desc` for descending) |
| `limit(n)` | Limit number of rows |
| `offset(n)` | Skip first n rows |

### Combining Filters

Filters can be chained to create complex queries:

```rust
let response = client
    .from("products")
    .select("id,name,price,category")
    .gte("price", "10")
    .lte("price", "100")
    .neq("status", "discontinued")
    .in_("category", ["electronics", "accessories"])
    .order("price.desc")
    .limit(20)
    .execute()
    .await?;
```

## Error Handling

All operations return `Result<T, supabase_rust::Error>`. The error type has the
following variants:

| Variant | Description |
|---------|-------------|
| `Error::Config(String)` | Missing URL or API key at construction |
| `Error::Request(reqwest::Error)` | HTTP transport failure |
| `Error::Serialization(serde_json::Error)` | JSON serialization/deserialization failure |
| `Error::Jwt(jsonwebtoken::errors::Error)` | JWT validation failure |
| `Error::AuthRequired(String)` | Operation requires a bearer token |
| `Error::Api { status, message }` | Non-2xx HTTP response from Supabase |

## Tips
The Supabase team has an outline of their OpenAPI specs over in [this yaml file](https://github.com/supabase/gotrue/blob/master/openapi.yaml).

## License

Supabase-rust is available under the MIT license, see the [LICENSE](https://github.com/kacy/supabase-rust/blob/master/LICENSE) file for more information.
