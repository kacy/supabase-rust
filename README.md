# 🦀 Supabase-rust

`supabase-rust` is a light [Rust](https://www.rust-lang.org/) wrapper around the [Supabase](https://supabase.com/) REST API.

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/supabase-rust.svg
[crates-url]: https://crates.io/crates/supabase-rust
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/kacy/supabase-rust/blob/master/LICENSE
[actions-badge]: https://github.com/kacy/supabase-rust/workflows/CI/badge.svg
[actions-url]: https://github.com/kacy/supabase-rust/actions?query=workflow%3ACI+branch%3Amaster

## Features

- [x] Client creation
- [x] Sign-in email/pass
- [x] Signup email/pass
- [x] Signup phone/pass
- [x] Token refresh
- [x] Logout
- [x] Verify one-time token
- [ ] Authorize external OAuth provicder
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
supabase-rust = "0.1.2"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Client Initialization

You can initialize the client with explicit values or via environment variables:

```rust
use supabase_rust::Supabase;

// Option 1: Using environment variables
// Set SUPABASE_URL, SUPABASE_API_KEY, and optionally SUPABASE_JWT_SECRET
let client = Supabase::new(None, None, None);

// Option 2: Explicit configuration
let client = Supabase::new(
    Some("https://your-project.supabase.co"),
    Some("your-api-key"),
    Some("your-jwt-secret"),
);
```

## Usage

### Authentication

```rust
use supabase_rust::Supabase;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Supabase::new(None, None, None);

    // Sign up a new user
    let response = client
        .signup_email_password("user@example.com", "password123")
        .await?;

    // Sign in with email and password
    let response = client
        .sign_in_password("user@example.com", "password123")
        .await?;

    // Parse the response to get tokens
    let json: serde_json::Value = response.json().await?;
    let access_token = json["access_token"].as_str().unwrap();
    let refresh_token = json["refresh_token"].as_str().unwrap();

    // Refresh an access token
    let response = client.refresh_token(refresh_token).await?;

    // Validate a JWT token
    let claims = client.jwt_valid(access_token).await?;
    println!("User email: {}", claims.email);

    Ok(())
}
```

### Database Operations

The library provides a fluent query builder for PostgREST database operations:

```rust
use supabase_rust::Supabase;
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Supabase::new(None, None, None);

    // SELECT: Get all users
    let response = client
        .from("users")
        .select("*")
        .execute()
        .await?;
    let users: Vec<User> = response.json().await?;

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
        .insert(&new_user)
        .execute()
        .await?;

    // UPDATE: Modify existing records
    let updates = serde_json::json!({
        "status": "inactive"
    });
    let response = client
        .from("users")
        .update(&updates)
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
    .in_("category", &["electronics", "accessories"])
    .order("price.desc")
    .limit(20)
    .execute()
    .await?;
```

## Tips
The Supabase team has an outline of their OpenAPI specs over in [this yaml file](https://github.com/supabase/gotrue/blob/master/openapi.yaml).

## License

Supabase-rust is available under the MIT license, see the [LICENSE](https://github.com/kacy/supabase-rust/blob/master/LICENSE) file for more information.