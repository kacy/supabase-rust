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
- [ ] Signup phone/pass
- [x] Token refresh
- [x] Logout
- [ ] Verify one-time token
- [ ] Authorize external OAuth provicder
- [ ] Password recovery
- [ ] Resend one-time password over email or SMS
- [ ] Magic link authentication
- [ ] One-time password authentication
- [ ] Retrieval of user's information
- [ ] Reauthentication of a password change
- [ ] Enrollment of MFA
- [ ] MFA challenge and verify
- [ ] OAuth callback
- [ ] All SSO
- [ ] All Admin
- [ ] All Database support

### Quickstart
Add the following dependency to your toml file:
```
[dependencies]
supabase_rust = "0.1.0"
```

You can initialize the two configuration keys either inline in the intialization or via environment variables (`SUPABASE_API_KEY` and `SUPABASE_URL`).

## Tips
The Supabase team has an outline of their OpenAPI specs over in [this yaml file](https://github.com/supabase/gotrue/blob/master/openapi.yaml).

## License

Supabase-rust is available under the MIT license, see the [LICENSE](https://github.com/kacy/supabase-rust/blob/master/LICENSE) file for more information.