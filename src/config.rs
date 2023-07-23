use serde::Deserialize;
use crate::Supabase;

#[derive(Debug, Clone, Deserialize)]
pub struct SupabaseConfig {
    pub supabase_url: String,
    pub supabase_jwt_secret: String,
    pub supabase_api_key: String,
    pub supabase_url_database: String,
}

impl SupabaseConfig {
    pub fn supabase(&self) -> Supabase {
        Supabase::new(
            Some(&self.supabase_url),
            Some(&self.supabase_api_key),
            Some(&self.supabase_jwt_secret),
        )
    }
}

impl Default for SupabaseConfig {
    fn default() -> Self {
        envy::from_env::<SupabaseConfig>().unwrap()
    }
}
