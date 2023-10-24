use crate::oauth::{ClientConfig, KoalaOAuth};
use reqwest::Client;

pub mod oauth;

/// The Koala API.
pub struct KoalaApi {
    client: Client,
    host: String,
}

impl KoalaApi {
    /// Create a new Koala client.
    ///
    /// # Errors
    ///
    /// If creating a [reqwest::Client] fails.
    pub fn new(host: String) -> reqwest::Result<Self> {
        Ok(Self {
            client: Client::builder().build()?,
            host,
        })
    }

    /// Create a new Koala client using a specific `User-Agent`.
    ///
    /// # Errors
    ///
    /// If creating a [reqwest::Client] fails.
    pub fn new_with_user_agent(host: String, user_agent: &str) -> reqwest::Result<Self> {
        Ok(Self {
            client: Client::builder().user_agent(user_agent).build()?,
            host,
        })
    }

    fn get_url(&self, path: &str) -> String {
        format!("{}{path}", self.host)
    }

    /// Access Koala's OAuth2 API
    pub fn oauth_api(&self, oauth_client: ClientConfig) -> KoalaOAuth<'_> {
        KoalaOAuth::new(&self, oauth_client)
    }
}
