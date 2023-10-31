use crate::KoalaApi;
use reqwest::header::ACCEPT;
use reqwest::Result;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const TOKEN_ENDPOINT: &str = "/api/oauth/token";
const USERINFO_ENDPOINT: &str = "/oauth/userinfo";
const LOGIN_ENDPOINT: &str = "/api/oauth/authorize";
const LOGIN_SCOPES: &str = "member-read+openid+email+profile";

/// Koala OAuth2 API.
/// Can be acquired via [KoalaApi::oauth_api].
///
/// This API allows the user to authorize with Koala.
/// Generally, the OAuth2 Login flow is as follows:
/// 1. The user sends a request to your server (we'll call this the `App`).
/// 2. The user gets redirected to the URL returned by [KoalaOAuth::get_login_redirect_uri].
/// 3. The user logs in in Koala.
/// 4. Koala redirects the user back to the App. The query will contain the `code` parameter if everything went OK.
/// 5. The App exchanges the `code` for an access- and refresh token using [KoalaOAuth::exchange_login_code].
/// 6. The App can now make requests to Koala APIs or other APIs using Koala for authorization using the acquired access token.
/// 7. In case the access token has expired, it can be renewed using the refresh token and [KoalaOAuth::refresh_access_token].
#[derive(Clone, Debug)]
pub struct KoalaOAuth<'a> {
    koala: &'a KoalaApi,
    config: ClientConfig,
}

/// OAuth2 client configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientConfig {
    id: String,
    secret: String,
    redirect_uri: String,
}

impl ClientConfig {
    /// Create a new OAuth2 client configuration.
    pub fn new(id: String, secret: String, redirect_uri: String) -> Self {
        Self {
            id,
            secret,
            redirect_uri,
        }
    }
}

/// OAuth2 token information.
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    /// OAuth2 access token.
    pub access_token: String,
    /// OAuth2 refresh token.
    pub refresh_token: String,
    /// UNIX Epoch timestamp at which the `access_token` expires
    pub expires_at: i64,
    /// Email address of the user
    pub email: String,
}

/// Information about the user
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Koala user ID.
    pub koala_id: i32,
    /// Whether the user is an administrator in Koala.
    pub is_admin: bool,
    /// The full name of the user
    pub full_name: String,
}

impl<'a> KoalaOAuth<'a> {
    pub(crate) fn new(koala: &'a KoalaApi, config: ClientConfig) -> Self {
        Self { koala, config }
    }

    /// Get the URL where the user should be redirected to to login with Koala.
    pub fn get_login_redirect_uri(&self) -> String {
        let query = format!(
            "?client_id={}&redirect_uri={}&response_type=code&scope={}",
            self.config.id, self.config.redirect_uri, LOGIN_SCOPES
        );

        self.koala.get_url(&format!("{LOGIN_ENDPOINT}{query}"))
    }

    /// Exchange an authorization code for OAuth2 tokens.
    ///
    /// # Errors
    ///
    /// - If the request fails.
    /// - If the code is invalid.
    pub async fn exchange_login_code<S: AsRef<str>>(&self, code: S) -> Result<OAuthTokens> {
        let response: ExchangeResponse = self
            .koala
            .client
            .post(self.koala.get_url(TOKEN_ENDPOINT))
            .json(&ExchangeRequest::new_exchange_code(
                code.as_ref(),
                &self.config,
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(response.into())
    }

    /// Refresh an access token using a refresh token.
    ///
    /// # Errors
    ///
    /// - If the request fails.
    /// - If the refresh token is invalid.
    pub async fn refresh_access_token<S: AsRef<str>>(
        &self,
        refresh_token: S,
    ) -> Result<OAuthTokens> {
        let response: ExchangeResponse = self
            .koala
            .client
            .post(self.koala.get_url(TOKEN_ENDPOINT))
            .json(&ExchangeRequest::new_refresh_token(
                refresh_token.as_ref(),
                &self.config,
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(response.into())
    }

    /// Get information about the user.
    ///
    /// # Errors
    ///
    /// - If the request fails.
    /// - If the access token is invalid.
    pub async fn get_userinfo<S: AsRef<str>>(&self, access_token: S) -> Result<UserInfo> {
        let response: UserInfoResponse = self
            .koala
            .client
            .get(self.koala.get_url(USERINFO_ENDPOINT))
            .header(ACCEPT, "application/json")
            .bearer_auth(access_token.as_ref())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(response.into())
    }
}

#[derive(Debug, Serialize)]
struct ExchangeRequest<'a> {
    grant_type: GrantType,
    code: Option<&'a str>,
    client_id: &'a str,
    client_secret: &'a str,
    redirect_uri: &'a str,
    refresh_token: Option<&'a str>,
}

impl<'a> ExchangeRequest<'a> {
    pub fn new_exchange_code(code: &'a str, client: &'a ClientConfig) -> Self {
        Self {
            grant_type: GrantType::AuthorizationCode,
            code: Some(code),
            client_id: &client.id,
            client_secret: &client.secret,
            redirect_uri: &client.redirect_uri,
            refresh_token: None,
        }
    }

    pub fn new_refresh_token(refresh_token: &'a str, client: &'a ClientConfig) -> Self {
        Self {
            grant_type: GrantType::RefreshToken,
            code: None,
            client_id: &client.id,
            client_secret: &client.secret,
            redirect_uri: &client.redirect_uri,
            refresh_token: Some(refresh_token),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum GrantType {
    /// OAuth authorization_code flow
    AuthorizationCode,
    /// OAuth refresh_token flow
    #[allow(unused)]
    RefreshToken,
}

#[derive(Debug, Deserialize)]
struct ExchangeResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    email: String,
}

impl From<ExchangeResponse> for OAuthTokens {
    fn from(value: ExchangeResponse) -> Self {
        Self {
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            expires_at: OffsetDateTime::now_utc().unix_timestamp() + value.expires_in,
            email: value.email,
        }
    }
}

#[derive(Deserialize)]
struct UserInfoResponse {
    sub: String,
    is_admin: bool,
    full_name: String,
}

impl From<UserInfoResponse> for UserInfo {
    fn from(value: UserInfoResponse) -> Self {
        Self {
            // Unwrap is safe: Koala guarantees this
            koala_id: value.sub.parse::<i32>().unwrap(),
            is_admin: value.is_admin,
            full_name: value.full_name,
        }
    }
}
