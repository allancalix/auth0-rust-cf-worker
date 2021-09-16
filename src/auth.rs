use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use worker::RouteContext;

use crate::routes::Error;

// Keys for Auth0 related secrets.
const DOMAIN: &str = "AUTH0_DOMAIN";
const CLIENT_ID: &str = "AUTH0_CLIENT_ID";
const CLIENT_SECRET: &str = "AUTH0_CLIENT_SECRET";

pub struct Auth0 {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    client: reqwest::Client,
}

impl<D> TryFrom<&RouteContext<D>> for Auth0 {
    type Error = worker::Error;

    fn try_from(ctx: &RouteContext<D>) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ctx.secret(DOMAIN)?.to_string(),
            ctx.secret(CLIENT_ID)?.to_string(),
            ctx.secret(CLIENT_SECRET)?.to_string()))
    }
}

impl Auth0 {
    pub fn new(domain: impl Into<String>, client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let http_client = reqwest::Client::new();

        Self {
            client: http_client,
            domain: domain.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }

    pub async fn get_user(&self, access_token: &str) -> Result<UserInfo, crate::routes::Error> {
            Ok(reqwest::Client::new()
                .get(format!(
                    "{}/userinfo",
                    &self.domain,
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", access_token),
                )
                .send()
                .await?
                .json()
                .await?)
    }

    pub async fn get_oauth_token(&self, req: &UserFetchRequest) -> Result<UserFetchResponse, crate::routes::Error> {
        let req = UserFetchRequest {
            client_id: Some(self.client_id.clone()),
            client_secret: Some(self.client_secret.clone()),
            grant_type: req.grant_type.to_string(),
            code: req.code.to_string(),
            redirect_uri: req.redirect_uri.to_string(),
        };

        let resp = self.client
            .post(format!(
                    "{}/oauth/token",
                    &self.domain,
            ))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&req)?)
            .send()
            .await
            .map_err(crate::routes::Error::from)?;

        if resp.status() != 200 {
            let body = resp.text().await.map_err(Error::from)?;
            worker::console_log!("Error claiming user token: {}.", body);
            return Err(Error::Unknown);
        }

        Ok(resp.json().await.map_err(Error::from)?)
    }

    pub fn authorize_url(&self, state: &str, callback_url: &str) -> String {
        format!("{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}",
            &self.domain,
            &self.client_id,
            callback_url,
            state)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserFetchRequestInternal {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserFetchRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserFetchResponse {
    pub access_token: String,
    pub id_token: String,
    pub scope: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub nickname: String,
    pub name: String,
    pub picture: String,
    pub updated_at: String,
}
