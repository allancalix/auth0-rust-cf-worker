use std::collections::HashMap;
use std::convert::TryFrom;

use cookie::Cookie;
use jsonwebtoken as jwt;
use sha2::{Digest, Sha256};
use worker::{Headers, Request, Response, RouteContext};

use crate::auth;
use crate::state::*;
use crate::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    JWT(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error("unknown error occurred")]
    Unknown,
}

impl From<Error> for worker::Error {
    fn from(err: Error) -> Self {
        worker::Error::RustError(format!("unexpected error: {}", err))
    }
}

pub async fn handle_login<T>(req: Request, ctx: RouteContext<T>) -> worker::Result<Response> {
    let query_params: HashMap<String, String> = req.url()?.query_pairs().into_owned().collect();

    let state: LoginState = match query_params.get("state") {
        Some(state) => {
            let state_key = format!("{}{}", STATE_KEY_PREFIX, state);

            let login_state = ctx.kv(AUTH_KV)?.get(&state_key).await?;
            match login_state {
                Some(state) => state.as_json()?,
                None => {
                    return Response::error("status token is invalid", 400);
                }
            }
        }
        None => return Response::error("no status token provided", 400),
    };

    match query_params.get("code") {
        Some(code) => {
            let domain = ctx.var("HOST_DOMAIN")?;
            let auth_client = auth::Auth0::try_from(&ctx)?;

            let request = auth::UserFetchRequest {
                code: code.clone(),
                grant_type: "authorization_code".into(),
                redirect_uri: format!("{}/login", domain.to_string()),
                client_id: None,
                client_secret: None,
            };
            let resp: auth::UserFetchResponse
                = auth_client.get_oauth_token(&request).await?;

            let key = key_from_userid(&ctx, &resp.id_token)?;
            ctx.kv(AUTH_KV)?
                .put(&key, serde_json::to_string(&resp)?)?
                .execute()
                .await?;

            let cookie_ns = ctx.var("COOKIE_DOMAIN")?;
            let mut headers = Headers::new();
            // TODO(allancalix): Add expiration time.
            let auth_cookie = cookie::CookieBuilder::new(AUTH_COOKIE, key)
                .domain(cookie_ns.to_string())
                .secure(true)
                .http_only(true)
                .same_site(cookie::SameSite::Lax)
                .finish();
            headers.append("Set-cookie", &auth_cookie.to_string())?;
            // IMPORTANT: Explicitly setting this header is used here in lieu of
            // a redirect response type. The worker crate Response type
            // does not expose a redirect type and the method we used
            // with EdgeResponse does not play well in combination with
            // setting headers (which we need to do to set the auth
            // cookie.
            headers.append("Location", &state.on_login)?;

            return Response::empty().map(|r| r.with_headers(headers).with_status(302));
        }
        None => return Response::error("no public code provided", 400),
    }
}

pub async fn handle<T>(req: Request, ctx: RouteContext<T>) -> worker::Result<Response> {
    let header = req.headers().get("Cookie")?.unwrap_or_else(String::new);
    let jar = parse_cookie_header(&header);

    let domain = ctx.var("HOST_DOMAIN")?;
    let query_params: HashMap<String, String> = req.url()?.query_pairs().into_owned().collect();
    let on_login = query_params
        .get("on_login")
        .map(|v| v.to_string())
        .unwrap_or(format!("{}/whoami", domain.to_string()));

    if let Some(auth_cookie) = jar.get(AUTH_COOKIE) {
        if let Some(user_auth) = ctx.kv(AUTH_KV)?.get(auth_cookie.value()).await? {
            let user_auth: auth::UserFetchResponse = user_auth.as_json()?;

            if ctx.kv(AUTH_KV)?.get(&format!("{}{}", "users/", user_auth.access_token)).await?.is_some() {
                return Ok(Response::from(EdgeResponse::redirect(
                            &on_login,
                )?));
            }

            let auth_client = auth::Auth0::try_from(&ctx)?;
            let resp = auth_client.get_user(&user_auth.access_token).await?;

            ctx.kv(AUTH_KV)?
                .put(
                    &format!("{}{}", "users/", user_auth.access_token),
                    serde_json::to_string(&resp)?,
                )?
                .expiration_ttl(86400)
                .execute()
                .await?;

            return Ok(Response::from(EdgeResponse::redirect(
                        &on_login,
            )?));
        }
    }

    let auth_client = auth::Auth0::try_from(&ctx)?;
    let login_state = LoginState {
        on_login: on_login.into(),
    };
    // TODO(allancalix): It looks like some characters don't survive being
    // encoded for the url. The pre-encoded string vs the post-decoded string
    // are different, replacing '+' characters with spaces. I should probably
    // replace the extra HTTP hop generating these state tokens with a library
    // implementation anyway.
    let state = rand::generate_state_param().await.replace("+", "M");
    ctx.kv(AUTH_KV)?
        .put(
            &format!("{}{}", STATE_KEY_PREFIX, state),
            serde_json::to_string(&login_state)?,
        )?
        .expiration_ttl(86400)
        .execute()
        .await?;
    Ok(Response::from(EdgeResponse::redirect(
        &auth_client.authorize_url(&state, &format!("{}/login", &domain.to_string())),
    )?))
}

pub async fn whoami<T>(req: Request, ctx: RouteContext<T>) -> worker::Result<Response> {
    let header = req.headers().get("Cookie")?.unwrap_or_else(String::new);
    let jar = parse_cookie_header(&header);

    if let Some(auth_cookie) = jar.get(AUTH_COOKIE) {
        if let Some(user_auth) = ctx.kv(AUTH_KV)?.get(auth_cookie.value()).await? {
            let user_auth: auth::UserFetchResponse = user_auth.as_json()?;

            if let Some(user) = ctx.kv(AUTH_KV)?.get(&format!("{}{}", "users/", user_auth.access_token)).await? {
                let user_info: auth::UserInfo = user.as_json()?;
                return Response::from_json(&user_info);
            }

            let auth_client = auth::Auth0::try_from(&ctx)?;
            let resp = auth_client.get_user(&user_auth.access_token).await?;
            ctx.kv(AUTH_KV)?
                .put(
                    &format!("{}{}", "users/", user_auth.access_token),
                    serde_json::to_string(&resp)?,
                )?
                .expiration_ttl(86400)
                .execute()
                .await?;

            return Response::from_json(&resp);
        }
    }

    Response::error("", 401)
}

fn key_from_userid<D>(ctx: &RouteContext<D>, token: &str) -> Result<String> {
    let token: jwt::TokenData<Claims> =
        jwt::dangerous_insecure_decode(token).map_err(Error::from)?;
    let mut hasher = Sha256::new();
    let salt = ctx.secret("AUTH_SALT")?.to_string();
    hasher.update(&format!("{}-{}", salt, token.claims.sub));
    let result = hasher.finalize();

    Ok(base64::encode(result.as_slice()))
}

fn parse_cookie_header(header: &str) -> HashMap<String, Cookie> {
    header
        .split(';')
        .map(|c| cookie::Cookie::parse(c.trim()))
        .filter_map(|c| c.ok())
        .map(|c| (c.name().into(), c))
        .collect()
}
