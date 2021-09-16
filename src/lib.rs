mod auth;
mod rand;
mod routes;
mod state;
mod utils;

use worker::*;
use worker_sys::Response as EdgeResponse;

pub(crate) const AUTH_COOKIE: &str = "AUTH0-AUTH";
pub(crate) const AUTH_KV: &str = "AUTH_STORE";
pub(crate) const STATE_KEY_PREFIX: &str = "state/";

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new(());

    router
        .get_async("/login", routes::handle_login)
        .get_async("/whoami", routes::whoami)
        .get_async("/", routes::handle)
        .run(req, env)
        .await
}
