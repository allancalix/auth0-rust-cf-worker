use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub nbf: Option<usize>,
    pub sub: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LoginState {
    /// Specifies where to send users after a successful login, should be a full
    /// url (i.e. with scheme, domain, and path). Can be specified by user by
    /// initiating the process with the "on_login" query parameter set to the
    /// destination.
    pub on_login: String,
}
