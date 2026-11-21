//! Local control API (127.0.0.1 only) consumed by the Electron desktop UI.
//!
//! Hardening: loopback bind, random bearer token stored in the user's
//! profile, constant-time token comparison, Host-header allowlist
//! (defeats DNS rebinding) and rejection of browser-originated requests
//! (any `Origin` header) so websites cannot drive the VPN.

use crate::engine::Engine;
use crate::store::Settings;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub token: Arc<String>,
    pub port: u16,
}

fn ct_eq(a: &str, b: &str) -> bool {
    // Compare digests so timing does not leak the token prefix.
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}

pub fn authorized(headers: &HeaderMap, token: &str, port: u16) -> Result<(), StatusCode> {
    if headers.contains_key("origin") {
        return Err(StatusCode::FORBIDDEN);
    }
    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        return Err(StatusCode::FORBIDDEN);
    }
    let auth = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
    match auth.strip_prefix("Bearer ") {
        Some(t) if ct_eq(t, token) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match authorized(req.headers(), &s.token, s.port) {
        Ok(()) => next.run(req).await,
        Err(code) => (code, Json(json!({"error": "unauthorized"}))).into_response(),
    }
}

fn err(e: anyhow::Error) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response()
}

async fn status(State(s): State<AppState>) -> Response {
    Json(s.engine.status()).into_response()
}

async fn servers(State(s): State<AppState>) -> Response {
    match s.engine.servers().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct LoginReq {
    api_url: String,
    email: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

async fn login(State(s): State<AppState>, Json(r): Json<LoginReq>) -> Response {
    match s.engine.login(&r.api_url, &r.email, &r.password, r.totp_code.as_deref()).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize, Default)]
struct ConnectReq {
    #[serde(default)]
    server_id: Option<String>,
}

async fn connect(State(s): State<AppState>, body: Option<Json<ConnectReq>>) -> Response {
    let r = body.map(|b| b.0).unwrap_or_default();
    match s.engine.connect(r.server_id).await {
        Ok(name) => Json(json!({"ok": true, "server": name})).into_response(),
        Err(e) => err(e),
    }
}

async fn disconnect(State(s): State<AppState>) -> Response {
    match s.engine.disconnect().await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

async fn logout(State(s): State<AppState>) -> Response {
    match s.engine.logout().await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(e),
    }
}

async fn put_settings(State(s): State<AppState>, Json(v): Json<Settings>) -> Response {
    match s.engine.update_settings(v) {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(e),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/servers", get(servers))
        .route("/v1/login", post(login))
        .route("/v1/logout", post(logout))
        .route("/v1/connect", post(connect))
        .route("/v1/disconnect", post(disconnect))
        .route("/v1/settings", post(put_settings))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

pub async fn serve(engine: Arc<Engine>, port: u16) -> anyhow::Result<()> {
    let token = engine.store.api_token()?;
    let state = AppState { engine: engine.clone(), token: Arc::new(token), port };
    // Auto-connect at service start (Forti "always up" / Proton auto-connect).
    if engine.store.load().settings.auto_connect && engine.store.load().access_token.is_some() {
        if let Err(e) = engine.connect(None).await {
            tracing::warn!(error = %e, "auto-connect failed");
        }
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!(port, "local API listening on 127.0.0.1");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn auth_rules() {
        let ok = h(&[("host", "127.0.0.1:47800"), ("authorization", "Bearer abc")]);
        assert!(authorized(&ok, "abc", 47800).is_ok());
        let wrong = h(&[("host", "127.0.0.1:47800"), ("authorization", "Bearer abd")]);
        assert_eq!(authorized(&wrong, "abc", 47800), Err(StatusCode::UNAUTHORIZED));
        let rebind = h(&[("host", "evil.com:47800"), ("authorization", "Bearer abc")]);
        assert_eq!(authorized(&rebind, "abc", 47800), Err(StatusCode::FORBIDDEN));
        let browser = h(&[("host", "127.0.0.1:47800"), ("authorization", "Bearer abc"), ("origin", "https://evil.com")]);
        assert_eq!(authorized(&browser, "abc", 47800), Err(StatusCode::FORBIDDEN));
    }
}
