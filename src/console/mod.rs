//! Embedded web console: a single-page app plus a JSON API for managing
//! buckets and objects. Served on its own port (default `:9001`), mirroring
//! MinIO's split between the S3 API and the console.

pub mod api;
pub mod auth;
pub mod oidc;

use axum::response::Html;
use axum::routing::{delete, get, post, put};
use axum::{middleware, Router};

use crate::state::AppState;

/// Build the web console router (SPA + `/api/*`).
///
/// Authenticated API routes are wrapped with [`api::require_auth`]; `login`
/// and the SPA itself are public.
///
/// # Parameters
/// - `state`: shared application state injected into every handler.
///
/// # Returns
/// A configured [`Router`] ready to be served on the console port.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/info", get(api::info))
        .route("/storage", get(api::storage))
        .route("/heal", post(api::heal))
        .route("/buckets", get(api::list_buckets).post(api::create_bucket))
        .route("/buckets/{bucket}", delete(api::delete_bucket))
        .route("/buckets/{bucket}/settings", get(api::bucket_settings))
        .route("/buckets/{bucket}/versioning", put(api::set_bucket_versioning))
        .route("/buckets/{bucket}/encryption", put(api::set_bucket_encryption))
        .route("/buckets/{bucket}/versions", get(api::list_versions))
        .route("/buckets/{bucket}/objects", get(api::list_objects))
        .route(
            "/buckets/{bucket}/objects/{*key}",
            put(api::upload).get(api::download).delete(api::delete_object),
        )
        .route("/users", get(api::list_users).post(api::add_user))
        .route("/users/{accessKey}", delete(api::delete_user))
        .route("/users/{accessKey}/status", post(api::set_user_status))
        // Applies only to the routes added above; the public routes below
        // (password login + the OIDC SSO endpoints) are added after the layer.
        .route_layer(middleware::from_fn_with_state(state.clone(), api::require_auth))
        .route("/login", post(api::login))
        .route("/oidc/enabled", get(oidc::enabled))
        .route("/oidc/login", get(oidc::login))
        .route("/oidc/callback", get(oidc::callback));

    Router::new()
        .route("/", get(index))
        .nest("/api", api)
        .with_state(state)
}

/// Serve the single-file console SPA (embedded at compile time).
///
/// # Returns
/// The `index.html` document as an HTML response.
async fn index() -> Html<&'static str> {
    Html(include_str!("../../web/index.html"))
}
