//! HTTP route table wiring the S3 path-style API to the handlers.
//!
//! Path-style addressing only (`host/bucket/key`); virtual-hosted-style is not
//! supported in v0.1. Method + query string together select the operation, so
//! several S3 operations share one route and dispatch internally.

use axum::http::header::SERVER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{middleware, Router};

use crate::auth::auth_middleware;
use crate::handlers::{admin, bucket, object, sts};
use crate::state::AppState;

/// `Server` response-header value identifying this server, e.g. `KerPlace/0.1.0`.
///
/// Mirrors MinIO's `Server: MinIO`, so clients, monitoring and the migration
/// tool can positively identify a KerPlace endpoint. Computed at compile time.
const SERVER_ID: &str = concat!("KerPlace/", env!("CARGO_PKG_VERSION"));

/// Build the application router with all S3 routes and the auth middleware.
///
/// # Parameters
/// - `state`: shared application state injected into every handler.
///
/// # Returns
/// A configured [`Router`] ready to be served.
pub fn build_router(state: AppState) -> Router {
    // Bucket-level methods, shared by `/{bucket}` and the trailing-slash form
    // `/{bucket}/` that clients such as `mc` use. matchit's catch-all does not
    // match an empty segment, so the two patterns do not overlap.
    let bucket_methods = || {
        get(bucket::list_objects)
            .put(bucket::create_bucket)
            .delete(bucket::delete_bucket)
            .head(bucket::head_bucket)
            .post(bucket::post_bucket)
    };

    // Root: GET lists buckets; POST is the STS endpoint (AssumeRoleWithWebIdentity).
    let base = Router::new().route("/", get(bucket::list_buckets).post(sts::dispatch));
    mount_admin(base, state.config.minio_compat)
        .route("/{bucket}", bucket_methods())
        .route("/{bucket}/", bucket_methods())
        .route(
            "/{bucket}/{*key}",
            get(object::get_object_dispatch)
                .put(object::put_object_dispatch)
                .head(object::head_object)
                .delete(object::delete_object_dispatch)
                .post(object::post_object_dispatch),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        // Per-request tracing. tower-http logs at DEBUG/TRACE, so it's silent at
        // the default `info` level and turns on with `KP_DEBUG=debug` — handy
        // when a user reports an issue: ask them to run with it and send the logs.
        .layer(tower_http::trace::TraceLayer::new_for_http())
        // Stamp `Server: KerPlace/<version>` on every response (incl. errors/health).
        .layer(middleware::map_response(add_server_header))
        .with_state(state)
}

/// Mount the admin + health API under the canonical `/kerplace/*` prefix, and —
/// when `compat` — also under the MinIO-compatible `/minio/*` prefix that
/// `mc admin` and madmin SDKs hard-code (Block A: A1 = own namespace, A2 =
/// toggleable compat alias). The handlers are identical; only the mount path
/// differs. `KP_MINIO_COMPAT=false` drops the alias.
///
/// # Parameters
/// - `router`: the base router to extend.
/// - `compat`: whether to also mount the `/minio/*` alias.
///
/// # Returns
/// `router` with the admin and health routes mounted.
fn mount_admin(router: Router<AppState>, compat: bool) -> Router<AppState> {
    // Rebuilt per mount because `nest` consumes the `Router`; the handlers are
    // zero-sized fns, so duplicating the route table costs nothing.
    let admin_v3 = || {
        Router::<AppState>::new()
            .route("/info", get(admin::info))
            .route("/heal", post(admin::heal))
            .route("/ping", get(health))
            .route("/add-user", put(admin::add_user))
            .route("/list-users", get(admin::list_users))
            .route("/remove-user", delete(admin::remove_user))
            .route("/set-user-status", put(admin::set_user_status))
            .route("/user-info", get(admin::user_info))
            .route("/idp/builtin/policy/attach", post(admin::attach_policy))
            .route("/idp/builtin/policy/detach", post(admin::detach_policy))
    };
    let health_routes = || {
        Router::<AppState>::new()
            .route("/live", get(health))
            .route("/ready", get(health))
    };
    let mut r = router
        .nest("/kerplace/admin/v3", admin_v3())
        .nest("/kerplace/health", health_routes());
    if compat {
        r = r
            .nest("/minio/admin/v3", admin_v3())
            .nest("/minio/health", health_routes());
    }
    r
}

/// Add the `Server: KerPlace/<version>` header to a response.
///
/// # Parameters
/// - `resp`: the outgoing response to stamp.
///
/// # Returns
/// The same response with the `Server` header set.
async fn add_server_header(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(SERVER, HeaderValue::from_static(SERVER_ID));
    resp
}

/// Health-check handler for `/{kerplace,minio}/health/{live,ready}`.
///
/// # Returns
/// Always `200 OK`. v0.1 reports readiness unconditionally.
async fn health() -> StatusCode {
    StatusCode::OK
}
