mod error;
mod preflight;
mod routes;

use axum::Router;

pub fn app() -> Router {
    Router::new().nest("/api/wallet", routes::wallet::router())
}
