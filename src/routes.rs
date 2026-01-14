use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use crate::{auth, services};

pub async fn app(pool: PgPool) -> Router {
    Router::new()
        .route("/signin", post(auth::sign_in))
        .route("/signup", post(auth::sign_up)) // <-- ¡AGREGA ESTA LÍNEA!
        .route(
            "/protected/",
            get(services::hello).layer(middleware::from_fn_with_state(pool.clone(), auth::authorize)),
        )
        .with_state(pool)
}