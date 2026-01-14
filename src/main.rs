use axum;
use tokio::net::TcpListener;
use sqlx::postgres::PgPoolOptions; // Importar opciones de pool
use dotenvy::dotenv;
use std::env;

mod auth;
mod routes;
mod services;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    // URL de conexión: postgres://usuario:password@localhost/nombre_bd
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    // Crear el pool de conexiones
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Fallaron las migraciones");
    
    println!("✅ Migraciones aplicadas correctamente");

    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Unable to connect to the server");

    println!("Listening on {}", listener.local_addr().unwrap());

    // Pasamos el pool a la app
    let app = routes::app(pool).await;

    axum::serve(listener, app)
        .await
        .expect("Error serving application");
}