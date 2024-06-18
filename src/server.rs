use std::sync::Arc;
use actix_web::{web, App, HttpServer, middleware};
use dotenv::dotenv;
use env_logger::Builder;
use log::{error, info};
use crate::config::CONFIG;
use crate::database::{create_pool, Database};
use crate::routes::init;
use std::io::Write;

pub struct AppState {
    pub db: Arc<dyn Database>,
}

pub async fn server() -> std::io::Result<()> {
    dotenv().ok();

    // Build the log format
    Builder::from_env(env_logger::Env::default().default_filter_or(&CONFIG.log_level))
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {}] {}",
                record.level(),
                chrono::Local::now().format("%Y-%m-%d - %H:%M:%S").to_string(),
                record.args()
            )
        })
        .init();

    let pool;
    match create_pool().await {
        Ok(conn) => {
            pool = conn;
        }
        Err(err) => {
            error!("Failed to create database pool: {}", err);
            std::process::exit(1);
        }
    }

    info!("🚀 Auth Service Started Successfully");
    // Start the server
    let server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(AppState{
                db: pool.clone(),
            }))
            .configure(init)
    });
    server.bind(&CONFIG.server)?.run().await
}
