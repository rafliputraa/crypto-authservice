mod config;
mod database;
mod errors;
mod models;
mod routes;
mod server;
mod auth;
mod helpers;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

use server::server;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    server().await
}
