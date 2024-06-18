use actix_web::web;
use crate::auth::{login, register};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg
        .service(
        web::scope("/api/v1")
            .route("/login", web::post().to(login))
            .route("/register", web::post().to(register))
    );
}
