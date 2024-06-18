use actix_web::HttpResponse;
use actix_web::web::Json;
use chrono::NaiveDateTime;
use serde::Serialize;
use crate::errors::ApiError;

pub fn respond_json<T>(data: T) -> Result<Json<T>, ApiError>
    where
        T: Serialize,
{
    Ok(Json(data))
}

/// Helper function to reduce boilerplate of an empty OK response
pub fn respond_ok() -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok().finish())
}

pub fn respond_created() -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Created().finish())
}

pub fn format_datetime(datetime: Option<NaiveDateTime>) -> String {
    match datetime {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(), // Customize format as needed
        None => String::new(), // Handle the case where datetime is None
    }
}