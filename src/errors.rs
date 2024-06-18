use actix_web::{error::ResponseError, HttpResponse};
use serde::Serialize;
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use derive_more::Display;
use sqlx::Error;

#[derive(Debug, Display)]
pub enum ApiError {
    #[display(fmt = "Bad request: {}", _0)]
    BadRequest(String),
    #[display(fmt = "Unauthorized: {}", _0)]
    Unauthorized(String),
    #[display(fmt = "Internal Server Error")]
    InternalServerError,
    NotFound,
    #[display(fmt = "Account with email {} already exist", _0)]
    EmailAlreadyExist(String),
    #[display(fmt = "Account with username {} already exist", _0)]
    UsernameAlreadyExist(String),
    LoginPasswordMismatch,
    #[display(fmt = "Invalid Credentials")]
    InvalidCredentials,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    errors: Vec<String>,
}

impl ErrorResponse {
    pub fn new(errors: Vec<String>) -> Self {
        ErrorResponse { errors }
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match *self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::EmailAlreadyExist(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::UsernameAlreadyExist(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::LoginPasswordMismatch => StatusCode::UNAUTHORIZED,
            ApiError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse::new(vec![self.to_string()]);
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| "{}".to_string());

        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(body)
    }
}

impl From<Error> for ApiError {
    fn from(error: Error) -> ApiError {
        match error {
            Error::RowNotFound => ApiError::NotFound,
            _ => ApiError::InternalServerError,
        }
    }
}