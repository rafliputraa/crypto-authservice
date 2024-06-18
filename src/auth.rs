use std::future::Future;
use std::sync::Arc;
use actix_web::HttpResponse;
use actix_web::web::{Data, Json};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use argon2::password_hash::{Salt, SaltString};
use argon2::password_hash::rand_core::OsRng;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use rand::random;
use sqlx::{Arguments, Error, Row};
use sqlx::postgres::PgArguments;
use validator::Validate;
use crate::config::CONFIG;
use crate::database::Database;
use crate::errors::ApiError;
use crate::errors::ApiError::{InternalServerError, InvalidCredentials, LoginPasswordMismatch, NotFound};
use crate::helpers::{respond_created, respond_json};
use crate::models::{LoginRequest, LoginResponse, RegisterRequest, User};
use crate::server::AppState;

const BEARER: &str = "Bearer ";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn login(
    state: Data<AppState>,
    body: Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let user = is_user_exist_by_username(&state.db, body.username.clone()).await?;
    match verify_password(&user.password, &body.password) {
        Ok(_valid) => {
            let token = create_jwt(&user.username, &CONFIG.jwt_secret)?;
            let login_response = LoginResponse {
                token,
            };
            respond_json(login_response)
        }
        Err(argon2::password_hash::Error::Password) => {
            debug!("password mismatch. username: {}", &body.username);
            Err(LoginPasswordMismatch)
        }
        Err(e) => {
            error!("internal server error: {}", e);
            Err(InternalServerError)
        }
    }
}

fn create_jwt(username: &str, secret: &str) -> Result<String, ApiError> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(1))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .map_err(|_| InternalServerError)?;
    Ok(token)
}

async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(1024, 2, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2i , Version::V0x13, params);
    let hashed_password = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    Ok(hashed_password)
}

fn verify_password(hash: &str, password: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let params = Params::new(1024, 2, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2i , Version::V0x13, params);
    argon2.verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .map_err(|_| argon2::password_hash::Error::Password)
}

pub async fn register(
    state: Data<AppState>,
    body: Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate the registration request
    body
        .validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    is_user_exist_by_username_and_email(&state.db, body.username.clone(), body.email.clone()).await?;

    // Hash the password
    let hashed_password = hash_password(&body.password)
        .await
        .map_err(|_| {
            error!("Password hashing failed");
            InternalServerError
        })?;

    let mut args = PgArguments::default();
    args.add(&body.username);
    args.add(&body.email);
    args.add(&hashed_password);

    let record = state.db
        .execute("INSERT INTO users (username, email, password) \
        values ($1, $2, $3)", args)
        .await?;

    if record.rows_affected() == 0 {
        error!("Register new user failed. username: {}, email: {}", &body.username, &body.email);
        return Err(InternalServerError)
    }

    respond_created()
}

async fn is_user_exist_by_username(db: &Arc<dyn Database>, username: String) -> Result<User, ApiError> {
    let mut args = PgArguments::default();
    args.add(&username);

    let result = db
        .fetch_one("SELECT id, username, email, password FROM users WHERE username = $1", args)
        .await;

    match result {
        Ok(record) => {
            let user = User {
                id: record.get("id"),
                username,
                password: record.get("password"),
                email: record.get("email"),
            };
            Ok(user)
        },
        Err(Error::RowNotFound) => {
            debug!("is_user_exist_by_username - The user is not found. username: {}", &username);
            return Err(InvalidCredentials);
        },
        Err(e) => {
            error!("is_user_exist_by_username - Database query error: {}", e);
            return Err(InternalServerError);
        }
    }
}

async fn is_user_exist_by_username_and_email(db: &Arc<dyn Database>, username: String, email: String) -> Result<(), ApiError> {
    let mut args = PgArguments::default();
    args.add(&username);
    args.add(&email);

    let result = db
        .fetch_one("SELECT username, email FROM users WHERE username = $1 OR email = $2", args)
        .await;

    match result {
        Ok(record) => {
            let username_parsed: String = record.try_get("username").map_err(|e| {
                error!("is_user_exist_by_username_and_email - There is an error when try_get the username. Detail: {}", e);
                InternalServerError
            })?;

            let email_parsed: String = record.try_get("email").map_err(|e| {
                error!("is_user_exist_by_username_and_email - There is an error when try_get the email. Detail: {}", e);
                InternalServerError
            })?;

            if &username_parsed == &username {
                return Err(ApiError::UsernameAlreadyExist(username_parsed))
            } else if &email_parsed == &email {
                return Err(ApiError::EmailAlreadyExist(email_parsed))
            }
        },
        Err(Error::RowNotFound) => {
            debug!("is_user_exist_by_username_and_email - The user is not found. username: {}, email: {}", &username, &email);
        },
        Err(e) => {
            error!("is_user_exist_by_username_and_email - Database query error: {}", e);
            return Err(InternalServerError);
        }
    }
    Ok(())
}