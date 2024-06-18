use std::sync::Arc;
use async_trait::async_trait;
use sqlx::{Error, PgPool, Row};
use sqlx::postgres::{PgArguments, PgPoolOptions, PgQueryResult, PgRow};
use crate::config::CONFIG;

#[async_trait]
pub trait Database: Send + Sync {
    async fn execute(&self, query: &str, args: PgArguments) -> Result<PgQueryResult, Error>;
    async fn fetch_all(&self, query: &str, args: PgArguments) -> Result<Vec<PgRow>, Error>;
    async fn fetch_one(&self, query: &str, args: PgArguments) -> Result<PgRow, Error>;
    async fn fetch_optional(&self, query: &str, args: PgArguments) -> Result<Option<PgRow>, Error>;
}

#[async_trait]
impl Database for PostgresDB {
    async fn execute(&self, query: &str, args: PgArguments) -> Result<PgQueryResult, Error> {
        sqlx::query_with(query, args).execute(&self.pool).await
    }

    async fn fetch_all(&self, query: &str, args: PgArguments) -> Result<Vec<PgRow>, Error> {
        sqlx::query_with(query, args).fetch_all(&self.pool).await
    }

    async fn fetch_one(&self, query: &str, args: PgArguments) -> Result<PgRow, Error> {
        sqlx::query_with(query, args).fetch_one(&self.pool).await
    }

    async fn fetch_optional(&self, query: &str, args: PgArguments) -> Result<Option<PgRow>, Error> {
        sqlx::query_with(query, args).fetch_optional(&self.pool).await
    }
}

pub struct PostgresDB {
    pub pool: PgPool,
}

pub async fn create_pool() -> Result<Arc<PostgresDB>, Error> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&CONFIG.database_url).await?;

    let arc_db = Arc::new(PostgresDB{ pool });

    let ping_response = sqlx::query("SELECT 1 + 1 as sum")
        .fetch_one(&arc_db.pool)
        .await?;
    let sum: i32 = ping_response.get("sum");
    println!("Successfully connected to the DB, 1+1: {}", sum);
    println!("✅ Connection to the database is successful!");
    Ok(arc_db)
}