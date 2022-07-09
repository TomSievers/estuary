use std::{time::Duration, fmt::Display};

use actix_web::ResponseError;
use argon2::{password_hash::{SaltString, rand_core::{OsRng, RngCore}}, Argon2, PasswordHasher, PasswordVerifier, PasswordHash};
use sqlx::{AnyPool, any::AnyPoolOptions};
use url::Url;


#[derive(Clone, Debug)]
pub struct Database {
    pool : AnyPool
}

impl Database {
    pub async fn new<U>(uri : U, max_connections : u32, timeout : Duration) -> Result<Database, DatabaseError> 
    where U: AsRef<str>
    {
        async fn inner(uri : &str, max_connections : u32, timeout : Duration) -> Result<Database, DatabaseError> {
            let url = Url::parse(uri).or(Err(DatabaseError::InvalidUri))?;

            match url.scheme() {
                "postgres" => {

                }
                _ => {
                    return Err(DatabaseError::InvalidUri);
                }
            }

            Ok(
                Database {
                    pool : AnyPoolOptions::new()
                    .max_connections(max_connections)
                    .acquire_timeout(timeout)
                    .connect(uri).await?
                }
            )
        }

        inner(uri.as_ref(), max_connections, timeout).await  
    }

    pub async fn get_user<U>(&self, name : U) -> Result<Option<User>, DatabaseError> 
    where U : AsRef<str>
    {
        async fn inner(db : &Database, name : &str) ->Result<Option<User>, DatabaseError> {
            let res : Option<User> = sqlx::query_as("SELECT * FROM users WHERE name=$1")
                .bind(name)
                .fetch_optional(&db.pool).await?;

            Ok(res)
        }

        inner(self, name.as_ref()).await
    }

    pub async fn get_user_by_id(&self, id : i32) -> Result<Option<User>, DatabaseError> 
    {
        let res : Option<User> = sqlx::query_as("SELECT * FROM users WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool).await?;

        Ok(res)
    }

    pub async fn get_api_keys(&self, uid : i32) -> Result<Vec<ApiKey>, DatabaseError> {
        let res : Vec<ApiKey> = sqlx::query_as("SELECT * FROM api_keys WHERE uid=$1")
            .bind(uid)
            .fetch_all(&self.pool).await?;

        Ok(res)
    }

    pub async fn create_user<U>(&self, name : U, password : U, write_permission : bool) -> Result<(), DatabaseError> 
    where U : AsRef<str>
    {
        async fn inner(db : &Database, name : &str, password : &str, write_permission : bool) -> Result<(), DatabaseError> {
            let user = db.get_user(name).await?;

            if user.is_some() {
                return Err(DatabaseError::UniqueAlreadyExists);
            }

            let salt = SaltString::generate(&mut OsRng);

            let argon2 = Argon2::default();

            let passowrd_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

            sqlx::query("INSERT INTO users (name, password_hash, write_permissions) VALUES ($1, $2, $3)")
                .bind(name)
                .bind(passowrd_hash)
                .bind(write_permission)
                .execute(&db.pool).await?;

            Ok(())
        } 

        inner(self, name.as_ref(), password.as_ref(), write_permission).await
    }

    pub async fn verify_password<U>(&self, user : &User, password : U) -> Result<(), DatabaseError> 
    where U : AsRef<str>
    {
        fn inner(user : &User, password : &str) -> Result<(), DatabaseError> {
            let hash = PasswordHash::new(&user.password_hash)?;
            Argon2::default().verify_password(password.as_bytes(), &hash)?;

            Ok(())
        }

        inner(user, password.as_ref())
    }

    pub async fn generate_api_key(&self, uid : i64) -> Result<String, DatabaseError> {

        let len = (OsRng.next_u32() % 32) + 32;

        let mut key = vec![0; len as usize];

        OsRng.fill_bytes(key.as_mut_slice());

        let key_str = base64::encode(key);

        let exists : Option<ApiKey> = sqlx::query_as("SELECT * FROM api_keys WHERE key = $1 AND uid = $2")
            .bind(key_str.clone())
            .bind(uid)
            .fetch_optional(&self.pool).await?;

        if exists.is_some() {
            return Err(DatabaseError::UniqueAlreadyExists)
        }

        sqlx::query("INSERT INTO api_keys (uid, key) VALUES ($1, $2)")
            .bind(uid)
            .bind(key_str.clone())
            .execute(&self.pool).await?;

        return Ok(key_str)
    }
}

#[derive(Debug)]
pub enum DatabaseError {
    SqlError(sqlx::Error),
    PWHashError(argon2::password_hash::Error),
    UniqueAlreadyExists,
    InvalidUri
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::SqlError(e) => {
                f.write_str(format!("SqlError: {:?}", e).as_str())
            },
            DatabaseError::PWHashError(e) => {
                f.write_str(format!("HashError: {:?}", e).as_str())
            },
            DatabaseError::UniqueAlreadyExists => {
                f.write_str("Unique value already exists")
            },
            DatabaseError::InvalidUri => {
                f.write_str("Invalid URI")
            },
        }
        
    }
}

impl From<sqlx::Error> for DatabaseError {
    fn from(v: sqlx::Error) -> Self {
        DatabaseError::SqlError(v) 
    }
}

impl From<argon2::password_hash::Error> for DatabaseError {
    fn from(v: argon2::password_hash::Error) -> Self {
        DatabaseError::PWHashError(v)
    }
}

impl ResponseError for DatabaseError {
    
}


#[derive(sqlx::FromRow, Debug, Clone)]
pub struct User {
    pub id : i32,
    pub name : String,
    pub password_hash : String,
    pub write_permissions : bool,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct ApiKey {
    pub id : i32,
    pub uid : i32,
    pub key : String,
}