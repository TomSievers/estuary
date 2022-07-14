use std::{time::Duration, fmt::Display, str::Utf8Error};

use actix_web::{ResponseError, HttpResponse};
use argon2::{password_hash::{SaltString, rand_core::{OsRng, RngCore}}, Argon2, PasswordHasher, PasswordVerifier, PasswordHash};
use base64::DecodeError;
use futures::{future::{LocalBoxFuture}, FutureExt};
use sqlx::{AnyPool, any::AnyPoolOptions};

#[derive(Clone, Debug)]
pub struct SqlDatabase {
    pool : AnyPool
}

#[derive(Clone, Debug)]
pub struct TestDatabase {

}

pub trait Database : std::fmt::Debug + Send + Sync {
    fn get_user(&self, name : String) -> LocalBoxFuture<Result<Option<User>, DatabaseError>>;
    fn get_user_by_id(&self, id : i32) -> LocalBoxFuture<Result<Option<User>, DatabaseError>>;
    fn get_api_keys(&self, uid : i32) -> LocalBoxFuture<Result<Vec<ApiKey>, DatabaseError>>;
    fn create_user(&self, name : String, password : String, role : UserRole) -> LocalBoxFuture<Result<User, DatabaseError>>;
    fn verify_password(&self, user : &User, password : String) -> LocalBoxFuture<Result<(), DatabaseError>>;
    fn generate_api_key(&self, name : String, user : &User) -> LocalBoxFuture<Result<String, DatabaseError>>;
    fn revoke_api_key(&self, id : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>>;
    fn verify_api_key(&self, key : String) -> LocalBoxFuture<Result<Option<User>, DatabaseError>>;
    fn create_crate(&self, name : String) -> LocalBoxFuture<Result<Crate, DatabaseError>>;
    fn add_crate_owner(&self, cid : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>>;
    fn remove_crate_owner(&self, cid : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>>;
    fn get_crate_owners(&self, name : String) -> LocalBoxFuture<Result<Vec<User>, DatabaseError>>;
    fn migrate(&self) -> LocalBoxFuture<Result<(), DatabaseError>>;
}

impl Database for SqlDatabase {
    fn get_user(&self, name : String) -> LocalBoxFuture<Result<Option<User>, DatabaseError>> {
        async move {
            let res : Option<User> = sqlx::query_as("SELECT * FROM users WHERE name=$1")
                .bind(name.as_str())
                .fetch_optional(&self.pool).await?;

            Ok(res)
        }.boxed_local()
    }

    fn get_user_by_id(&self, id : i32) -> LocalBoxFuture<Result<Option<User>, DatabaseError>> {
        async move {
            let res : Option<User> = sqlx::query_as("SELECT * FROM users WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool).await?;

            Ok(res)
        }.boxed_local()
    }

    fn get_api_keys(&self, uid : i32) -> LocalBoxFuture<Result<Vec<ApiKey>, DatabaseError>> {
        async move {
            let res : Vec<ApiKey> = sqlx::query_as("SELECT * FROM api_keys WHERE uid=$1")
            .bind(uid)
            .fetch_all(&self.pool).await?;

        Ok(res)
        }.boxed_local()
    }

    fn create_user(&self, name : String, password : String, role : UserRole) -> LocalBoxFuture<Result<User, DatabaseError>> {

        async move {
            let user = self.get_user(name.clone()).await?;

            if user.is_some() {
                return Err(DatabaseError::UniqueAlreadyExists);
            }

            let salt = SaltString::generate(&mut OsRng);

            let argon2 = Argon2::default();

            let passowrd_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

            sqlx::query("INSERT INTO users (name, password_hash, role) VALUES ($1, $2, $3)")
                .bind(name.clone())
                .bind(passowrd_hash)
                .bind(role)
                .execute(&self.pool).await?;

            if let Some(user) = self.get_user(name).await? {
                Ok(user)
            } else {
                Err(DatabaseError::InvalidInput)
            }
        }.boxed_local()

    }

    fn verify_password(&self, user : &User, password : String) -> LocalBoxFuture<Result<(), DatabaseError>> {

        let user = user.clone();

        async move {
            let hash = PasswordHash::new(&user.password_hash)?;
            Argon2::default().verify_password(password.as_bytes(), &hash)?;

            Ok(())
        }.boxed_local()
    }

    fn generate_api_key(&self, name : String, user : &User) -> LocalBoxFuture<Result<String, DatabaseError>> {
        let user = user.clone();

        async move {
            let len = (OsRng.next_u32() % 32) + 32;

            let mut key = vec![0; 32];

            OsRng.fill_bytes(key.as_mut_slice());

            let key_str = base64::encode(key);

            let salt = SaltString::generate(&mut OsRng);

            let argon2 = Argon2::default();

            let key_hash = argon2.hash_password(key_str.as_bytes(), &salt)?.to_string();

            let exists : Option<ApiKey> = sqlx::query_as("SELECT * FROM api_keys WHERE name = $1")
                .bind(name.as_str())
                .fetch_optional(&self.pool).await?;

            if exists.is_some() {
                return Err(DatabaseError::UniqueAlreadyExists)
            }

            let exists : Option<ApiKey> = sqlx::query_as("SELECT * FROM api_keys WHERE key = $1 AND uid = $2")
                .bind(key_hash.clone())
                .bind(user.id)
                .fetch_optional(&self.pool).await?;

            if exists.is_some() {
                return Err(DatabaseError::UniqueAlreadyExists)
            }

            sqlx::query("INSERT INTO api_keys (name, uid, key) VALUES ($1, $2, $3)")
                .bind(name.as_str())
                .bind(user.id)
                .bind(key_hash.clone())
                .execute(&self.pool).await?;


            let mut res_string = String::new();
            res_string.push_str(&user.name);
            res_string.push_str(":");
            res_string.push_str(&key_str);

            return Ok(base64::encode(res_string))
        }.boxed_local()
    }

    fn verify_api_key(&self, key : String) -> LocalBoxFuture<Result<Option<User>, DatabaseError>> {
        async move {
            let data = base64::decode(key)?;
            let str = std::str::from_utf8(&data)?;
            let parts : Vec<&str> = str.split(':').collect();

            if parts.len() == 2 {
                if let Some(user) = self.get_user(String::from(parts[0])).await? {
                    let keys = self.get_api_keys(user.id).await?;

                    for key in keys {
                        let hash = PasswordHash::new(&key.key)?;
                        if Argon2::default().verify_password(parts[1].as_bytes(), &hash).is_ok() {
                            return Ok(Some(user));
                        }
                    }
                }
            }

            Ok(None)
        }.boxed_local()
    }

    fn revoke_api_key(&self, id : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>>{
        async move {
            sqlx::query("DELETE FROM api_keys WHERE id=$1 AND uid=$2")
                .bind(id)
                .bind(uid)
                .execute(&self.pool).await?;

            Ok(())
        }.boxed_local()
    }

    fn get_crate_owners(&self, name : String) -> LocalBoxFuture<Result<Vec<User>, DatabaseError>> {
        async move {
            let c : Option<Crate> = sqlx::query_as("SELECT * FROM crates WHERE name=$1")
                .bind(name.as_str())
                .fetch_optional(&self.pool).await?;

            if let Some(c) = c {
                let res : Vec<User> = sqlx::query_as(
                    "SELECT users.id, users.name, users.password_hash, users.role 
                        FROM users INNER JOIN owners ON users.id=owners.uid 
                        INNER JOIN crates ON owners.cid=crates.id 
                        WHERE crates.id=$1;")
                    .bind(c.id)
                    .fetch_all(&self.pool).await?;
                Ok(res)
            } else {
                Ok(Vec::new())
            }
        }.boxed_local()
    }

    fn create_crate(&self, name : String) -> LocalBoxFuture<Result<Crate, DatabaseError>> {
        async move {
            sqlx::query("INSERT INTO crates(name) VALUES($1)")
                .bind(name.as_str())
                .execute(&self.pool).await?;

            let res : Crate = sqlx::query_as("SELECT * FROM crates WHERE name=$1")
                .bind(name.as_str())
                .fetch_one(&self.pool).await?;

            Ok(res)
        }.boxed_local()
    }

    fn add_crate_owner(&self, cid : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>> {
        async move {
            sqlx::query("INSERT INTO owners(cid, uid) VALUES($1, $2)")
                .bind(cid)
                .bind(uid)
                .execute(&self.pool).await?;

            Ok(())
        }.boxed_local()
    }

    fn remove_crate_owner(&self, cid : i32, uid : i32) -> LocalBoxFuture<Result<(), DatabaseError>> {
        async move {
            sqlx::query("DELETE FROM owners WHERE cid=$1 AND uid=$2")
                .bind(cid)
                .bind(uid)
                .execute(&self.pool).await?;

            Ok(())
        }.boxed_local()
    }

    fn migrate(&self) -> LocalBoxFuture<Result<(), DatabaseError>> {
        async move {

            let create_table_query = format!("CREATE TABLE IF NOT EXISTS users (
                id {} PRIMARY KEY NOT NULL,
                name VARCHAR(50) NOT NULL {},
                password_hash VARCHAR(200) NOT NULL,
                role INTEGER NOT NULL
            );", id_type(DatabaseType::PgSql)
            , unique(DatabaseType::PgSql));

            sqlx::query(&create_table_query)
                .execute(&self.pool).await?;

            let create_table_query = format!("CREATE TABLE IF NOT EXISTS api_keys (
                id {} PRIMARY KEY NOT NULL,
                name VARCHAR(200) NOT NULL {},
                uid INTEGER NOT NULL,
                key VARCHAR(500) NOT NULL,
                CONSTRAINT api_key_user FOREIGN KEY(uid) REFERENCES users(id)
            );", id_type(DatabaseType::PgSql)
            , unique(DatabaseType::PgSql));

            sqlx::query(&create_table_query)
                .execute(&self.pool).await?;

            let create_table_query = format!("CREATE TABLE IF NOT EXISTS crates (
                id {} PRIMARY KEY NOT NULL,
                name VARCHAR(200)
            );", id_type(DatabaseType::PgSql));

            sqlx::query(&create_table_query)
                .execute(&self.pool).await?;

            let create_table_query = format!("CREATE TABLE IF NOT EXISTS owners (
                cid INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                CONSTRAINT crate_id FOREIGN KEY(cid) REFERENCES crates(id),
                CONSTRAINT user_id FOREIGN KEY(uid) REFERENCES users(id)
            );");

            sqlx::query(&create_table_query)
                .execute(&self.pool).await?;

            let res = self.create_user(String::from("admin"), String::from("admin"), UserRole::Administrator).await;

            match res {
                Ok(_) => (),
                Err(e) => {
                    match e {
                        DatabaseError::UniqueAlreadyExists => (),
                        _ => return Err(e),
                    }
                },
            }

            Ok(())
        }.boxed_local()
    }
}

enum DatabaseType {
    MySql,
    MsSql,
    PgSql,
    Sqlite
}

fn id_type(t : DatabaseType) -> &'static str {
    match t {
        DatabaseType::PgSql => "SERIAL",
        _ => "INTEGER AUTO_INCREMENT"
    }
}

fn unique(t : DatabaseType) -> &'static str {
    match t {
        DatabaseType::PgSql => "UNIQUE",
        _ => "UNIQUE KEY"
    }
}

impl SqlDatabase {
    pub async fn new<U>(uri : U, max_connections : u32, timeout : Duration) -> SqlDatabase
    where U: AsRef<str>
    {
        async fn inner(uri : &str, max_connections : u32, timeout : Duration) -> SqlDatabase {
            let mut pool = AnyPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(timeout)
                .connect(uri).await;

            while pool.is_err() {
                log::error!("Unable to connect to database at {}\t Retrying...", uri);
                pool = AnyPoolOptions::new()
                    .max_connections(max_connections)
                    .acquire_timeout(timeout)
                    .connect(uri).await;
            }

            SqlDatabase {
                pool : pool.unwrap()
            }
        }

        inner(uri.as_ref(), max_connections, timeout).await  
    }
}

#[derive(Debug)]
pub enum DatabaseError {
    SqlError(sqlx::Error),
    PWHashError(argon2::password_hash::Error),
    InvalidInput,
    UniqueAlreadyExists,
    InvalidUri
}

impl ResponseError for DatabaseError {
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::BadRequest()
            .finish()
    }
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
            DatabaseError::InvalidInput => {
                f.write_str("Invalid input")
            }
        }
        
    }
}

impl From<sqlx::Error> for DatabaseError {
    fn from(v: sqlx::Error) -> Self {
        /*match v {
            sqlx::Error::Configuration(_) => todo!(),
            sqlx::Error::Database(_) => todo!(),
            sqlx::Error::Io(_) => todo!(),
            sqlx::Error::Tls(_) => todo!(),
            sqlx::Error::Protocol(_) => todo!(),
            sqlx::Error::RowNotFound => todo!(),
            sqlx::Error::TypeNotFound { type_name } => todo!(),
            sqlx::Error::ColumnIndexOutOfBounds { index, len } => todo!(),
            sqlx::Error::ColumnNotFound(_) => todo!(),
            sqlx::Error::ColumnDecode { index, source } => todo!(),
            sqlx::Error::Decode(_) => todo!(),
            sqlx::Error::PoolTimedOut => todo!(),
            sqlx::Error::PoolClosed => todo!(),
            sqlx::Error::WorkerCrashed => todo!(),
            sqlx::Error::Migrate(_) => todo!(),
            _ => todo!(),
        }*/
        DatabaseError::SqlError(v) 
    }
}

impl From<argon2::password_hash::Error> for DatabaseError {
    fn from(v: argon2::password_hash::Error) -> Self {
        DatabaseError::PWHashError(v)
    }
}

impl From<DecodeError> for DatabaseError {
    fn from(_: DecodeError) -> Self {
        DatabaseError::InvalidInput
    }
}

impl From<Utf8Error> for DatabaseError {
    fn from(_: Utf8Error) -> Self {
        DatabaseError::InvalidInput
    }
}

#[derive(Clone, Copy, Debug, sqlx::Type)]
#[repr(i32)]
pub enum UserRole {
    Viewer,
    Publisher,
    Administrator
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct User {
    pub id : i32,
    pub name : String,
    pub password_hash : String,
    pub role : UserRole,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Crate {
    pub id : i32,
    pub name : String,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct ApiKey {
    pub id : i32,
    pub name : String,
    pub uid : i32,
    pub key : String,
}