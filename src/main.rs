use crate::errors::EstuaryError;
use actix_web::{middleware, web, App, HttpServer, cookie::Key};
use package_index::{Config, PackageIndex};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::Duration;
use database::{SqlDatabase, Database};
use actix_session::{storage::RedisActorSessionStore, SessionMiddleware};

mod cli;
mod errors;
mod handlers;
mod package_index;
mod storage;
mod database;
mod auth;

/// Common configuration details to share with handlers.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Root path for storing `.crate` files when they are published.
    pub crate_dir: PathBuf,
    /// Location for the git repo that tracks changes to the package index.
    ///
    /// Note that this should be the path to the working tree, not the `.git`
    /// directory inside it.
    pub index_dir: PathBuf,
    /// Optionally specify a path to `git`.
    ///
    /// Defaults to just "git", expecting it to be in your `PATH`.
    pub git_binary: PathBuf,

    /// The key that must be presented in order to publish a crate.
    pub publish_key: Option<String>,

    pub db : Arc<dyn Database>
}

#[cfg(not(tarpaulin_include))]
#[actix_web::main]
async fn main() -> Result<(), EstuaryError> {

    #[cfg(feature = "dotenv")]
    dotenv::dotenv().ok();

    env_logger::init();

    let args = cli::parse_args();

    let bind_addr = format!("{}:{}", args.http_host, args.http_port);
    let config = Config {
        dl: args.download_url(),
        api: args.base_url().to_string(),
    };

    let db = Arc::new(SqlDatabase::new(
        args.db_uri.clone(),
        args.db_max_connections,
        Duration::from_secs(args.db_timeout_s.into())
    ).await);
        

    log::warn!("{:?}", db.migrate().await);

    let settings = Settings {
        crate_dir: args.crate_dir,
        index_dir: args.index_dir,
        git_binary: args.git_bin,
        publish_key: args.publish_key,
        db : db.clone()
    };

    std::fs::create_dir_all(&settings.index_dir)?;
    std::fs::create_dir_all(&settings.crate_dir)?;

    log::info!("Server starting on `{}`", bind_addr);
    log::info!("\tIndex Dir: `{}`", settings.index_dir.display());
    log::info!("\tCrate Dir: `{}`", settings.crate_dir.display());
    log::info!("\tPackage Index Config: `{:?}`", config);
    log::info!("\tDatabase URI: `{:?}`", args.db_uri);
    log::info!("\tRedis URI: `{:?}`", args.redis_uri);

    let package_index = web::Data::new(Mutex::new(PackageIndex::init(
        &settings.index_dir,
        &config,
    )?));

    let secret_key = Key::generate();

    //let redis_uri = args.redis_uri.clone();

    Ok(HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(auth::AuthFactory::new(db.clone()))
            .wrap(SessionMiddleware::builder(
                    RedisActorSessionStore::new("localhost:6379"),
                    secret_key.clone()
                )
                .cookie_secure(false)
                .build()
            )
            .app_data(package_index.clone())
            .app_data(web::Data::new(settings.clone()))
            .configure(handlers::configure_routes)
    })
    .bind(bind_addr)?
    .run()
    .await?)
}

#[cfg(test)]
mod test_helpers;
