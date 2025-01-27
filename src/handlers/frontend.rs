use crate::Settings;
use crate::auth::Authenticated;
use crate::database::{ApiKey, User};
use crate::errors::{EstuaryError, PackageIndexError};
use crate::package_index::{Dependency, DependencyKind, PackageIndex, PackageVersion};
use actix_session::Session;
use actix_web::{get, web, HttpRequest, HttpResponse, post, delete};
use askama::Template;
use serde::Deserialize;
use serde_json::json;
use std::sync::Mutex;

type Result<T> = std::result::Result<T, EstuaryError>;

#[cfg(not(tarpaulin_include))]
#[get("/styles/main.dist.css")]
pub async fn styles(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/css")
        .body(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/styles/main.dist.css"
        )))
}

#[derive(Template)]
#[template(path = "landing.html")]
pub struct LandingTemplate<'a> {
    title: &'a str,
    user: Option<User>,
    packages: Vec<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    title: &'a str,
    user: Option<User>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate<'a> {
    title: &'a str,
    user: Option<User>,
    name: &'a str,
    api_keys: Vec<ApiKey>
}

#[derive(Template)]
#[template(path = "crate_detail.html")]
pub struct CrateDetailTemplate {
    title: String,
    user: Option<User>,
    pkg: PackageVersion,
    dev_deps: Vec<Dependency>,
    non_dev_deps: Vec<Dependency>,
    releases: Vec<PackageVersion>,
}

#[get("/")]
pub async fn landing(index: web::Data<Mutex<PackageIndex>>) -> Result<LandingTemplate<'static>> {
    let index = index.lock().unwrap();
    let mut names = index.list_crates()?;
    names.sort();

    Ok(LandingTemplate {
        title: "Crate List",
        user : None,
        packages: names,
    })
}

#[get("/me")]
pub async fn me_redirect(_auth : Authenticated) -> Result<HttpResponse> {
    Ok(
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", "/user"))
            .finish()
    )
}

#[get("/user")]
pub async fn get_user(auth : Authenticated, settings : web::Data<Settings>) -> actix_web::Result<HttpResponse> {
    let keys = settings.db.get_api_keys(auth.id).await?;

    Ok(
        HttpResponse::Ok()
            .body(UserTemplate {
                title : &auth.name,
                user : None,
                name: &auth.name,
                api_keys: keys,
            }.to_string())
    )
}

#[derive(Deserialize)]
pub struct NewKey {
    name: String,
}

#[post("/user/api-key")]
pub async fn gen_api_key(auth : Authenticated, new_key : web::Json<NewKey>, settings : web::Data<Settings>) -> actix_web::Result<HttpResponse> {

    let res = settings.db.generate_api_key(new_key.name.clone(), &auth).await?;

    Ok(
        HttpResponse::Ok()
        .json(json!({
            "key": res
        }))
    )
}

#[derive(Deserialize)]
pub struct OldKey {
    id: i32,
}

#[delete("/user/api-key")]
pub async fn revoke_api_key(auth : Authenticated, new_key : web::Json<OldKey>, settings : web::Data<Settings>) -> actix_web::Result<HttpResponse> {
    settings.db.revoke_api_key(new_key.id, auth.id).await?;

    Ok(
        HttpResponse::Ok()
            .finish()
    )
}

#[get("/login")]
pub async fn login(_req: HttpRequest) -> Result<LoginTemplate<'static>> {
    Ok(LoginTemplate {
        title: "Login",
        user : None
    })
}

#[derive(Debug, Deserialize)]
pub struct LoginData {
    username : String,
    password : String,
}

#[post("/login")]
pub async fn login_req(data: web::Form<LoginData>, settings: web::Data<Settings>, session : Session) -> actix_web::Result<HttpResponse> {

    if let Some(user) = settings.db.get_user(data.username.clone()).await? {
        settings.db.verify_password(&user, data.password.clone()).await?;

        session.insert("uid", user.id)?;

        return Ok(
            HttpResponse::SeeOther()
                .append_header(("Location", "/user"))
                .finish()
        )
    }

    Ok(HttpResponse::Ok()
        .body(LoginTemplate {
            title: "Login",
            user : None
        }.to_string()))
}

#[derive(Template)]
#[template(path = "crate_version_list.html")]
pub struct CrateVersionListTemplate {
    user : Option<User>,
    crate_name: String,
    releases: Vec<PackageVersion>,
}

#[derive(Deserialize, Debug)]
pub struct CrateVersionListPath {
    crate_name: String,
}

pub async fn version_list(
    path: web::Path<CrateVersionListPath>,
    index: web::Data<Mutex<PackageIndex>>,
) -> Result<CrateVersionListTemplate> {
    let index = index.lock().unwrap();
    let releases = index
        .get_package_versions(&path.crate_name)
        .map_err(|e| match e {
            PackageIndexError::IO(e @ std::io::Error { .. })
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                EstuaryError::NotFound
            }
            _ => e.into(),
        })?;

    Ok(CrateVersionListTemplate {
        crate_name: path.crate_name.clone(),
        user : None,
        releases,
    })
}

#[derive(Deserialize, Debug)]
pub struct CrateDetailPath {
    crate_name: String,
    /// When version is None, we'll serve the highest available version.
    version: Option<semver::Version>,
}

pub async fn crate_detail(
    path: web::Path<CrateDetailPath>,
    index: web::Data<Mutex<PackageIndex>>,
) -> Result<CrateDetailTemplate> {
    // 404 if:
    // - the crate isn't in the index
    // - the crate version doesn't exist
    // - the requested version isn't a valid version string

    let index = index.lock().unwrap();

    let all_releases = index
        .get_package_versions(&path.crate_name)
        .map_err(|e| match e {
            PackageIndexError::IO(e @ std::io::Error { .. })
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                EstuaryError::NotFound
            }
            _ => e.into(),
        })?;

    let pkg = match &path.version {
        Some(vers) => all_releases.iter().find(|p| &p.vers == vers),
        None => all_releases.iter().max_by_key(|p| &p.vers),
    }
    .cloned();

    match pkg {
        Some(pkg) => {
            let (dev_deps, non_dev_deps) = pkg
                .deps
                .iter()
                .cloned()
                .partition(|dep| dep.kind == DependencyKind::Dev);

            Ok(CrateDetailTemplate {
                user : None,
                title: format!("{} v{}", pkg.name, pkg.vers),
                pkg,
                dev_deps,
                non_dev_deps,
                // Think about showing the highest N instead of all
                releases: all_releases,
            })
        }
        None => return Err(EstuaryError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers;
    use crate::test_helpers::MY_CRATE_0_1_0;
    use actix_web::http::StatusCode;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_landing_ok_empty() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);
        let mut app = test::init_service(
            App::new()
                .app_data(package_index.clone())
                .app_data(settings.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::OK, resp.status());
    }

    #[actix_rt::test]
    async fn test_login() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(package_index.clone())
                .app_data(settings.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::get().uri("/me").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::OK, resp.status());
    }

    #[actix_rt::test]
    async fn test_detail_existing_crate_no_version_is_ok() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(settings.clone())
                .app_data(package_index.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::put()
            .uri("/api/v1/crates/new")
            .set_payload(MY_CRATE_0_1_0)
            .to_request();

        let _: serde_json::Value = test::call_and_read_body_json(&mut app, req).await;

        let req = test::TestRequest::get()
            .uri("/crates/my-crate")
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::OK, resp.status());
    }

    #[actix_rt::test]
    async fn test_detail_nonexistent_crate_is_not_found() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(settings.clone())
                .app_data(package_index.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/crates/non-existent/0.1.0")
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::NOT_FOUND, resp.status());
    }

    #[actix_rt::test]
    async fn test_detail_nonexistent_crate_no_version_is_not_found() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(settings.clone())
                .app_data(package_index.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/crates/non-existent")
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::NOT_FOUND, resp.status());
    }

    #[actix_rt::test]
    async fn test_version_list_existing_crate_is_ok() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(settings.clone())
                .app_data(package_index.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::put()
            .uri("/api/v1/crates/new")
            .set_payload(MY_CRATE_0_1_0)
            .to_request();

        let _: serde_json::Value = test::call_and_read_body_json(&mut app, req).await;

        let req = test::TestRequest::get()
            .uri("/crates/my-crate/versions")
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::OK, resp.status());
    }

    #[actix_rt::test]
    async fn test_version_list_nonexistent_crate_is_not_found() {
        let data_root = test_helpers::get_data_root();
        let settings = test_helpers::get_test_settings(&data_root.path());
        let package_index = test_helpers::get_test_package_index(&settings.index_dir);

        let mut app = test::init_service(
            App::new()
                .app_data(settings.clone())
                .app_data(package_index.clone())
                .configure(crate::handlers::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/crates/non-existent/versions")
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(StatusCode::NOT_FOUND, resp.status());
    }
}
