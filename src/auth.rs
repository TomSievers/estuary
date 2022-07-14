use std::{sync::Arc, rc::Rc, fmt::Display, ops::Deref};

use actix_session::{SessionExt};
use futures::{future::{LocalBoxFuture, Ready, ready}, FutureExt};

use actix_web::{dev::{Transform, ServiceRequest, Service, ServiceResponse, forward_ready}, HttpMessage, HttpResponse, FromRequest, ResponseError, http::header, HttpRequest};

use crate::database::{SqlDatabase, User, Database};

#[derive(Debug, Clone)]
pub enum AuthError {
    Redirect(String),
    Unauthorized
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Auth Error: {:?}", self))
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        match self {
            AuthError::Redirect(loc) => {
                HttpResponse::TemporaryRedirect()
                    .append_header(("Location", loc.as_str()))
                    .finish()
            },
            AuthError::Unauthorized => {
                HttpResponse::Forbidden()
                    .append_header(header::ContentType::json())
                    .body("{\"errors\": [{\"detail\": \"Unauthorized user\"}]}")
            },
        }
    }
}

fn auth_method(path : &str) -> AuthMethod {
    let parts : Vec<&str> = path.split('/').collect();

    if parts.len() >= 1 {
        match parts[1] {
            "git" =>  AuthMethod::Http,
            "api" => AuthMethod::Http,
            _ => AuthMethod::Session
        }
    } else {
        AuthMethod::Http
    }
}

pub struct Authenticated(User);

impl FromRequest for Authenticated {
    type Error = AuthError;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready(if let Some(user) = req.extensions_mut().get::<User>().cloned() {
            Ok(Authenticated(user))
        } else {
            match auth_method(req.path()) {
                AuthMethod::Session => Err(AuthError::Redirect(String::from("/login"))),
                AuthMethod::Http => Err(AuthError::Unauthorized),
            }
        })
    }
}

impl Deref for Authenticated {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct OptionalAuthenticated(Option<User>);

impl FromRequest for OptionalAuthenticated {
    type Error = AuthError;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        ready(if let Some(user) = req.extensions_mut().get::<User>().cloned() {
            Ok(OptionalAuthenticated(Some(user)))
        } else {
            Ok(OptionalAuthenticated(None))
        })
    }
}

impl Deref for OptionalAuthenticated {
    type Target = Option<User>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct AuthFactory {
    db : Arc<SqlDatabase>
}

impl AuthFactory {
    pub fn new(db : Arc<SqlDatabase>) -> Self {
        AuthFactory { db }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthFactory 
where 
    S : Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static
{
    type Error = actix_web::Error;

    type Response = ServiceResponse<B>;

    type Transform = AuthMiddelware<S>;

    type InitError = ();

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(
            Ok(AuthMiddelware {
                service : Rc::new(service),
                db : self.db.clone()
            })
        )
    }

}

enum AuthMethod {
    Session,
    Http
}

pub struct AuthMiddelware<S> {
    service : Rc<S>,
    db : Arc<SqlDatabase>
}

impl<S, B> Service<ServiceRequest> for AuthMiddelware<S> 
where S : Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let db = self.db.clone();

        async move {
            match auth_method(req.path()) {
                AuthMethod::Session => {
                    if let Some(uid) = req.get_session().get::<i32>("uid")? {
                        if let Some(user) = db.get_user_by_id(uid).await? {
                            req.extensions_mut().insert::<User>(user);
                        }
                    }
                },
                AuthMethod::Http => {
                    if let Some(key) = req.headers().get(header::AUTHORIZATION) {
                        if let Ok(key_s) = key.to_str() {
                            if let Ok(opt) = db.verify_api_key(String::from(key_s)).await {
                                if let Some(user) = opt {
                                    req.extensions_mut().insert::<User>(user);
                                }
                            }
                        }
                    }
                },
            }

            srv.call(req).await

        }
        .boxed_local()
    }
}