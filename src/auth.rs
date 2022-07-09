use std::{rc::Rc};

use actix_session::SessionExt;
use futures::{future::{LocalBoxFuture, Ready}, FutureExt};

use actix_web::dev::{Transform, ServiceRequest, Service, ServiceResponse, forward_ready};

use crate::database::Database;

pub struct AuthFactory {
    
}

pub enum AuthMethod {
    Session,
    ApiKey,
}

impl AuthFactory {
    pub fn new(db : Rc<Database>, method : AuthMethod) -> Self {
        AuthFactory {  }
    }
}

pub enum Error {
    None
}

impl<S, B> Transform<S, ServiceRequest> for AuthFactory 
where 
    S : Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static
{
    type Error = Error;

    type Response = ServiceResponse<B>;

    type Transform = AuthMiddelware<S>;

    type InitError = ();

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        todo!()
    }

}

pub struct AuthMiddelware<S> {
    service : Rc<S>
}

impl<S, B> Service<ServiceRequest> for AuthMiddelware<S> 
where S : Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();

        async move {
            // Get the session cookie value, if it exists. 
            if let Some(uid) = req.get_session().get::<u32>("uid").or(Err(Error::None))? {

            }

            let res = srv.call(req).await?;

            Ok(res)
        }
        .boxed_local()
    }
}