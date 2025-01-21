use std::sync::Mutex;
mod auth;
use actix_web::{delete, dev::ServiceRequest, get, post, web, HttpResponse, Responder};
use actix_web_httpauth::extractors::basic::BasicAuth;
use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Subscriber {
    name: String,
    email: String,
}

#[derive(Serialize)]
pub struct Temperature {
    fahrenheit: f32,
    celcius: f32,
}

#[derive(Default)]
pub struct Counters {
    to_celcius: u32,
    to_fahrenheit: u32,
}

#[derive(Default)]
pub struct UsageStats {
    counters: Mutex<Counters>,
}

impl UsageStats {
    pub fn new() -> Self {
        UsageStats::default()
    }
}

#[get("/healthz")]
pub async fn liveness() -> &'static str {
    "ok\r\n"
}

#[post("/subscribe")]
pub async fn subscribe(info: web::Form<Subscriber>) -> HttpResponse {
    println!("New subscriber : {:?}", info.into_inner());
    HttpResponse::NoContent().finish()
}

pub async fn subscribe_with_json(info: web::Json<Subscriber>) -> HttpResponse {
    println!("New json subscriber : {:?}", info.into_inner());
    HttpResponse::NoContent().finish()
}

#[get("/to-celcius/{fahrenheit}")]
pub async fn to_celcius(f: web::Path<f32>, stats: web::Data<UsageStats>) -> impl Responder {
    actix_web::rt::spawn(async move {
        let mut counts = stats.counters.lock().unwrap();
        counts.to_celcius += 1;
    });
    let f = f.into_inner();
    let c = (f - 32.0) / 1.8;
    web::Json(Temperature {
        celcius: c,
        fahrenheit: f,
    })
}

#[get("/to-fahrenheit/{celcius}")]
pub async fn to_fahrenheit(c: web::Path<f32>, stats: web::Data<UsageStats>) -> impl Responder {
    actix_web::rt::spawn(async move {
        let mut counts = stats.counters.lock().unwrap();
        counts.to_fahrenheit += 1;
    });
    let c = c.into_inner();
    let f = c * 1.8 + 32.0;
    web::Json(Temperature {
        celcius: c,
        fahrenheit: f,
    })
}

#[get("/")]
pub async fn index() -> HttpResponse {
    let body = r#"
    <!DOCTYPE html>
    <html>
        <head>
            <style>
                * { font-family: sans-serif; }
                form { display: table; }
                form > div { display: table-row; }
                input, lable { 
                    display: table-cell; 
                    margin-bottom: 8px;
                }
                label { pagging-right: 1rem; }
            </style>
        </head>
        <body>
            <p>A demo web applicaiton</p>

            <form action="/subscribe" method="POST">
                <div>
                    <label for="n">Name:</label>
                    <input id="n" name="name" type="text" required>
                </div>
                <div>
                    <label for="e">Email:</label>
                    <input id="e" name="email" type="email" required>
                </div>
                <input type="submit">
            </form>
        </body>
    </html>
    "#;
    HttpResponse::Ok().content_type("text/html").body(body)
}

pub async fn validator(
    req: ServiceRequest,
    basic_auth: BasicAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    let api_key = basic_auth.user_id();
    match auth::is_key_allowed_access(api_key) {
        Ok(true) => Ok(req),
        Ok(false) => Err((
            actix_web::error::ErrorUnauthorized("Supplied token is not authorized"),
            req
        )),
        Err(_) => Err((
            actix_web::error::ErrorInternalServerError(""),
            req
        ))
    }
}

#[get("/api-key")]
pub async fn request_api_key() -> actix_web::Result<impl Responder> {
    let api_key = String::from("1234");
    auth::store_api_key(&api_key)?;
    Ok(api_key + "\r\n")
}

#[delete("/api-key")]
pub async fn delete_api_key(basic_auth: BasicAuth) -> actix_web::Result<impl Responder> {
    let api_key = basic_auth.user_id();
    auth::revoke_api_key(api_key)?;
    Ok(HttpResponse::NoContent().finish())
}
