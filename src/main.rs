use actix_web::{
    guard,
    web::{self, scope},
    App, HttpServer,
};
use actix_web_httpauth::middleware::HttpAuthentication;
use log::info;
use tracing_actix_web::TracingLogger;
use web_apis_in_rust::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let env = env_logger::Env::default()
        .filter("LOG")
        .default_filter_or("info");
    env_logger::init_from_env(env);
    let counts = web::Data::new(UsageStats::new());
    let app = move || {
        info!("Alive");
        App::new()
            .wrap(TracingLogger::default())
            .wrap(actix_web::middleware::Logger::default())
            .app_data(counts.clone())
            .service(liveness)
            .service(
                web::resource("/subscrive")
                    .guard(guard::Header("Content-type", "application/json"))
                    .route(web::post().to(subscribe_with_json)),
            )
            .service(
                scope("/api")
                    .wrap(HttpAuthentication::basic(validator))
                    .service(to_fahrenheit)
                    .service(to_celcius),
            )
            .service(request_api_key)
            .service(delete_api_key)
            .service(subscribe)
            .service(index)
    };
    HttpServer::new(app).bind(("127.0.0.1", 8080))?.run().await
}
