use actix_web::App;
use web_apis_in_rust::request_api_key;

#[actix_web::test]
async fn request_api_key_endpoint() {
    let app = actix_web::test::init_service(
        App::new()
            .service(request_api_key)
    ).await;

    let req = actix_web::test::TestRequest::get().uri("/api-key").to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}