use askama::Template;
use fastly::{
    http::{header, Method, StatusCode},
    ConfigStore, Error, Request, Response,
};
use oauth2::TokenResponse;

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.

const GITHUB_BACKEND: &str = "github_backend";

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    // Filter request methods...
    match req.get_method() {
        // Block requests with unexpected methods
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD, PURGE")
                .with_body_text_plain("This method is not allowed\n"))
        }

        // Let any other requests through
        _ => (),
    };

    // Pattern match on the path...
    match req.get_path() {
        "/auth" => {
            match req.get_query_parameter("provider") {
                None | Some("github") => {}
                Some(provider) => {
                    return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                        .with_body_text_plain(&format!("Unexpected provider {provider}")));
                }
            }

            let scope = req.get_query_parameter("scope").unwrap_or("repo");

            let host = match req.get_header(header::HOST) {
                Some(host) => host.to_str()?,
                None => {
                    return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                        .with_body_text_plain("No host header"))
                }
            };

            let client = create_client(host);

            let (auth_url, _csrf_state) = client
                .authorize_url(oauth2::CsrfToken::new_random)
                .add_scope(oauth2::Scope::new(scope.to_owned()))
                .url();

            Ok(Response::temporary_redirect(auth_url))
        }
        "/auth/done" => {
            match req.get_query_parameter("provider") {
                None | Some("github") => {}
                Some(provider) => {
                    return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                        .with_body_text_plain(&format!("Unexpected provider {provider}")));
                }
            }

            let code = match req.get_query_parameter("code") {
                Some(code) => oauth2::AuthorizationCode::new(code.to_string()),
                None => {
                    return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                        .with_body_text_plain("Code is required"))
                }
            };

            let host = match req.get_header(header::HOST) {
                Some(host) => host.to_str()?,
                None => {
                    return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                        .with_body_text_plain("No host header"))
                }
            };

            let client = create_client(host);

            match client.exchange_code(code).request(oauth2_request) {
                Ok(token) => Ok(Response::from_status(StatusCode::OK).with_body_text_html(
                    &LoginResponse {
                        token: token.access_token().secret(),
                    }
                    .render()
                    .expect("LoginResponse should render with no error"),
                )),
                Err(e) => {
                    eprintln!("{:?}", e);
                    Ok(Response::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .with_body_text_plain(&e.to_string()))
                }
            }
        }

        // Catch all other requests and return a 404.
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)
            .with_body_text_plain("The page you requested could not be found\n")),
    }
}

fn oauth2_request(
    req: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, fastly::http::request::SendError> {
    let mut request = Request::new(req.method, req.url).with_body(req.body);

    for (name, value) in req.headers {
        if let Some(name) = name {
            request.append_header(name, value);
        }
    }

    let response = request.send(GITHUB_BACKEND)?;

    Ok(oauth2::HttpResponse {
        status_code: response.get_status(),
        headers: response
            .get_headers()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        body: response.into_body_bytes(),
    })
}

#[derive(Template)]
#[template(path = "login_response.html")]
struct LoginResponse<'s> {
    token: &'s str,
}

fn create_client(host: &str) -> oauth2::basic::BasicClient {
    let store = ConfigStore::open("decap_oauth");

    oauth2::basic::BasicClient::new(
        oauth2::ClientId::new(
            store
                .get("client_id")
                .expect("client_id should exist in decap_oauth config store"),
        ),
        Some(oauth2::ClientSecret::new(
            store
                .get("client_secret")
                .expect("client_secret should exist in decap_oauth config store"),
        )),
        oauth2::AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .expect("Auth URL should be a valid URL"),
        Some(
            oauth2::TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                .expect("Token URL should be a valid URL"),
        ),
    )
    .set_redirect_uri(
        oauth2::RedirectUrl::new(format!("https://{host}/auth/done"))
            .expect("Invalid redirect URL"),
    )
}
