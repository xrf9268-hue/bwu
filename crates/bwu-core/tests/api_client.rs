use bwu_core::api::{
    ApiClient, ApiKeyTokenRequest, Device, EndpointConfig, PasswordTokenRequest, PreloginRequest,
    RefreshTokenRequest,
};
use mockito::{Matcher, Server};

#[test]
fn endpoint_model_builds_us_eu_and_self_hosted_urls() {
    let us = EndpointConfig::official_us();
    assert_eq!(us.web_vault_url().as_str(), "https://vault.bitwarden.com/");
    assert_eq!(
        us.prelogin_url().as_str(),
        "https://identity.bitwarden.com/accounts/prelogin/password"
    );
    assert_eq!(
        us.token_url().as_str(),
        "https://identity.bitwarden.com/connect/token"
    );
    assert_eq!(
        us.sync_url(false).as_str(),
        "https://api.bitwarden.com/sync"
    );
    assert_eq!(
        us.sync_url(true).as_str(),
        "https://api.bitwarden.com/sync?excludeDomains=true"
    );

    let eu = EndpointConfig::official_eu();
    assert_eq!(eu.web_vault_url().as_str(), "https://vault.bitwarden.eu/");
    assert_eq!(
        eu.prelogin_url().as_str(),
        "https://identity.bitwarden.eu/accounts/prelogin/password"
    );
    assert_eq!(eu.sync_url(false).as_str(), "https://api.bitwarden.eu/sync");

    let custom = EndpointConfig::self_hosted("https://vault.example.test/")
        .expect("valid self-hosted base URL");
    assert_eq!(
        custom.web_vault_url().as_str(),
        "https://vault.example.test/"
    );
    assert_eq!(
        custom.prelogin_url().as_str(),
        "https://vault.example.test/identity/accounts/prelogin/password"
    );
    assert_eq!(
        custom.token_url().as_str(),
        "https://vault.example.test/identity/connect/token"
    );
    assert_eq!(
        custom.sync_url(false).as_str(),
        "https://vault.example.test/api/sync"
    );
}

#[test]
fn prelogin_posts_to_identity_endpoint_and_parses_kdf_response() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _mock = server
        .mock("POST", "/identity/accounts/prelogin/password")
        .match_header(
            "content-type",
            Matcher::Regex("application/json.*".to_owned()),
        )
        .match_body(Matcher::JsonString(
            r#"{"email":"user@example.test"}"#.to_owned(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"Kdf":0,"KdfIterations":600000}"#)
        .create();

    let response = ApiClient::new(endpoint)
        .prelogin(&PreloginRequest::new("user@example.test"))
        .expect("prelogin response should parse");

    assert_eq!(response.kdf, 0);
    assert_eq!(response.kdf_iterations, 600000);
}

#[test]
fn token_exchange_and_refresh_parse_structured_response_fields() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let device = Device::new(25, "Linux CLI", "synthetic-device-id");

    let _token_mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".to_owned(), "password".to_owned()),
            Matcher::UrlEncoded("client_id".to_owned(), "synthetic-client-id".to_owned()),
            Matcher::UrlEncoded("username".to_owned(), "user@example.test".to_owned()),
            Matcher::UrlEncoded("password".to_owned(), "synthetic-master-hash".to_owned()),
            Matcher::UrlEncoded("deviceType".to_owned(), "25".to_owned()),
            Matcher::UrlEncoded("deviceName".to_owned(), "Linux CLI".to_owned()),
            Matcher::UrlEncoded(
                "deviceIdentifier".to_owned(),
                "synthetic-device-id".to_owned(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "access_token":"synthetic-access-token",
                "expires_in":3600,
                "refresh_token":"synthetic-refresh-token",
                "token_type":"Bearer",
                "PrivateKey":"2.encrypted-private-key",
                "Key":"2.encrypted-user-key",
                "Kdf":0,
                "KdfIterations":600000,
                "ForcePasswordReset":false,
                "TwoFactorToken":"synthetic-two-factor-token",
                "ApiUseKeyConnector":false
            }"#,
        )
        .create();

    let client = ApiClient::new(endpoint.clone());
    let token_response = client
        .exchange_password_token(&PasswordTokenRequest::new(
            "user@example.test",
            "synthetic-master-hash",
            "synthetic-client-id",
            device,
        ))
        .expect("token response should parse");

    assert_eq!(
        token_response.access_token.as_str(),
        "synthetic-access-token"
    );
    assert_eq!(
        token_response.refresh_token.as_deref(),
        Some("synthetic-refresh-token")
    );
    assert_eq!(token_response.kdf, Some(0));
    assert_eq!(token_response.kdf_iterations, Some(600000));
    assert_eq!(token_response.force_password_reset, Some(false));

    let _refresh_mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".to_owned(), "refresh_token".to_owned()),
            Matcher::UrlEncoded("client_id".to_owned(), "web".to_owned()),
            Matcher::UrlEncoded(
                "refresh_token".to_owned(),
                "synthetic-refresh-token".to_owned(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "access_token":"synthetic-refreshed-access-token",
                "expires_in":3600,
                "refresh_token":"synthetic-rotated-refresh-token",
                "token_type":"Bearer"
            }"#,
        )
        .create();

    let refresh_response = client
        .refresh_token(&RefreshTokenRequest::new("web", "synthetic-refresh-token"))
        .expect("refresh response should parse");

    assert_eq!(
        refresh_response.access_token.as_str(),
        "synthetic-refreshed-access-token"
    );
    assert_eq!(
        refresh_response.refresh_token.as_deref(),
        Some("synthetic-rotated-refresh-token")
    );
}

#[test]
fn api_key_token_request_uses_client_credentials_scope() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _token_mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".to_owned(), "client_credentials".to_owned()),
            Matcher::UrlEncoded("client_id".to_owned(), "organization.synthetic".to_owned()),
            Matcher::UrlEncoded(
                "client_secret".to_owned(),
                "synthetic-client-secret".to_owned(),
            ),
            Matcher::UrlEncoded("scope".to_owned(), "api.organization".to_owned()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "access_token":"synthetic-api-access-token",
                "expires_in":3600,
                "token_type":"Bearer",
                "Kdf":0,
                "KdfIterations":600000
            }"#,
        )
        .create();

    let response = ApiClient::new(endpoint)
        .exchange_api_key_token(&ApiKeyTokenRequest::new(
            "organization.synthetic",
            "synthetic-client-secret",
            Device::new(25, "Linux CLI", "synthetic-device-id"),
        ))
        .expect("api key token response should parse");

    assert_eq!(response.access_token.as_str(), "synthetic-api-access-token");
}

#[test]
fn sync_gets_api_endpoint_and_preserves_encrypted_envelope_fields() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _sync_mock = server
        .mock("GET", "/api/sync")
        .match_header("authorization", "Bearer synthetic-access-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "Profile":{"Email":"user@example.test","Name":"Synthetic User"},
                "Folders":[{"Id":"folder-1","Name":"2.encrypted-folder"}],
                "Collections":[],
                "Ciphers":[{"Id":"cipher-1","Name":"2.encrypted-cipher"}],
                "Domains":{"EquivalentDomains":[["example.com","example.org"]]},
                "Policies":[],
                "Sends":[{"Id":"send-1","Name":"2.encrypted-send"}],
                "UserDecryption":{"MasterPasswordUnlock":{"Kdf":0}}
            }"#,
        )
        .create();

    let response = ApiClient::new(endpoint)
        .sync("synthetic-access-token")
        .expect("sync response should parse");

    assert_eq!(
        response
            .profile
            .as_ref()
            .and_then(|profile| profile.get("Email")),
        Some(&serde_json::json!("user@example.test"))
    );
    assert_eq!(response.folders.len(), 1);
    assert_eq!(response.ciphers.len(), 1);
    assert_eq!(response.sends.len(), 1);
    assert!(response.user_decryption.is_some());
}

#[test]
fn api_client_errors_redact_tokens_and_client_secrets() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _refresh_mock = server
        .mock("POST", "/identity/connect/token")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "error":"invalid_grant",
                "error_description":"synthetic-refresh-token synthetic-client-secret"
            }"#,
        )
        .create();

    let error = ApiClient::new(endpoint)
        .refresh_token(&RefreshTokenRequest::new("web", "synthetic-refresh-token"))
        .expect_err("401 response should be an API client error");
    let rendered = format!("{error:?}\n{error}");

    for secret in ["synthetic-refresh-token", "synthetic-client-secret"] {
        assert!(
            !rendered.contains(secret),
            "API client error leaked secret {secret:?}: {rendered}"
        );
    }
    assert!(
        rendered.contains("/identity/connect/token"),
        "error should retain a redacted endpoint path for debugging: {rendered}"
    );
}
