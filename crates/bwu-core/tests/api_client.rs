use bwu_core::api::{
    ApiClient, ApiKeyTokenRequest, Device, EndpointConfig, PasswordTokenRequest, PreloginRequest,
    RefreshTokenRequest, SecretString, TokenResponse, TwoFactorProvider, TwoFactorToken,
};
use mockito::{Matcher, Server};

#[test]
fn secret_string_has_zeroizing_drop_contract() {
    fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroizes_on_drop::<SecretString>();
}

#[test]
fn device_model_constructs_and_redacts_identifier() {
    let device = Device::new(25, "Linux CLI", "synthetic-device-id");
    let rendered = format!("{device:?}");

    assert!(
        rendered.contains("Linux CLI"),
        "Device debug should retain non-secret device name for diagnostics: {rendered}"
    );
    assert!(
        !rendered.contains("synthetic-device-id"),
        "Device debug leaked the device identifier: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "Device debug should make identifier redaction visible: {rendered}"
    );
}

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
fn endpoint_model_preserves_path_roots_without_trailing_slash() {
    let self_hosted = EndpointConfig::self_hosted("https://vault.example.test/bw")
        .expect("valid self-hosted subpath URL");
    assert_eq!(
        self_hosted.prelogin_url().as_str(),
        "https://vault.example.test/bw/identity/accounts/prelogin/password"
    );
    assert_eq!(
        self_hosted.sync_url(false).as_str(),
        "https://vault.example.test/bw/api/sync"
    );

    let custom = EndpointConfig::custom(
        "https://vault.example.test/root",
        "https://vault.example.test/root/api",
        "https://vault.example.test/root/identity",
    )
    .expect("valid custom subpath URLs");
    assert_eq!(
        custom.token_url().as_str(),
        "https://vault.example.test/root/identity/connect/token"
    );
    assert_eq!(
        custom.sync_url(false).as_str(),
        "https://vault.example.test/root/api/sync"
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
fn prelogin_parses_lower_camel_response_fields() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _mock = server
        .mock("POST", "/identity/accounts/prelogin/password")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}"#)
        .create();

    let response = ApiClient::new(endpoint)
        .prelogin(&PreloginRequest::new("user@example.test"))
        .expect("lower-camel prelogin response should parse");

    assert_eq!(response.kdf, 1);
    assert_eq!(response.kdf_iterations, 3);
    assert_eq!(response.kdf_memory, Some(64));
    assert_eq!(response.kdf_parallelism, Some(4));
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
fn password_token_request_serializes_two_factor_retry_fields_and_redacts_token() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let device = Device::new(25, "Linux CLI", "synthetic-device-id");
    let request = PasswordTokenRequest::new(
        "user@example.test",
        "synthetic-master-hash",
        "synthetic-client-id",
        device,
    )
    .with_two_factor(TwoFactorToken::new(
        TwoFactorProvider::Authenticator,
        "synthetic-two-factor-code",
        true,
    ));
    let rendered = format!("{request:?}");

    assert!(
        !rendered.contains("synthetic-two-factor-code"),
        "PasswordTokenRequest debug leaked two-factor token: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "PasswordTokenRequest debug should make two-factor token redaction visible: {rendered}"
    );

    let _token_mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".to_owned(), "password".to_owned()),
            Matcher::UrlEncoded("client_id".to_owned(), "synthetic-client-id".to_owned()),
            Matcher::UrlEncoded("username".to_owned(), "user@example.test".to_owned()),
            Matcher::UrlEncoded("password".to_owned(), "synthetic-master-hash".to_owned()),
            Matcher::UrlEncoded(
                "twoFactorToken".to_owned(),
                "synthetic-two-factor-code".to_owned(),
            ),
            Matcher::UrlEncoded("twoFactorProvider".to_owned(), "0".to_owned()),
            Matcher::UrlEncoded("twoFactorRemember".to_owned(), "1".to_owned()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "access_token":"synthetic-access-token",
                "expires_in":3600,
                "refresh_token":"synthetic-refresh-token",
                "token_type":"Bearer"
            }"#,
        )
        .create();

    let response = ApiClient::new(endpoint)
        .exchange_password_token(&request)
        .expect("two-factor password token response should parse");

    assert_eq!(response.access_token.as_str(), "synthetic-access-token");
}

#[test]
fn token_response_debug_redacts_nested_user_decryption_options() {
    let response: TokenResponse = serde_json::from_str(
        r#"{
            "access_token":"synthetic-access-token",
            "expires_in":3600,
            "refresh_token":"synthetic-refresh-token",
            "token_type":"Bearer",
            "UserDecryptionOptions":{
                "HasMasterPassword":true,
                "TrustedDeviceOption":{
                    "HasAdminApproval":true,
                    "HasLoginApprovingDevice":true,
                    "HasManageResetPasswordPermission":false,
                    "IsTdeOffboarding":false,
                    "EncryptedPrivateKey":"2.synthetic-trusted-device-private-key",
                    "EncryptedUserKey":"2.synthetic-trusted-device-user-key"
                },
                "WebAuthnPrfOption":{
                    "EncryptedPrivateKey":"2.synthetic-prf-private-key",
                    "EncryptedUserKey":"2.synthetic-prf-user-key",
                    "CredentialId":"synthetic-credential-id",
                    "Transports":["usb"]
                }
            }
        }"#,
    )
    .expect("token response should parse nested decryption options");

    let rendered = format!("{response:?}");

    for secret in [
        "2.synthetic-trusted-device-private-key",
        "2.synthetic-trusted-device-user-key",
        "2.synthetic-prf-private-key",
        "2.synthetic-prf-user-key",
    ] {
        assert!(
            !rendered.contains(secret),
            "TokenResponse debug leaked nested secret {secret:?}: {rendered}"
        );
    }
    assert!(
        rendered.contains("<redacted>"),
        "TokenResponse debug should make nested secret redaction visible: {rendered}"
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
fn sync_parses_lower_camel_envelope_fields() {
    let mut server = Server::new();
    let endpoint = EndpointConfig::self_hosted(server.url()).expect("mock server URL is valid");
    let _sync_mock = server
        .mock("GET", "/api/sync")
        .match_header("authorization", "Bearer synthetic-access-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "profile":{"email":"user@example.test","name":"Synthetic User"},
                "folders":[{"id":"folder-1","name":"2.encrypted-folder"}],
                "collections":[{"id":"collection-1","name":"2.encrypted-collection"}],
                "ciphers":[{"id":"cipher-1","name":"2.encrypted-cipher"}],
                "domains":{"equivalentDomains":[["example.com","example.org"]]},
                "policies":[{"id":"policy-1"}],
                "policiesNew":[{"id":"policy-new-1"}],
                "sends":[{"id":"send-1","name":"2.encrypted-send"}],
                "userDecryption":{"masterPasswordUnlock":{"kdf":0}}
            }"#,
        )
        .create();

    let response = ApiClient::new(endpoint)
        .sync("synthetic-access-token")
        .expect("lower-camel sync response should parse");

    assert_eq!(
        response
            .profile
            .as_ref()
            .and_then(|profile| profile.get("email")),
        Some(&serde_json::json!("user@example.test"))
    );
    assert_eq!(response.folders.len(), 1);
    assert_eq!(response.collections.len(), 1);
    assert_eq!(response.ciphers.len(), 1);
    assert!(response.domains.is_some());
    assert_eq!(response.policies.len(), 1);
    assert_eq!(
        response.policies_new.as_ref().map(Vec::len),
        Some(1),
        "policiesNew should preserve the optional lower-camel policy envelope"
    );
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
