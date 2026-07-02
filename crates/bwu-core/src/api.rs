//! Bitwarden-compatible endpoint model and API client boundary.
//!
//! This module intentionally stops at encrypted/auth response envelopes. Later
//! milestones own key derivation, vault decryption, and command integration.

use std::{fmt, ops::Deref};

use reqwest::{StatusCode, blocking::Response};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned, ser::SerializeStruct};
use serde_json::Value;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const US_WEB_VAULT_URL: &str = "https://vault.bitwarden.com";
const US_API_URL: &str = "https://api.bitwarden.com";
const US_IDENTITY_URL: &str = "https://identity.bitwarden.com";
const EU_WEB_VAULT_URL: &str = "https://vault.bitwarden.eu";
const EU_API_URL: &str = "https://api.bitwarden.eu";
const EU_IDENTITY_URL: &str = "https://identity.bitwarden.eu";
const DEFAULT_SCOPE: &str = "api offline_access";

/// Redacted secret string used for token material and request secrets.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Creates a secret string from caller-provided material.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret for building an outbound protocol request.
    fn expose_for_request(&self) -> &str {
        self.as_str()
    }

    /// Exposes the value to callers that intentionally need token storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Bitwarden service endpoints for one account environment.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EndpointConfig {
    web_vault: Url,
    api: Url,
    identity: Url,
}

impl EndpointConfig {
    /// Official United States Bitwarden cloud endpoints.
    #[must_use]
    pub fn official_us() -> Self {
        Self::parse_known(US_WEB_VAULT_URL, US_API_URL, US_IDENTITY_URL)
    }

    /// Official European Union Bitwarden cloud endpoints.
    #[must_use]
    pub fn official_eu() -> Self {
        Self::parse_known(EU_WEB_VAULT_URL, EU_API_URL, EU_IDENTITY_URL)
    }

    /// Vaultwarden-compatible self-hosted endpoints derived from one base URL.
    ///
    /// A base of `https://vault.example.test` produces API and Identity roots
    /// at `/api/` and `/identity/`, matching the official client derivation for
    /// self-hosted environments.
    pub fn self_hosted(base_url: impl AsRef<str>) -> Result<Self, EndpointConfigError> {
        let web_vault = parse_base_url(base_url.as_ref())?;
        let api = web_vault
            .join("api/")
            .map_err(EndpointConfigError::invalid_url)?;
        let identity = web_vault
            .join("identity/")
            .map_err(EndpointConfigError::invalid_url)?;

        Ok(Self {
            web_vault,
            api,
            identity,
        })
    }

    /// Fully custom service roots for advanced/self-hosted deployments.
    pub fn custom(
        web_vault_url: impl AsRef<str>,
        api_url: impl AsRef<str>,
        identity_url: impl AsRef<str>,
    ) -> Result<Self, EndpointConfigError> {
        Ok(Self {
            web_vault: parse_base_url(web_vault_url.as_ref())?,
            api: parse_base_url(api_url.as_ref())?,
            identity: parse_base_url(identity_url.as_ref())?,
        })
    }

    /// Web vault root URL.
    #[must_use]
    pub fn web_vault_url(&self) -> &Url {
        &self.web_vault
    }

    /// API service root URL.
    #[must_use]
    pub fn api_url(&self) -> &Url {
        &self.api
    }

    /// Identity service root URL.
    #[must_use]
    pub fn identity_url(&self) -> &Url {
        &self.identity
    }

    /// Prelogin endpoint URL.
    #[must_use]
    pub fn prelogin_url(&self) -> Url {
        self.identity
            .join("accounts/prelogin/password")
            .expect("validated identity root should join prelogin path")
    }

    /// OAuth token endpoint URL.
    #[must_use]
    pub fn token_url(&self) -> Url {
        self.identity
            .join("connect/token")
            .expect("validated identity root should join token path")
    }

    /// Vault sync endpoint URL.
    #[must_use]
    pub fn sync_url(&self, exclude_domains: bool) -> Url {
        let mut url = self
            .api
            .join("sync")
            .expect("validated API root should join sync path");
        if exclude_domains {
            url.query_pairs_mut().append_pair("excludeDomains", "true");
        }
        url
    }

    fn parse_known(web_vault: &str, api: &str, identity: &str) -> Self {
        Self::custom(web_vault, api, identity)
            .expect("official Bitwarden endpoint constants should be valid")
    }
}

/// Endpoint configuration error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EndpointConfigError {
    message: String,
}

impl EndpointConfigError {
    fn invalid_url(source: url::ParseError) -> Self {
        Self {
            message: format!("invalid endpoint URL: {source}"),
        }
    }
}

impl fmt::Display for EndpointConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EndpointConfigError {}

fn parse_base_url(input: &str) -> Result<Url, EndpointConfigError> {
    let mut url = Url::parse(input).map_err(EndpointConfigError::invalid_url)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(EndpointConfigError {
            message: "endpoint URL must use http or https".to_owned(),
        });
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_owned();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

/// Request body for Bitwarden prelogin.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PreloginRequest {
    email: String,
}

impl PreloginRequest {
    /// Creates a prelogin request for an email address.
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
        }
    }
}

/// Response body for Bitwarden prelogin.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct PreloginResponse {
    /// KDF algorithm identifier from the server.
    #[serde(rename = "Kdf", alias = "kdf")]
    pub kdf: u32,
    /// PBKDF2 iterations or Argon2id iterations, depending on `kdf`.
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: u32,
    /// Argon2 memory parameter when returned by the server.
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    /// Argon2 parallelism parameter when returned by the server.
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

/// Device metadata attached to token requests.
#[derive(Clone, Eq, PartialEq)]
pub struct Device {
    device_type: u16,
    name: String,
    identifier: String,
}

impl Device {
    /// Creates device metadata for the Identity token request.
    #[must_use]
    pub fn new(device_type: u16, name: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            device_type,
            name: name.into(),
            identifier: identifier.into(),
        }
    }
}

impl fmt::Debug for Device {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Device")
            .field("device_type", &self.device_type)
            .field("name", &self.name)
            .field("identifier", &"<redacted>")
            .finish()
    }
}

/// Bitwarden two-step login provider identifiers accepted by Identity token requests.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TwoFactorProvider {
    /// Authenticator app code.
    Authenticator,
    /// Email-delivered code.
    Email,
    /// Individual Duo challenge.
    Duo,
    /// YubiKey OTP.
    YubiKey,
    /// Remembered-device token.
    Remember,
    /// Organization Duo challenge.
    OrganizationDuo,
    /// WebAuthn two-step login.
    WebAuthn,
    /// Account recovery code.
    RecoveryCode,
}

impl TwoFactorProvider {
    fn as_protocol_id(self) -> u8 {
        match self {
            Self::Authenticator => 0,
            Self::Email => 1,
            Self::Duo => 2,
            Self::YubiKey => 3,
            Self::Remember => 5,
            Self::OrganizationDuo => 6,
            Self::WebAuthn => 7,
            Self::RecoveryCode => 8,
        }
    }
}

/// Two-step login retry fields for a password-grant token exchange.
#[derive(Clone, Eq, PartialEq)]
pub struct TwoFactorToken {
    provider: TwoFactorProvider,
    token: SecretString,
    remember: bool,
}

impl TwoFactorToken {
    /// Creates two-step login retry material for a password token request.
    #[must_use]
    pub fn new(provider: TwoFactorProvider, token: impl Into<String>, remember: bool) -> Self {
        Self {
            provider,
            token: SecretString::new(token),
            remember,
        }
    }
}

impl fmt::Debug for TwoFactorToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoFactorToken")
            .field("provider", &self.provider)
            .field("token", &self.token)
            .field("remember", &self.remember)
            .finish()
    }
}

/// Password grant token request boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordTokenRequest {
    email: String,
    master_password_hash: SecretString,
    client_id: String,
    device: Device,
    two_factor: Option<TwoFactorToken>,
}

impl PasswordTokenRequest {
    /// Creates a password token request.
    #[must_use]
    pub fn new(
        email: impl Into<String>,
        master_password_hash: impl Into<String>,
        client_id: impl Into<String>,
        device: Device,
    ) -> Self {
        Self {
            email: email.into(),
            master_password_hash: SecretString::new(master_password_hash),
            client_id: client_id.into(),
            device,
            two_factor: None,
        }
    }

    /// Adds two-step login retry fields to a password token request.
    #[must_use]
    pub fn with_two_factor(mut self, two_factor: TwoFactorToken) -> Self {
        self.two_factor = Some(two_factor);
        self
    }

    fn form_pairs(&self) -> PasswordTokenForm<'_> {
        PasswordTokenForm { request: self }
    }
}

impl fmt::Debug for PasswordTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordTokenRequest")
            .field("email", &self.email)
            .field("master_password_hash", &self.master_password_hash)
            .field("client_id", &self.client_id)
            .field("device", &self.device)
            .field("two_factor", &self.two_factor)
            .finish()
    }
}

/// User or organization API-key token request boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ApiKeyTokenRequest {
    client_id: String,
    client_secret: SecretString,
    device: Device,
}

impl ApiKeyTokenRequest {
    /// Creates an API-key token request.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        device: Device,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: SecretString::new(client_secret),
            device,
        }
    }

    fn form_pairs(&self) -> ApiKeyTokenForm<'_> {
        ApiKeyTokenForm {
            request: self,
            scope: if self.client_id.starts_with("organization") {
                "api.organization"
            } else {
                "api"
            },
        }
    }
}

impl fmt::Debug for ApiKeyTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyTokenRequest")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("device", &self.device)
            .finish()
    }
}

/// Refresh-token request boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct RefreshTokenRequest {
    client_id: String,
    refresh_token: SecretString,
}

impl RefreshTokenRequest {
    /// Creates a refresh-token request.
    #[must_use]
    pub fn new(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            refresh_token: SecretString::new(refresh_token),
        }
    }

    fn form_pairs(&self) -> RefreshTokenForm<'_> {
        RefreshTokenForm { request: self }
    }
}

impl fmt::Debug for RefreshTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshTokenRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &self.refresh_token)
            .finish()
    }
}

struct PasswordTokenForm<'a> {
    request: &'a PasswordTokenRequest,
}

impl Serialize for PasswordTokenForm<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let field_count = if self.request.two_factor.is_some() {
            11
        } else {
            8
        };
        let mut form = serializer.serialize_struct("PasswordTokenForm", field_count)?;
        form.serialize_field("scope", DEFAULT_SCOPE)?;
        form.serialize_field("client_id", &self.request.client_id)?;
        form.serialize_field("grant_type", "password")?;
        form.serialize_field("username", &self.request.email)?;
        form.serialize_field(
            "password",
            self.request.master_password_hash.expose_for_request(),
        )?;
        serialize_device_form_fields(&mut form, &self.request.device)?;
        if let Some(two_factor) = &self.request.two_factor {
            form.serialize_field("twoFactorToken", two_factor.token.expose_for_request())?;
            form.serialize_field("twoFactorProvider", &two_factor.provider.as_protocol_id())?;
            form.serialize_field(
                "twoFactorRemember",
                if two_factor.remember { "1" } else { "0" },
            )?;
        }
        form.end()
    }
}

impl fmt::Debug for PasswordTokenForm<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordTokenForm")
            .field("scope", &DEFAULT_SCOPE)
            .field("client_id", &self.request.client_id)
            .field("grant_type", &"password")
            .field("username", &self.request.email)
            .field("password", &self.request.master_password_hash)
            .field("device", &self.request.device)
            .field("two_factor", &self.request.two_factor)
            .finish()
    }
}

struct ApiKeyTokenForm<'a> {
    request: &'a ApiKeyTokenRequest,
    scope: &'static str,
}

impl Serialize for ApiKeyTokenForm<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut form = serializer.serialize_struct("ApiKeyTokenForm", 7)?;
        form.serialize_field("scope", self.scope)?;
        form.serialize_field("client_id", &self.request.client_id)?;
        form.serialize_field(
            "client_secret",
            self.request.client_secret.expose_for_request(),
        )?;
        form.serialize_field("grant_type", "client_credentials")?;
        serialize_device_form_fields(&mut form, &self.request.device)?;
        form.end()
    }
}

impl fmt::Debug for ApiKeyTokenForm<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyTokenForm")
            .field("scope", &self.scope)
            .field("client_id", &self.request.client_id)
            .field("client_secret", &self.request.client_secret)
            .field("grant_type", &"client_credentials")
            .field("device", &self.request.device)
            .finish()
    }
}

struct RefreshTokenForm<'a> {
    request: &'a RefreshTokenRequest,
}

impl Serialize for RefreshTokenForm<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut form = serializer.serialize_struct("RefreshTokenForm", 3)?;
        form.serialize_field("grant_type", "refresh_token")?;
        form.serialize_field("client_id", &self.request.client_id)?;
        form.serialize_field(
            "refresh_token",
            self.request.refresh_token.expose_for_request(),
        )?;
        form.end()
    }
}

impl fmt::Debug for RefreshTokenForm<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshTokenForm")
            .field("grant_type", &"refresh_token")
            .field("client_id", &self.request.client_id)
            .field("refresh_token", &self.request.refresh_token)
            .finish()
    }
}

fn serialize_device_form_fields<S>(
    form: &mut S,
    device: &Device,
) -> Result<(), <S as SerializeStruct>::Error>
where
    S: SerializeStruct,
{
    form.serialize_field("deviceType", &device.device_type)?;
    form.serialize_field("deviceName", &device.name)?;
    form.serialize_field("deviceIdentifier", &device.identifier)?;
    Ok(())
}

/// Token response decryption options used by trusted-device and key-connector flows.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct UserDecryptionOptions {
    /// Whether the user has a master password available for vault decryption.
    #[serde(rename = "HasMasterPassword", alias = "hasMasterPassword")]
    pub has_master_password: Option<bool>,
    /// Master-password unlock envelope for the account user key.
    #[serde(rename = "MasterPasswordUnlock", alias = "masterPasswordUnlock")]
    pub master_password_unlock: Option<MasterPasswordUnlockOption>,
    /// WebAuthn PRF decryption envelope.
    #[serde(rename = "WebAuthnPrfOption", alias = "webAuthnPrfOption")]
    pub webauthn_prf_option: Option<WebAuthnPrfOption>,
    /// Trusted-device decryption envelope.
    #[serde(rename = "TrustedDeviceOption", alias = "trustedDeviceOption")]
    pub trusted_device_option: Option<TrustedDeviceOption>,
    /// Key Connector decryption envelope.
    #[serde(rename = "KeyConnectorOption", alias = "keyConnectorOption")]
    pub key_connector_option: Option<KeyConnectorOption>,
}

/// Master-password unlock decryption envelope.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct MasterPasswordUnlockOption {
    /// User key encrypted by the master key.
    #[serde(
        rename = "MasterKeyEncryptedUserKey",
        alias = "masterKeyEncryptedUserKey",
        alias = "MasterKeyWrappedUserKey",
        alias = "masterKeyWrappedUserKey"
    )]
    pub master_key_wrapped_user_key: Option<SecretString>,
}

/// Trusted-device decryption envelope.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct TrustedDeviceOption {
    /// Whether admin approval is available for trusted-device login.
    #[serde(rename = "HasAdminApproval", alias = "hasAdminApproval")]
    pub has_admin_approval: Option<bool>,
    /// Whether another trusted device can approve login.
    #[serde(rename = "HasLoginApprovingDevice", alias = "hasLoginApprovingDevice")]
    pub has_login_approving_device: Option<bool>,
    /// Whether the user can manage reset-password setup.
    #[serde(
        rename = "HasManageResetPasswordPermission",
        alias = "hasManageResetPasswordPermission"
    )]
    pub has_manage_reset_password_permission: Option<bool>,
    /// Whether trusted-device offboarding is in progress.
    #[serde(rename = "IsTdeOffboarding", alias = "isTdeOffboarding")]
    pub is_tde_offboarding: Option<bool>,
    /// Device-key-encrypted private key for a trusted device.
    #[serde(rename = "EncryptedPrivateKey", alias = "encryptedPrivateKey")]
    pub encrypted_private_key: Option<SecretString>,
    /// Public-key-encrypted user key for a trusted device.
    #[serde(rename = "EncryptedUserKey", alias = "encryptedUserKey")]
    pub encrypted_user_key: Option<SecretString>,
}

/// WebAuthn PRF decryption envelope.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct WebAuthnPrfOption {
    /// PRF-encrypted private key.
    #[serde(rename = "EncryptedPrivateKey", alias = "encryptedPrivateKey")]
    pub encrypted_private_key: SecretString,
    /// PRF-encrypted user key.
    #[serde(rename = "EncryptedUserKey", alias = "encryptedUserKey")]
    pub encrypted_user_key: SecretString,
    /// Credential identifier used by the WebAuthn PRF option.
    #[serde(rename = "CredentialId", alias = "credentialId")]
    pub credential_id: String,
    /// Authenticator transports reported for the credential.
    #[serde(rename = "Transports", alias = "transports", default)]
    pub transports: Vec<String>,
}

/// Key Connector decryption envelope.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct KeyConnectorOption {
    /// Key Connector service URL.
    #[serde(rename = "KeyConnectorUrl", alias = "keyConnectorUrl")]
    pub key_connector_url: String,
}

/// Successful Identity token response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct TokenResponse {
    /// Bearer access token.
    pub access_token: SecretString,
    /// Lifetime in seconds when returned by the server.
    pub expires_in: Option<u64>,
    /// Optional refresh token.
    pub refresh_token: Option<SecretString>,
    /// Token type, normally `Bearer`.
    pub token_type: String,
    /// User-key-encrypted private key.
    #[serde(rename = "PrivateKey")]
    pub private_key: Option<SecretString>,
    /// Master-key-encrypted user key.
    #[serde(rename = "Key")]
    pub key: Option<SecretString>,
    /// KDF algorithm identifier when included.
    #[serde(rename = "Kdf")]
    pub kdf: Option<u32>,
    /// KDF iteration count when included.
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: Option<u32>,
    /// Argon2 memory parameter when included.
    #[serde(rename = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    /// Argon2 parallelism parameter when included.
    #[serde(rename = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
    /// Whether the account must reset its password.
    #[serde(rename = "ForcePasswordReset")]
    pub force_password_reset: Option<bool>,
    /// Remembered two-factor bypass token.
    #[serde(rename = "TwoFactorToken")]
    pub two_factor_token: Option<SecretString>,
    /// API-key login Key Connector flag.
    #[serde(rename = "ApiUseKeyConnector")]
    pub api_use_key_connector: Option<bool>,
    /// User decryption options needed by later auth and crypto work.
    #[serde(rename = "UserDecryptionOptions")]
    pub user_decryption_options: Option<UserDecryptionOptions>,
    /// Master password policy envelope for later auth work.
    #[serde(rename = "MasterPasswordPolicy")]
    pub master_password_policy: Option<Value>,
}

/// Successful refresh-token response.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct RefreshTokenResponse {
    /// Bearer access token.
    pub access_token: SecretString,
    /// Lifetime in seconds when returned by the server.
    pub expires_in: Option<u64>,
    /// Optional rotated refresh token.
    pub refresh_token: Option<SecretString>,
    /// Token type, normally `Bearer`.
    pub token_type: String,
}

/// Encrypted sync envelope with top-level Bitwarden response sections.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SyncResponse {
    /// Profile envelope.
    #[serde(rename = "Profile", alias = "profile")]
    pub profile: Option<Value>,
    /// Folder envelopes.
    #[serde(rename = "Folders", alias = "folders", default)]
    pub folders: Vec<Value>,
    /// Collection envelopes.
    #[serde(rename = "Collections", alias = "collections", default)]
    pub collections: Vec<Value>,
    /// Cipher envelopes.
    #[serde(rename = "Ciphers", alias = "ciphers", default)]
    pub ciphers: Vec<Value>,
    /// Domain settings envelope.
    #[serde(rename = "Domains", alias = "domains")]
    pub domains: Option<Value>,
    /// Legacy policy envelopes.
    #[serde(rename = "Policies", alias = "policies", default)]
    pub policies: Vec<Value>,
    /// New policy envelopes when present.
    #[serde(rename = "PoliciesNew", alias = "policiesNew")]
    pub policies_new: Option<Vec<Value>>,
    /// Send envelopes.
    #[serde(rename = "Sends", alias = "sends", default)]
    pub sends: Vec<Value>,
    /// User decryption envelope.
    #[serde(rename = "UserDecryption", alias = "userDecryption")]
    pub user_decryption: Option<Value>,
}

/// Blocking API client boundary for Bitwarden-compatible endpoints.
#[derive(Debug, Clone)]
pub struct ApiClient {
    endpoint: EndpointConfig,
    http: reqwest::blocking::Client,
}

impl ApiClient {
    /// Creates an API client for the provided endpoint set.
    #[must_use]
    pub fn new(endpoint: EndpointConfig) -> Self {
        Self {
            endpoint,
            http: reqwest::blocking::Client::new(),
        }
    }

    /// Posts a prelogin request to the Identity service.
    pub fn prelogin(&self, request: &PreloginRequest) -> Result<PreloginResponse, ApiClientError> {
        let url = self.endpoint.prelogin_url();
        let response = self
            .http
            .post(url.clone())
            .json(request)
            .send()
            .map_err(|source| ApiClientError::transport("POST", &url, source))?;
        parse_json_response("POST", &url, response)
    }

    /// Exchanges password credentials for an Identity token response.
    pub fn exchange_password_token(
        &self,
        request: &PasswordTokenRequest,
    ) -> Result<TokenResponse, ApiClientError> {
        let form = request.form_pairs();
        self.post_token_form(&form)
    }

    /// Exchanges API-key credentials for an Identity token response.
    pub fn exchange_api_key_token(
        &self,
        request: &ApiKeyTokenRequest,
    ) -> Result<TokenResponse, ApiClientError> {
        let form = request.form_pairs();
        self.post_token_form(&form)
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh_token(
        &self,
        request: &RefreshTokenRequest,
    ) -> Result<RefreshTokenResponse, ApiClientError> {
        let url = self.endpoint.token_url();
        let form = request.form_pairs();
        let response = self
            .http
            .post(url.clone())
            .form(&form)
            .send()
            .map_err(|source| ApiClientError::transport("POST", &url, source))?;
        parse_json_response("POST", &url, response)
    }

    /// Fetches the encrypted sync envelope from the API service.
    pub fn sync(&self, access_token: &str) -> Result<SyncResponse, ApiClientError> {
        let url = self.endpoint.sync_url(false);
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(access_token)
            .send()
            .map_err(|source| ApiClientError::transport("GET", &url, source))?;
        parse_json_response("GET", &url, response)
    }

    fn post_token_form<T>(&self, form: &T) -> Result<TokenResponse, ApiClientError>
    where
        T: Serialize + ?Sized,
    {
        let url = self.endpoint.token_url();
        let response = self
            .http
            .post(url.clone())
            .form(form)
            .send()
            .map_err(|source| ApiClientError::transport("POST", &url, source))?;
        parse_json_response("POST", &url, response)
    }
}

/// Redacted API client error.
#[derive(Debug)]
pub enum ApiClientError {
    /// HTTP transport failed before a response was received.
    Transport {
        method: &'static str,
        path: String,
        source: reqwest::Error,
    },
    /// Server returned a non-success status.
    Status {
        method: &'static str,
        path: String,
        status: StatusCode,
    },
    /// Response body could not be decoded as the expected JSON envelope.
    Decode {
        method: &'static str,
        path: String,
        source: reqwest::Error,
    },
}

impl ApiClientError {
    fn transport(method: &'static str, url: &Url, source: reqwest::Error) -> Self {
        Self::Transport {
            method,
            path: redacted_path(url),
            source,
        }
    }

    fn decode(method: &'static str, url: &Url, source: reqwest::Error) -> Self {
        Self::Decode {
            method,
            path: redacted_path(url),
            source,
        }
    }

    fn status(method: &'static str, url: &Url, status: StatusCode) -> Self {
        Self::Status {
            method,
            path: redacted_path(url),
            status,
        }
    }
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { method, path, .. } => {
                write!(
                    formatter,
                    "{method} {path} failed before receiving a response"
                )
            }
            Self::Status {
                method,
                path,
                status,
            } => write!(formatter, "{method} {path} returned HTTP {status}"),
            Self::Decode { method, path, .. } => {
                write!(
                    formatter,
                    "{method} {path} returned an invalid JSON envelope"
                )
            }
        }
    }
}

impl std::error::Error for ApiClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } | Self::Decode { source, .. } => Some(source),
            Self::Status { .. } => None,
        }
    }
}

fn parse_json_response<T>(
    method: &'static str,
    url: &Url,
    response: Response,
) -> Result<T, ApiClientError>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        return Err(ApiClientError::status(method, url, status));
    }

    response
        .json::<T>()
        .map_err(|source| ApiClientError::decode(method, url, source))
}

fn redacted_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_form_material_debug_redacts_request_secrets() {
        let device = Device::new(25, "Linux CLI", "synthetic-device-id");
        let password_request = PasswordTokenRequest::new(
            "user@example.test",
            "synthetic-master-hash",
            "synthetic-client-id",
            device.clone(),
        );
        let password_form = password_request.form_pairs();
        let api_key_request =
            ApiKeyTokenRequest::new("organization.synthetic", "synthetic-client-secret", device);
        let api_key_form = api_key_request.form_pairs();
        let refresh_request = RefreshTokenRequest::new("web", "synthetic-refresh-token");
        let refresh_form = refresh_request.form_pairs();

        let rendered = format!("{password_form:?}\n{api_key_form:?}\n{refresh_form:?}");

        for secret in [
            "synthetic-master-hash",
            "synthetic-client-secret",
            "synthetic-refresh-token",
            "synthetic-device-id",
        ] {
            assert!(
                !rendered.contains(secret),
                "token form debug leaked request secret {secret:?}: {rendered}"
            );
        }
        assert!(
            rendered.contains("<redacted>"),
            "token form debug should show explicit redaction markers: {rendered}"
        );
    }
}
