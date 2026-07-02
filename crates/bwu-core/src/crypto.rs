//! Bitwarden-compatible cryptographic primitives for local vault decryption.
//!
//! This module implements the small M3 read path needed by `bwu`: KDF handling,
//! authenticated encrypted-string parsing/decryption, and explicit key unwrap
//! flows for account, organization, item, and field data. It fails closed on
//! unknown encryption formats rather than silently attempting unsafe
//! compatibility behavior.

use std::{collections::BTreeMap, fmt};

use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use ciborium::Value;
use coset::{
    Algorithm as CoseAlgorithm, CborSerializable, CoseEncrypt0, CoseKey, Label, RegisteredLabel,
    iana,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openssl::{
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::redaction::SecretString;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

const AES_CBC_256_HMAC_SHA256: u8 = 2;
const COSE_ENCRYPT0: u8 = 7;
const RSA_2048_OAEP_SHA256: u8 = 3;
const RSA_2048_OAEP_SHA1: u8 = 4;
const RSA_2048_OAEP_SHA256_HMAC_SHA256: u8 = 5;
const RSA_2048_OAEP_SHA1_HMAC_SHA256: u8 = 6;
const XCHACHA20_POLY1305: i64 = -70_000;
const AES_KEY_LEN: usize = 32;
const SYMMETRIC_HMAC_KEY_LEN: usize = 64;
const AES_BLOCK_LEN: usize = 16;
const HMAC_SHA256_LEN: usize = 32;
const XCHACHA20_POLY1305_KEY_LEN: usize = 32;
const XCHACHA20_POLY1305_NONCE_LEN: usize = 24;
const MIN_COSE_ENCODED_KEY_LEN: usize = SYMMETRIC_HMAC_KEY_LEN + 1;
const BITWARDEN_PADDED_UTF8_CONTENT_TYPE: &str = "application/x.bitwarden.utf8-padded";
const PBKDF2_PRELOGIN_MIN_ITERATIONS: u32 = 5_000;
const PBKDF2_PRELOGIN_MAX_ITERATIONS: u32 = 2_000_000;
const ARGON2ID_PRELOGIN_MIN_ITERATIONS: u32 = 2;
const ARGON2ID_PRELOGIN_MIN_MEMORY_MIB: u32 = 16;
const ARGON2ID_PRELOGIN_MIN_PARALLELISM: u32 = 1;
const ARGON2ID_PRELOGIN_MAX_ITERATIONS: u32 = 10;
const ARGON2ID_PRELOGIN_MAX_MEMORY_MIB: u32 = 1_024;
const ARGON2ID_PRELOGIN_MAX_PARALLELISM: u32 = 16;

/// Errors from the crypto core.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CryptoError {
    /// KDF parameters are below Bitwarden-compatible pre-login minimums.
    InvalidKdfParameters,
    /// The wrapped key material has an unsupported byte length.
    InvalidKeyLength,
    /// The encrypted string does not match a supported authenticated format.
    InvalidEncryptedString,
    /// The encrypted string declares a disabled or unknown encryption type.
    UnsupportedEncryptionType,
    /// The encrypted string contains invalid base64.
    InvalidBase64,
    /// The IV is not an AES-CBC IV.
    InvalidIvLength,
    /// HMAC authentication failed.
    AuthenticationFailed,
    /// AES-CBC decryption or padding validation failed.
    DecryptionFailed,
    /// Decrypted field bytes were not valid UTF-8.
    InvalidUtf8,
    /// Decrypted RSA private key material could not be parsed.
    InvalidPrivateKey,
    /// An organization item referenced an organization key that is unavailable.
    MissingOrganizationKey,
    /// An encrypted vault item contained duplicate field names.
    DuplicateFieldName,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidKdfParameters => "invalid KDF parameters",
            Self::InvalidKeyLength => "invalid key length",
            Self::InvalidEncryptedString => "invalid encrypted string",
            Self::UnsupportedEncryptionType => "unsupported encryption type",
            Self::InvalidBase64 => "invalid encrypted string encoding",
            Self::InvalidIvLength => "invalid encrypted string IV",
            Self::AuthenticationFailed => "encrypted string authentication failed",
            Self::DecryptionFailed => "encrypted string decryption failed",
            Self::InvalidUtf8 => "decrypted field is not valid UTF-8",
            Self::InvalidPrivateKey => "invalid RSA private key",
            Self::MissingOrganizationKey => "missing organization key",
            Self::DuplicateFieldName => "duplicate encrypted field name",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CryptoError {}

/// Supported Bitwarden KDF configurations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KdfConfig {
    /// PBKDF2-HMAC-SHA256 with the server-provided iteration count.
    Pbkdf2Sha256 { iterations: u32 },
    /// Argon2id with Bitwarden-style MiB memory units.
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl KdfConfig {
    /// Builds a PBKDF2-SHA256 KDF config.
    #[must_use]
    pub fn pbkdf2_sha256(iterations: u32) -> Self {
        Self::Pbkdf2Sha256 { iterations }
    }

    /// Builds an Argon2id KDF config.
    #[must_use]
    pub fn argon2id(iterations: u32, memory_mib: u32, parallelism: u32) -> Self {
        Self::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        }
    }

    fn validate(self) -> Result<(), CryptoError> {
        match self {
            Self::Pbkdf2Sha256 { iterations }
                if (PBKDF2_PRELOGIN_MIN_ITERATIONS..=PBKDF2_PRELOGIN_MAX_ITERATIONS)
                    .contains(&iterations) =>
            {
                Ok(())
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } if (ARGON2ID_PRELOGIN_MIN_ITERATIONS..=ARGON2ID_PRELOGIN_MAX_ITERATIONS)
                .contains(&iterations)
                && (ARGON2ID_PRELOGIN_MIN_MEMORY_MIB..=ARGON2ID_PRELOGIN_MAX_MEMORY_MIB)
                    .contains(&memory_mib)
                && (ARGON2ID_PRELOGIN_MIN_PARALLELISM..=ARGON2ID_PRELOGIN_MAX_PARALLELISM)
                    .contains(&parallelism) =>
            {
                Ok(())
            }
            Self::Pbkdf2Sha256 { .. } | Self::Argon2id { .. } => {
                Err(CryptoError::InvalidKdfParameters)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoError, KdfConfig};

    #[test]
    fn argon2id_prelogin_validation_rejects_oversized_metadata_before_hashing() {
        for config in [
            KdfConfig::argon2id(11, 16, 1),
            KdfConfig::argon2id(2, 1_025, 1),
            KdfConfig::argon2id(2, 16, 17),
        ] {
            assert_eq!(
                config.validate(),
                Err(CryptoError::InvalidKdfParameters),
                "oversized Argon2id pre-login metadata should fail before hashing"
            );
        }
    }

    #[test]
    fn pbkdf2_prelogin_validation_rejects_oversized_iterations_before_hashing() {
        for iterations in [2_000_001, u32::MAX] {
            let err = KdfConfig::pbkdf2_sha256(iterations)
                .validate()
                .expect_err("oversized PBKDF2 pre-login metadata should fail before hashing");
            assert_eq!(err, CryptoError::InvalidKdfParameters);

            let rendered = format!("{err:?} {err}");
            assert!(
                !rendered.contains(&iterations.to_string()),
                "PBKDF2 KDF error output should not echo untrusted metadata"
            );
            assert!(
                !rendered.contains("synthetic-master-password"),
                "PBKDF2 KDF error output should not echo password material"
            );
        }
    }
}

/// Zeroizing symmetric key material.
#[derive(Clone, Eq, PartialEq)]
pub struct SymmetricKey {
    material: SymmetricKeyMaterial,
}

#[derive(Clone, Eq, PartialEq)]
enum SymmetricKeyMaterial {
    Legacy(Zeroizing<Vec<u8>>),
    XChaCha20Poly1305 {
        key: Zeroizing<Vec<u8>>,
        key_id: Vec<u8>,
    },
}

impl SymmetricKey {
    /// Wraps raw Bitwarden symmetric key bytes.
    pub fn new(key: impl Into<Vec<u8>>) -> Result<Self, CryptoError> {
        let key = key.into();
        match key.len() {
            AES_KEY_LEN | SYMMETRIC_HMAC_KEY_LEN => Ok(Self {
                material: SymmetricKeyMaterial::Legacy(Zeroizing::new(key)),
            }),
            MIN_COSE_ENCODED_KEY_LEN.. => {
                let (key, key_id) = parse_padded_cose_symmetric_key(&key)?;
                Ok(Self {
                    material: SymmetricKeyMaterial::XChaCha20Poly1305 { key, key_id },
                })
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    /// Exposes key bytes to deliberate crypto call sites.
    #[must_use]
    pub fn expose_key(&self) -> &[u8] {
        match &self.material {
            SymmetricKeyMaterial::Legacy(key) => key,
            SymmetricKeyMaterial::XChaCha20Poly1305 { key, .. } => key,
        }
    }

    fn aes_hmac_parts(&self) -> Result<(&[u8], &[u8]), CryptoError> {
        match &self.material {
            SymmetricKeyMaterial::Legacy(key) if key.len() == SYMMETRIC_HMAC_KEY_LEN => {
                Ok(key.split_at(AES_KEY_LEN))
            }
            SymmetricKeyMaterial::Legacy(_) | SymmetricKeyMaterial::XChaCha20Poly1305 { .. } => {
                Err(CryptoError::InvalidKeyLength)
            }
        }
    }

    fn xchacha20_poly1305_parts(&self) -> Result<(&[u8], &[u8]), CryptoError> {
        match &self.material {
            SymmetricKeyMaterial::XChaCha20Poly1305 { key, key_id } => {
                if key.len() != XCHACHA20_POLY1305_KEY_LEN {
                    return Err(CryptoError::InvalidKeyLength);
                }
                Ok((key, key_id))
            }
            SymmetricKeyMaterial::Legacy(_) => Err(CryptoError::InvalidKeyLength),
        }
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SymmetricKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Parsed authenticated Bitwarden encrypted string.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedString {
    encryption_type: u8,
    payload: EncryptedStringPayload,
}

#[derive(Clone, Eq, PartialEq)]
enum EncryptedStringPayload {
    AesCbcHmac {
        iv: Vec<u8>,
        data: Vec<u8>,
        mac: Vec<u8>,
    },
    CoseEncrypt0 {
        data: Vec<u8>,
    },
}

struct ParsedAesCbcHmacString {
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedString {
    /// Parses a serialized Bitwarden encrypted string.
    ///
    /// Only authenticated AES-CBC-HMAC strings are accepted for local vault
    /// decryption. Legacy unauthenticated AES-CBC and unknown formats fail
    /// closed.
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let (prefix, payload) = value
            .split_once('.')
            .ok_or(CryptoError::InvalidEncryptedString)?;
        let encryption_type = prefix
            .parse::<u8>()
            .map_err(|_| CryptoError::InvalidEncryptedString)?;

        let payload = match encryption_type {
            AES_CBC_256_HMAC_SHA256 => {
                let parsed = parse_aes_cbc_hmac_payload(payload)?;
                EncryptedStringPayload::AesCbcHmac {
                    iv: parsed.iv,
                    data: parsed.data,
                    mac: parsed.mac,
                }
            }
            COSE_ENCRYPT0 => {
                if payload.contains('|') || payload.is_empty() {
                    return Err(CryptoError::InvalidEncryptedString);
                }
                let data = STANDARD
                    .decode(payload)
                    .map_err(|_| CryptoError::InvalidBase64)?;
                CoseEncrypt0::from_slice(&data).map_err(|_| CryptoError::InvalidEncryptedString)?;
                EncryptedStringPayload::CoseEncrypt0 { data }
            }
            _ => return Err(CryptoError::UnsupportedEncryptionType),
        };

        Ok(Self {
            encryption_type,
            payload,
        })
    }

    /// Returns the numeric Bitwarden encryption type.
    #[must_use]
    pub fn encryption_type(&self) -> u8 {
        self.encryption_type
    }
}

impl fmt::Debug for EncryptedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedString")
            .field("encryption_type", &self.encryption_type)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Parsed Bitwarden RSA encrypted string.
#[derive(Clone, Eq, PartialEq)]
pub struct RsaEncryptedString {
    encryption_type: u8,
    data: Vec<u8>,
}

impl RsaEncryptedString {
    /// Parses a serialized Bitwarden RSA encrypted string.
    ///
    /// Organization keys are protected with the user's RSA public key in
    /// RSA-OAEP encrypted strings. Current type 3/4 strings carry one
    /// ciphertext payload; deprecated type 5/6 strings carry the same
    /// ciphertext plus a legacy MAC payload.
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let (prefix, payload) = value
            .split_once('.')
            .ok_or(CryptoError::InvalidEncryptedString)?;
        let encryption_type = prefix
            .parse::<u8>()
            .map_err(|_| CryptoError::InvalidEncryptedString)?;

        let data = match encryption_type {
            RSA_2048_OAEP_SHA256 | RSA_2048_OAEP_SHA1 => {
                if payload.contains('|') {
                    return Err(CryptoError::InvalidEncryptedString);
                }
                STANDARD
                    .decode(payload)
                    .map_err(|_| CryptoError::InvalidBase64)?
            }
            RSA_2048_OAEP_SHA256_HMAC_SHA256 | RSA_2048_OAEP_SHA1_HMAC_SHA256 => {
                let mut pieces = payload.split('|');
                let data = pieces.next().ok_or(CryptoError::InvalidEncryptedString)?;
                let mac = pieces.next().ok_or(CryptoError::InvalidEncryptedString)?;
                if pieces.next().is_some() {
                    return Err(CryptoError::InvalidEncryptedString);
                }

                let data = STANDARD
                    .decode(data)
                    .map_err(|_| CryptoError::InvalidBase64)?;
                let mac = STANDARD
                    .decode(mac)
                    .map_err(|_| CryptoError::InvalidBase64)?;
                if mac.is_empty() {
                    return Err(CryptoError::InvalidEncryptedString);
                }
                data
            }
            _ => return Err(CryptoError::UnsupportedEncryptionType),
        };
        if data.is_empty() {
            return Err(CryptoError::InvalidEncryptedString);
        }

        Ok(Self {
            encryption_type,
            data,
        })
    }

    /// Returns the numeric Bitwarden encryption type.
    #[must_use]
    pub fn encryption_type(&self) -> u8 {
        self.encryption_type
    }
}

impl fmt::Debug for RsaEncryptedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaEncryptedString")
            .field("encryption_type", &self.encryption_type)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Zeroizing RSA private-key material decrypted from the account key.
pub struct RsaPrivateKeyMaterial {
    key: Zeroizing<Vec<u8>>,
}

impl RsaPrivateKeyMaterial {
    fn from_decrypted_bytes(key: Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        parse_private_key_bytes(&key)?;
        Ok(Self { key })
    }

    fn parse(&self) -> Result<PKey<Private>, CryptoError> {
        parse_private_key_bytes(&self.key)
    }
}

impl fmt::Debug for RsaPrivateKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RsaPrivateKeyMaterial")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Item categories required by M3 read-only decryption tests.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VaultItemType {
    /// Bitwarden login item.
    Login,
    /// Bitwarden secure note item.
    SecureNote,
    /// Bitwarden card item.
    Card,
    /// Bitwarden identity item.
    Identity,
    /// Bitwarden SSH key item.
    SshKey,
    /// Passkey metadata stored on a vault item.
    PasskeyMetadata,
}

/// A named encrypted item field.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncryptedField {
    /// Stable field path for read-only command output.
    pub name: String,
    /// Encrypted field value.
    pub value: EncryptedString,
}

/// Minimal encrypted vault item shape for the M3 read path.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncryptedVaultItem {
    /// Item category.
    pub item_type: VaultItemType,
    /// Organization id when the item belongs to an organization.
    pub organization_id: Option<String>,
    /// Optional item key encrypted by the account or organization key.
    pub item_key: Option<EncryptedString>,
    /// Encrypted fields needed by read-only commands.
    pub fields: Vec<EncryptedField>,
}

/// Decryption keys available for an unlocked vault.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VaultKeys {
    /// Unlocked account key.
    pub account_key: SymmetricKey,
    /// Unlocked organization keys by organization id.
    pub organization_keys: BTreeMap<String, SymmetricKey>,
}

/// Decrypted read-only vault item.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecryptedVaultItem {
    /// Item category.
    pub item_type: VaultItemType,
    fields: BTreeMap<String, SecretString>,
}

impl DecryptedVaultItem {
    /// Returns a decrypted field by stable field path.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&SecretString> {
        self.fields.get(name)
    }
}

/// Derives a Bitwarden master key from a master password and salt.
///
/// KDF salts are account-email strings normalized the same way Bitwarden
/// normalizes them before key derivation.
pub fn derive_master_key(
    password: &SecretString,
    salt: &str,
    kdf: KdfConfig,
) -> Result<SymmetricKey, CryptoError> {
    kdf.validate()?;
    let normalized_salt = salt.trim().to_lowercase();
    let mut output = Zeroizing::new([0_u8; AES_KEY_LEN]);
    match kdf {
        KdfConfig::Pbkdf2Sha256 { iterations } => {
            pbkdf2_hmac::<Sha256>(
                password.expose_secret().as_bytes(),
                normalized_salt.as_bytes(),
                iterations,
                &mut *output,
            );
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or(CryptoError::InvalidKdfParameters)?;
            let params = Params::new(memory_kib, iterations, parallelism, Some(AES_KEY_LEN))
                .map_err(|_| CryptoError::InvalidKdfParameters)?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(
                    password.expose_secret().as_bytes(),
                    normalized_salt.as_bytes(),
                    &mut *output,
                )
                .map_err(|_| CryptoError::InvalidKdfParameters)?;
        }
    }
    SymmetricKey::new(output.to_vec())
}

/// Stretches a 256-bit master key into Bitwarden's 512-bit enc/mac key.
pub fn stretch_key(key: &SymmetricKey) -> Result<SymmetricKey, CryptoError> {
    if key.expose_key().len() != AES_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let hkdf =
        Hkdf::<Sha256>::from_prk(key.expose_key()).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut stretched = Zeroizing::new(vec![0_u8; SYMMETRIC_HMAC_KEY_LEN]);
    hkdf.expand(b"enc", &mut stretched[..AES_KEY_LEN])
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    hkdf.expand(b"mac", &mut stretched[AES_KEY_LEN..])
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    SymmetricKey::new(stretched.to_vec())
}

/// Decrypts the account key using the stretched master key.
pub fn decrypt_account_key(
    protected_account_key: &EncryptedString,
    stretched_master_key: &SymmetricKey,
) -> Result<SymmetricKey, CryptoError> {
    decrypt_symmetric_key(protected_account_key, stretched_master_key)
}

/// Decrypts a user's RSA private key using the already-unlocked account key.
pub fn decrypt_private_key(
    encrypted_private_key: &EncryptedString,
    account_key: &SymmetricKey,
) -> Result<RsaPrivateKeyMaterial, CryptoError> {
    let plaintext = decrypt_bytes(encrypted_private_key, account_key)?;
    RsaPrivateKeyMaterial::from_decrypted_bytes(plaintext)
}

/// Decrypts an organization key using the user's decrypted RSA private key.
pub fn decrypt_organization_key(
    encrypted_organization_key: &RsaEncryptedString,
    private_key: &RsaPrivateKeyMaterial,
) -> Result<SymmetricKey, CryptoError> {
    let private_key = private_key.parse()?;
    let digest = match encrypted_organization_key.encryption_type {
        RSA_2048_OAEP_SHA256 | RSA_2048_OAEP_SHA256_HMAC_SHA256 => Md::sha256(),
        RSA_2048_OAEP_SHA1 | RSA_2048_OAEP_SHA1_HMAC_SHA256 => Md::sha1(),
        _ => return Err(CryptoError::UnsupportedEncryptionType),
    };

    let mut context = PkeyCtx::new(&private_key).map_err(|_| CryptoError::DecryptionFailed)?;
    context
        .decrypt_init()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    context
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    context
        .set_rsa_oaep_md(digest)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    context
        .set_rsa_mgf1_md(digest)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut plaintext = Zeroizing::new(Vec::new());
    context
        .decrypt_to_vec(
            encrypted_organization_key.data.as_slice(),
            plaintext.as_mut(),
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    SymmetricKey::new(plaintext.to_vec())
}

/// Decrypts an item key using an account or organization wrapping key.
pub fn decrypt_item_key(
    encrypted_item_key: &EncryptedString,
    wrapping_key: &SymmetricKey,
) -> Result<SymmetricKey, CryptoError> {
    decrypt_symmetric_key(encrypted_item_key, wrapping_key)
}

/// Decrypts a UTF-8 field value using an item, account, or organization key.
pub fn decrypt_field(
    encrypted_field: &EncryptedString,
    key: &SymmetricKey,
) -> Result<SecretString, CryptoError> {
    let plaintext = decrypt_bytes(encrypted_field, key)?;
    let field = std::str::from_utf8(&plaintext).map_err(|_| CryptoError::InvalidUtf8)?;
    Ok(SecretString::new(field.to_owned()))
}

/// Decrypts all fields of a minimal vault item shape.
pub fn decrypt_vault_item(
    item: &EncryptedVaultItem,
    keys: &VaultKeys,
) -> Result<DecryptedVaultItem, CryptoError> {
    let wrapping_key = match &item.organization_id {
        Some(organization_id) => keys
            .organization_keys
            .get(organization_id)
            .ok_or(CryptoError::MissingOrganizationKey)?,
        None => &keys.account_key,
    };

    let field_key = match &item.item_key {
        Some(item_key) => decrypt_item_key(item_key, wrapping_key)?,
        None => wrapping_key.clone(),
    };

    let mut fields = BTreeMap::new();
    for field in &item.fields {
        let decrypted = decrypt_field(&field.value, &field_key)?;
        if fields.insert(field.name.clone(), decrypted).is_some() {
            return Err(CryptoError::DuplicateFieldName);
        }
    }

    Ok(DecryptedVaultItem {
        item_type: item.item_type,
        fields,
    })
}

fn decrypt_symmetric_key(
    encrypted_key: &EncryptedString,
    wrapping_key: &SymmetricKey,
) -> Result<SymmetricKey, CryptoError> {
    let plaintext = decrypt_bytes(encrypted_key, wrapping_key)?;
    SymmetricKey::new(plaintext.to_vec())
}

fn parse_private_key_bytes(key: &[u8]) -> Result<PKey<Private>, CryptoError> {
    let private_key = PKey::private_key_from_der(key)
        .or_else(|_| PKey::private_key_from_pem(key))
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    let rsa = private_key
        .rsa()
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    PKey::from_rsa(rsa).map_err(|_| CryptoError::InvalidPrivateKey)
}

fn decrypt_bytes(
    encrypted: &EncryptedString,
    key: &SymmetricKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match &encrypted.payload {
        EncryptedStringPayload::AesCbcHmac { iv, data, mac } => {
            let (enc_key, mac_key) = key.aes_hmac_parts()?;

            let mut hmac =
                HmacSha256::new_from_slice(mac_key).map_err(|_| CryptoError::InvalidKeyLength)?;
            hmac.update(iv);
            hmac.update(data);
            hmac.verify_slice(mac)
                .map_err(|_| CryptoError::AuthenticationFailed)?;

            let decryptor = Aes256CbcDecryptor::new_from_slices(enc_key, iv)
                .map_err(|_| CryptoError::InvalidIvLength)?;
            let plaintext = decryptor
                .decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|_| CryptoError::DecryptionFailed)?;
            Ok(Zeroizing::new(plaintext))
        }
        EncryptedStringPayload::CoseEncrypt0 { data } => decrypt_cose_encrypt0_bytes(data, key),
    }
}

fn parse_aes_cbc_hmac_payload(payload: &str) -> Result<ParsedAesCbcHmacString, CryptoError> {
    let mut pieces = payload.split('|');
    let iv = pieces.next().ok_or(CryptoError::InvalidEncryptedString)?;
    let data = pieces.next().ok_or(CryptoError::InvalidEncryptedString)?;
    let mac = pieces.next().ok_or(CryptoError::InvalidEncryptedString)?;
    if pieces.next().is_some() {
        return Err(CryptoError::InvalidEncryptedString);
    }

    let iv = STANDARD
        .decode(iv)
        .map_err(|_| CryptoError::InvalidBase64)?;
    let data = STANDARD
        .decode(data)
        .map_err(|_| CryptoError::InvalidBase64)?;
    let mac = STANDARD
        .decode(mac)
        .map_err(|_| CryptoError::InvalidBase64)?;

    if iv.len() != AES_BLOCK_LEN {
        return Err(CryptoError::InvalidIvLength);
    }
    if mac.len() != HMAC_SHA256_LEN || data.is_empty() || data.len() % AES_BLOCK_LEN != 0 {
        return Err(CryptoError::InvalidEncryptedString);
    }

    Ok(ParsedAesCbcHmacString { iv, data, mac })
}

fn decrypt_cose_encrypt0_bytes(
    data: &[u8],
    key: &SymmetricKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let message =
        CoseEncrypt0::from_slice(data).map_err(|_| CryptoError::InvalidEncryptedString)?;
    if message.protected.header.alg != Some(CoseAlgorithm::PrivateUse(XCHACHA20_POLY1305)) {
        return Err(CryptoError::UnsupportedEncryptionType);
    }

    let (xchacha_key, key_id) = key.xchacha20_poly1305_parts()?;
    if message.protected.header.key_id.is_empty() || message.protected.header.key_id != key_id {
        return Err(CryptoError::AuthenticationFailed);
    }
    let nonce: &[u8; XCHACHA20_POLY1305_NONCE_LEN] = message
        .unprotected
        .iv
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidIvLength)?;
    let cipher_key: &[u8; XCHACHA20_POLY1305_KEY_LEN] = xchacha_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let is_padded_utf8 = cose_content_type_is_padded_utf8(&message)?;
    let plaintext = message.decrypt_ciphertext(
        &[],
        || CryptoError::InvalidEncryptedString,
        |ciphertext, aad| {
            let mut buffer = ciphertext.to_vec();
            XChaCha20Poly1305::new(cipher_key.into())
                .decrypt_in_place(nonce.into(), aad, &mut buffer)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            Ok(buffer)
        },
    )?;

    if is_padded_utf8 {
        Ok(Zeroizing::new(
            unpad_bitwarden_bytes(&plaintext)
                .map_err(|_| CryptoError::DecryptionFailed)?
                .to_vec(),
        ))
    } else {
        Ok(Zeroizing::new(plaintext))
    }
}

fn cose_content_type_is_padded_utf8(message: &CoseEncrypt0) -> Result<bool, CryptoError> {
    match message.protected.header.content_type.as_ref() {
        Some(RegisteredLabel::Text(value)) if value == BITWARDEN_PADDED_UTF8_CONTENT_TYPE => {
            Ok(true)
        }
        None => Err(CryptoError::InvalidEncryptedString),
        Some(_) => Err(CryptoError::UnsupportedEncryptionType),
    }
}

fn parse_padded_cose_symmetric_key(
    padded_key: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    let key_bytes = unpad_bitwarden_bytes(padded_key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let cose_key = CoseKey::from_slice(key_bytes).map_err(|_| CryptoError::InvalidKeyLength)?;
    if cose_key.kty != RegisteredLabel::Assigned(iana::KeyType::Symmetric)
        || cose_key.alg != Some(CoseAlgorithm::PrivateUse(XCHACHA20_POLY1305))
        || cose_key.key_id.is_empty()
    {
        return Err(CryptoError::InvalidKeyLength);
    }
    if !cose_key.key_ops.is_empty()
        && !cose_key
            .key_ops
            .contains(&RegisteredLabel::Assigned(iana::KeyOperation::Decrypt))
    {
        return Err(CryptoError::InvalidKeyLength);
    }

    let key = cose_key
        .params
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Int(label), Value::Bytes(bytes))
                if *label == iana::SymmetricKeyParameter::K as i64 =>
            {
                Some(bytes)
            }
            _ => None,
        })
        .ok_or(CryptoError::InvalidKeyLength)?;
    if key.len() != XCHACHA20_POLY1305_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    Ok((Zeroizing::new(key.clone()), cose_key.key_id))
}

fn unpad_bitwarden_bytes(padded: &[u8]) -> Result<&[u8], CryptoError> {
    let padding_len = usize::from(*padded.last().ok_or(CryptoError::InvalidEncryptedString)?);
    if padding_len == 0 || padding_len > padded.len() {
        return Err(CryptoError::InvalidEncryptedString);
    }
    let unpadded_len = padded.len() - padding_len;
    if !padded[unpadded_len..]
        .iter()
        .all(|byte| usize::from(*byte) == padding_len)
    {
        return Err(CryptoError::InvalidEncryptedString);
    }
    Ok(&padded[..unpadded_len])
}
