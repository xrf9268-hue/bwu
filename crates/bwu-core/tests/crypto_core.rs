use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bwu_core::{
    crypto::{EncryptedString, KdfConfig, RsaEncryptedString, SymmetricKey, derive_master_key},
    redaction::SecretString,
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use coset::{
    Algorithm, CborSerializable, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

fn assert_secret_hex(secret: &bwu_core::crypto::SymmetricKey, expected_hex: &str) {
    let actual_hex = secret
        .expose_key()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(
        actual_hex == expected_hex,
        "derived key did not match the fixed synthetic vector"
    );
}

fn expected_argon2id_master_key(password: &SecretString, normalized_salt: &str) -> SymmetricKey {
    let salt_sha = Sha256::digest(normalized_salt.as_bytes());
    let params = Params::new(16 * 1024, 2, 1, Some(32)).expect("synthetic Argon2id params fit");
    let mut expected = Zeroizing::new([0_u8; 32]);
    Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(
            password.expose_secret().as_bytes(),
            &salt_sha,
            &mut *expected,
        )
        .expect("synthetic Argon2id vector should derive");
    SymmetricKey::new(expected.to_vec()).expect("expected vector length is valid")
}

fn pad_cose_key(mut encoded_key: Vec<u8>) -> Vec<u8> {
    let padding = 65_usize.saturating_sub(encoded_key.len()).max(1);
    assert!(padding <= u8::MAX as usize);
    let padded_len = encoded_key.len().saturating_add(padding).max(65);
    encoded_key.resize(
        padded_len,
        u8::try_from(padding).expect("padding should fit in one byte"),
    );
    encoded_key
}

fn synthetic_xchacha_key_bytes() -> [u8; 32] {
    (0x90_u8..=0xaf)
        .collect::<Vec<_>>()
        .try_into()
        .expect("synthetic XChaCha key should be 32 bytes")
}

fn synthetic_cose_key() -> Vec<u8> {
    let key = synthetic_xchacha_key_bytes();
    let key_id = b"synthetic-cose-key-id".to_vec();
    let mut cose_key = CoseKeyBuilder::new_symmetric_key(key.to_vec())
        .key_id(key_id)
        .add_key_op(iana::KeyOperation::Decrypt)
        .add_key_op(iana::KeyOperation::UnwrapKey)
        .build();
    cose_key.alg = Some(Algorithm::PrivateUse(-70_000));
    let cose_key = cose_key
        .to_vec()
        .expect("synthetic COSE key should serialize");
    pad_cose_key(cose_key)
}

fn synthetic_cose_encrypted_string(plaintext: &[u8]) -> String {
    let key = synthetic_xchacha_key_bytes();
    let key_id = b"synthetic-cose-key-id".to_vec();
    let nonce = b"synthetic-cose-nonce!!00";
    let mut protected = HeaderBuilder::new()
        .algorithm_label(Algorithm::PrivateUse(-70_000))
        .key_id(key_id)
        .content_type("application/x.bitwarden.utf8-padded".to_owned())
        .build();
    let mut ciphertext = plaintext.to_vec();
    let padding = 32 - (ciphertext.len() % 32);
    ciphertext.extend(std::iter::repeat_n(
        u8::try_from(padding).expect("padding should fit in one byte"),
        padding,
    ));

    let mut captured_aad = Vec::new();
    let message = CoseEncrypt0Builder::new()
        .protected(protected.clone())
        .create_ciphertext(&ciphertext, &[], |data, aad| {
            captured_aad = aad.to_vec();
            let mut buffer = data.to_vec();
            XChaCha20Poly1305::new((&key).into())
                .encrypt_in_place(nonce.into(), aad, &mut buffer)
                .expect("synthetic COSE fixture should encrypt");
            buffer
        })
        .unprotected(HeaderBuilder::new().iv(nonce.to_vec()).build())
        .build();

    assert!(
        !captured_aad.is_empty(),
        "COSE fixture should use the generated protected-header AAD"
    );
    protected.key_id.clear();
    assert_ne!(
        message.protected.header, protected,
        "COSE fixture should carry key id in the protected header"
    );

    format!(
        "7.{}",
        STANDARD.encode(
            message
                .to_vec()
                .expect("synthetic COSE Encrypt0 should serialize")
        )
    )
}

#[test]
fn crypto_core_kdf_vectors_cover_pbkdf2_and_argon2id() {
    let password = SecretString::new("synthetic-master-password");

    let pbkdf2 = derive_master_key(
        &password,
        "USER@example.com ",
        KdfConfig::pbkdf2_sha256(5_000),
    )
    .expect("PBKDF2 vector should derive");
    assert_secret_hex(
        &pbkdf2,
        "378d043bc158965246ff907225eaaf38478e9b204ed769e3e959a946be2d022e",
    );

    let argon2id = derive_master_key(
        &password,
        "synthetic-salt-16",
        KdfConfig::argon2id(2, 16, 1),
    )
    .expect("Argon2id vector should derive");
    assert_eq!(
        argon2id,
        expected_argon2id_master_key(&password, "synthetic-salt-16"),
        "Argon2id vector should hash the normalized salt before derivation"
    );
}

#[test]
fn crypto_core_rejects_weak_or_unsupported_kdf_parameters() {
    let password = SecretString::new("synthetic-master-password");

    for config in [
        KdfConfig::pbkdf2_sha256(4_999),
        KdfConfig::argon2id(1, 16, 1),
        KdfConfig::argon2id(2, 15, 1),
        KdfConfig::argon2id(2, 16, 0),
    ] {
        let err = derive_master_key(&password, "user@example.com", config)
            .expect_err("weak KDF parameters should fail closed");
        let rendered = format!("{err:?} {err}");
        assert!(
            !rendered.contains("synthetic-master-password"),
            "KDF error output leaked the master password"
        );
    }
}

#[test]
fn crypto_core_argon2id_normalizes_account_email_salt() {
    let password = SecretString::new("synthetic-master-password");
    let config = KdfConfig::argon2id(2, 16, 1);

    let normalized = derive_master_key(&password, "user@example.com", config)
        .expect("normalized Argon2id account salt should derive");
    let noisy = derive_master_key(&password, " USER@example.com ", config)
        .expect("case and whitespace variants should derive");

    assert_eq!(
        noisy, normalized,
        "Argon2id account-email salts should be normalized consistently with PBKDF2"
    );
}

#[test]
fn crypto_core_argon2id_uses_sha256_of_normalized_account_email_salt() {
    let password = SecretString::new("synthetic-master-password");
    let expected = expected_argon2id_master_key(&password, "user@example.com");

    let derived = derive_master_key(
        &password,
        " USER@example.com ",
        KdfConfig::argon2id(2, 16, 1),
    )
    .expect("Argon2id master key should derive");

    assert_eq!(
        derived, expected,
        "Argon2id should use SHA-256 of the normalized account email as the salt"
    );
}

#[test]
fn crypto_core_encrypted_string_parser_rejects_malformed_inputs() {
    let valid = EncryptedString::parse(
        "2.YWNjb3VudC1rZXktaXYhIQ==|tgMg75OxorP0hiI5rt3T6bDyt0s9tcvtRQ2FxRGj7HPCjRRW598dqnq1EeWw7Cc+2hzuoLyWr4ZyW5fIKUMqLvsUwwWXa4BZg2aW4vrlfDI=|UeL8DxxJsZpeuTAkas560WEcuosQCwHL6Rk6PwUlzyU=",
    )
    .expect("authenticated Bitwarden encrypted string should parse");
    assert_eq!(valid.encryption_type(), 2);

    for malformed in [
        "",
        "2.",
        "2.only-two|parts",
        "2.not-base64|also-not-base64|still-not-base64",
        "0.aW5pdC12ZWN0b3ItaXYh|Y2lwaGVydGV4dA==",
        "7.Y29zZS1kYXRh",
        "not-a-number.payload",
        "2.YWNjb3VudC1rZXktaXYhIQ==|tgMg75OxorP0hiI5rt3T6bDyt0s9tcvtRQ2FxRGj7HPCjRRW598dqnq1EeWw7Cc+2hzuoLyWr4ZyW5fIKUMqLvsUwwWXa4BZg2aW4vrlfDI=|UeL8DxxJsZpeuTAkas560WEcuosQCwHL6Rk6PwUlzyU=|extra",
    ] {
        let err = EncryptedString::parse(malformed)
            .expect_err("malformed encrypted strings should fail closed");
        let rendered = format!("{err:?} {err}");
        if !malformed.is_empty() {
            assert!(
                !rendered.contains(malformed),
                "parse error output should not echo encrypted payloads"
            );
        }
    }
}

#[test]
fn crypto_core_accepts_current_cose_encrypted_strings_and_keys() {
    let encrypted = synthetic_cose_encrypted_string(b"synthetic COSE field");
    let parsed = EncryptedString::parse(&encrypted)
        .expect("type 7 COSE encrypted string should parse as a supported shape");
    assert_eq!(parsed.encryption_type(), 7);

    let key = SymmetricKey::new(synthetic_cose_key())
        .expect("padded COSE XChaCha key material should parse as a supported key");

    let rendered = format!("{parsed:?} {key:?}");
    for secret in [
        "synthetic COSE field",
        "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaav",
        "synthetic-cose-key-id",
    ] {
        assert!(
            !rendered.contains(secret),
            "COSE parser/key debug output leaked synthetic fixture material"
        );
    }
}

#[test]
fn crypto_core_rsa_encrypted_string_parser_accepts_official_rsa_oaep_shapes() {
    let sha256 = RsaEncryptedString::parse("3.cnNhLW9hZXAtc2hhMjU2LWZpeHR1cmU=")
        .expect("RSA-OAEP-SHA256 encrypted string should parse");
    assert_eq!(sha256.encryption_type(), 3);

    let sha1 = RsaEncryptedString::parse("4.cnNhLW9hZXAtc2hhMS1maXh0dXJl")
        .expect("RSA-OAEP-SHA1 encrypted string should parse");
    assert_eq!(sha1.encryption_type(), 4);

    let legacy_sha256 =
        RsaEncryptedString::parse("5.cnNhLW9hZXAtc2hhMjU2LWZpeHR1cmU=|bGVnYWN5LW1hYw==")
            .expect("legacy RSA-OAEP-SHA256-HMAC encrypted string should parse");
    assert_eq!(legacy_sha256.encryption_type(), 5);

    let legacy_sha1 = RsaEncryptedString::parse("6.cnNhLW9hZXAtc2hhMS1maXh0dXJl|bGVnYWN5LW1hYw==")
        .expect("legacy RSA-OAEP-SHA1-HMAC encrypted string should parse");
    assert_eq!(legacy_sha1.encryption_type(), 6);

    for malformed in [
        "2.YWNjb3VudC1rZXktaXYhIQ==|ciphertext|mac",
        "3.not-base64",
        "3.cGF5bG9hZA==|unexpected-mac",
        "5.cGF5bG9hZA==",
        "5.cGF5bG9hZA==|not-base64",
        "5.cGF5bG9hZA==|bWFj|extra",
        "7.cGF5bG9hZA==",
    ] {
        let err = RsaEncryptedString::parse(malformed)
            .expect_err("malformed or unsupported RSA encrypted strings should fail closed");
        let rendered = format!("{err:?} {err}");
        assert!(
            !rendered.contains(malformed),
            "RSA parse error output should not echo encrypted payloads"
        );
    }
}
