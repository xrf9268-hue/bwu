use bwu_core::{
    crypto::{EncryptedString, KdfConfig, derive_master_key},
    redaction::SecretString,
};

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
    assert_secret_hex(
        &argon2id,
        "38cdf665340138c1f8554ea03cf23789a0233e810944d5d69571497248a1b3ba",
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
