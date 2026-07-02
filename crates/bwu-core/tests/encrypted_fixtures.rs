use std::collections::BTreeMap;

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bwu_core::{
    crypto::{
        CryptoError, EncryptedField, EncryptedString, EncryptedVaultItem, KdfConfig,
        RsaEncryptedString, VaultItemType, VaultKeys, decrypt_account_key,
        decrypt_organization_key, decrypt_private_key, decrypt_vault_item, derive_master_key,
        stretch_key,
    },
    redaction::SecretString,
};
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use coset::{
    Algorithm, CborSerializable, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana,
};
use hmac::{Hmac, Mac};
use openssl::{
    md::{Md, MdRef},
    pkey::PKey,
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use sha2::Sha256;

const PROTECTED_ACCOUNT_KEY: &str = "2.YWNjb3VudC1rZXktaXYhIQ==|tgMg75OxorP0hiI5rt3T6bDyt0s9tcvtRQ2FxRGj7HPCjRRW598dqnq1EeWw7Cc+2hzuoLyWr4ZyW5fIKUMqLvsUwwWXa4BZg2aW4vrlfDI=|UeL8DxxJsZpeuTAkas560WEcuosQCwHL6Rk6PwUlzyU=";
const ENCRYPTED_ITEM_KEY: &str = "2.Y2lwaGVyLWtleS0taXYhIQ==|SvhxYcvkKZHLnNDQW6X/en7ETyJj4gZhnz7tUlCpDW38yu3VqmUzDew2LCZ5q6aZdo5+X+FseMfcwJ7NSpyZsMMoQXL2rcZV+RlnmbZ7+VU=|uDZgT7i1cwUYrDly8RK1548LPPm8Qg+INp0S8ATVF8k=";
const LEGACY_RSA_ORG_KEY_MAC: &[u8] = b"synthetic-legacy-org-key-mac";

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;

#[derive(Clone, Copy)]
enum CoseContentTypePlacement {
    Protected,
    Missing,
    UnprotectedOnly,
}

fn encrypted_fixture_keys() -> VaultKeys {
    let password = SecretString::new("synthetic-master-password");
    let master = derive_master_key(
        &password,
        "user@example.com",
        KdfConfig::pbkdf2_sha256(5_000),
    )
    .expect("synthetic master key should derive");
    let stretched = stretch_key(&master).expect("master key should stretch");
    let account_key = decrypt_account_key(
        &EncryptedString::parse(PROTECTED_ACCOUNT_KEY).expect("protected key should parse"),
        &stretched,
    )
    .expect("account key should decrypt");
    let org_key = synthetic_org_key();

    let mut organization_keys = BTreeMap::new();
    organization_keys.insert("org-1".to_owned(), org_key);
    VaultKeys {
        account_key,
        organization_keys,
    }
}

fn synthetic_org_key() -> bwu_core::crypto::SymmetricKey {
    bwu_core::crypto::SymmetricKey::new((0x50_u8..=0x8f).collect::<Vec<_>>())
        .expect("synthetic organization key should be valid")
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

fn synthetic_cose_key() -> bwu_core::crypto::SymmetricKey {
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
    bwu_core::crypto::SymmetricKey::new(pad_cose_key(cose_key))
        .expect("synthetic COSE key should parse")
}

fn encrypt_cose_fixture(
    plaintext: &[u8],
    key: &[u8; 32],
    key_id: &[u8],
    nonce: &[u8; 24],
) -> String {
    encrypt_cose_fixture_with_content_type(
        plaintext,
        key,
        key_id,
        nonce,
        CoseContentTypePlacement::Protected,
    )
}

fn encrypt_cose_fixture_with_content_type(
    plaintext: &[u8],
    key: &[u8; 32],
    key_id: &[u8],
    nonce: &[u8; 24],
    content_type_placement: CoseContentTypePlacement,
) -> String {
    let mut padded_plaintext = plaintext.to_vec();
    let padding = 32 - (padded_plaintext.len() % 32);
    padded_plaintext.extend(std::iter::repeat_n(
        u8::try_from(padding).expect("padding should fit in one byte"),
        padding,
    ));

    let mut protected = HeaderBuilder::new()
        .algorithm_label(Algorithm::PrivateUse(-70_000))
        .key_id(key_id.to_vec());
    if matches!(content_type_placement, CoseContentTypePlacement::Protected) {
        protected = protected.content_type("application/x.bitwarden.utf8-padded".to_owned());
    }

    let mut unprotected = HeaderBuilder::new().iv(nonce.to_vec());
    if matches!(
        content_type_placement,
        CoseContentTypePlacement::UnprotectedOnly
    ) {
        unprotected = unprotected.content_type("application/x.bitwarden.utf8-padded".to_owned());
    }

    let message = CoseEncrypt0Builder::new()
        .protected(protected.build())
        .create_ciphertext(&padded_plaintext, &[], |data, aad| {
            let mut buffer = data.to_vec();
            XChaCha20Poly1305::new(key.into())
                .encrypt_in_place(nonce.into(), aad, &mut buffer)
                .expect("synthetic COSE fixture should encrypt");
            buffer
        })
        .unprotected(unprotected.build())
        .build();

    format!(
        "7.{}",
        STANDARD.encode(
            message
                .to_vec()
                .expect("synthetic COSE Encrypt0 should serialize")
        )
    )
}

fn encrypt_symmetric_fixture(
    plaintext: &[u8],
    key: &bwu_core::crypto::SymmetricKey,
    iv: &[u8; 16],
) -> String {
    let (enc_key, mac_key) = key.expose_key().split_at(32);
    let ciphertext = Aes256CbcEncryptor::new_from_slices(enc_key, iv)
        .expect("synthetic fixture key and IV should be valid")
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut hmac =
        HmacSha256::new_from_slice(mac_key).expect("synthetic fixture HMAC key should be valid");
    hmac.update(iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(ciphertext),
        STANDARD.encode(mac)
    )
}

fn rsa_organization_key_fixture() -> (String, Vec<u8>, String) {
    rsa_organization_key_fixture_with(3, Md::sha256(), None)
}

fn rsa_organization_key_fixture_with(
    encryption_type: u8,
    digest: &'static MdRef,
    legacy_mac: Option<&[u8]>,
) -> (String, Vec<u8>, String) {
    let rsa = Rsa::generate(2048).expect("synthetic RSA key should generate");
    let pkey = PKey::from_rsa(rsa).expect("synthetic RSA key should convert");
    let private_pem = String::from_utf8(
        pkey.private_key_to_pem_pkcs8()
            .expect("synthetic RSA key should encode"),
    )
    .expect("synthetic RSA key PEM should be UTF-8");
    let private_der = pkey
        .private_key_to_pkcs8()
        .expect("synthetic RSA key should encode as PKCS#8 DER");

    let mut context = PkeyCtx::new(&pkey).expect("synthetic RSA context should create");
    context
        .encrypt_init()
        .expect("synthetic RSA context should initialize encryption");
    context
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .expect("synthetic RSA context should set OAEP padding");
    context
        .set_rsa_oaep_md(digest)
        .expect("synthetic RSA context should set OAEP digest");
    context
        .set_rsa_mgf1_md(digest)
        .expect("synthetic RSA context should set MGF1 digest");

    let mut encrypted_org_key = Vec::new();
    context
        .encrypt_to_vec(synthetic_org_key().expose_key(), &mut encrypted_org_key)
        .expect("synthetic organization key should RSA-encrypt");

    let mut payload = STANDARD.encode(encrypted_org_key);
    if let Some(mac) = legacy_mac {
        payload.push('|');
        payload.push_str(&STANDARD.encode(mac));
    }

    (
        private_pem,
        private_der,
        format!("{encryption_type}.{payload}"),
    )
}

fn encrypted_field(name: &str, encrypted: &str) -> EncryptedField {
    EncryptedField {
        name: name.to_owned(),
        value: EncryptedString::parse(encrypted).expect("field fixture should parse"),
    }
}

fn org_item(item_type: VaultItemType, fields: Vec<EncryptedField>) -> EncryptedVaultItem {
    EncryptedVaultItem {
        item_type,
        organization_id: Some("org-1".to_owned()),
        item_key: Some(EncryptedString::parse(ENCRYPTED_ITEM_KEY).expect("item key should parse")),
        fields,
    }
}

fn personal_item(item_type: VaultItemType, fields: Vec<EncryptedField>) -> EncryptedVaultItem {
    EncryptedVaultItem {
        item_type,
        organization_id: None,
        item_key: None,
        fields,
    }
}

fn cose_item(fields: Vec<EncryptedField>) -> EncryptedVaultItem {
    EncryptedVaultItem {
        item_type: VaultItemType::SecureNote,
        organization_id: None,
        item_key: None,
        fields,
    }
}

fn assert_field(item: &bwu_core::crypto::DecryptedVaultItem, name: &str, expected: &str) {
    let actual = item
        .field(name)
        .unwrap_or_else(|| panic!("missing decrypted field {name}"));
    assert!(
        actual.expose_secret() == expected,
        "decrypted field {name} did not match the synthetic fixture"
    );
}

#[test]
fn encrypted_fixtures_unwrap_organization_key_with_decrypted_rsa_private_key() {
    let keys = encrypted_fixture_keys();
    let (private_pem, _private_der, encrypted_org_key) = rsa_organization_key_fixture();
    let encrypted_private_key = encrypt_symmetric_fixture(
        private_pem.as_bytes(),
        &keys.account_key,
        b"rsa-private-iv!!",
    );

    let private_key = decrypt_private_key(
        &EncryptedString::parse(&encrypted_private_key)
            .expect("encrypted private key fixture should parse"),
        &keys.account_key,
    )
    .expect("private key should decrypt");
    let org_key = decrypt_organization_key(
        &RsaEncryptedString::parse(&encrypted_org_key)
            .expect("RSA organization key fixture should parse"),
        &private_key,
    )
    .expect("organization key should unwrap through the user's RSA private key");

    assert_eq!(org_key, synthetic_org_key());

    let rendered = format!("{private_key:?} {org_key:?}");
    for secret in [
        "BEGIN PRIVATE KEY",
        "505152535455565758595a5b5c5d5e5f",
        "cnNhLW9hZXA",
    ] {
        assert!(
            !rendered.contains(secret),
            "RSA organization-key fixture output leaked secret material"
        );
    }
}

#[test]
fn encrypted_fixtures_unwrap_organization_key_with_der_private_key_bytes() {
    let keys = encrypted_fixture_keys();
    let (_private_pem, private_der, encrypted_org_key) = rsa_organization_key_fixture();
    let encrypted_private_key =
        encrypt_symmetric_fixture(&private_der, &keys.account_key, b"rsa-der-key-iv!!");

    let private_key = decrypt_private_key(
        &EncryptedString::parse(&encrypted_private_key)
            .expect("encrypted DER private key fixture should parse"),
        &keys.account_key,
    )
    .expect("DER private key bytes should decrypt");
    let org_key = decrypt_organization_key(
        &RsaEncryptedString::parse(&encrypted_org_key)
            .expect("RSA organization key fixture should parse"),
        &private_key,
    )
    .expect("organization key should unwrap through a DER private key");

    assert_eq!(org_key, synthetic_org_key());

    let rendered = format!("{private_key:?} {org_key:?}");
    for secret in [
        STANDARD.encode(&private_der[..24]),
        "BEGIN PRIVATE KEY".to_owned(),
        "505152535455565758595a5b5c5d5e5f".to_owned(),
    ] {
        assert!(
            !rendered.contains(&secret),
            "DER private-key fixture output leaked secret material"
        );
    }
}

#[test]
fn encrypted_fixtures_unwrap_legacy_rsa_organization_key_shapes() {
    let keys = encrypted_fixture_keys();

    for (encryption_type, digest, iv) in [
        (5, Md::sha256(), b"legacy-rsa-iv005"),
        (6, Md::sha1(), b"legacy-rsa-iv006"),
    ] {
        let (_private_pem, private_der, encrypted_org_key) = rsa_organization_key_fixture_with(
            encryption_type,
            digest,
            Some(LEGACY_RSA_ORG_KEY_MAC),
        );
        let encrypted_private_key = encrypt_symmetric_fixture(&private_der, &keys.account_key, iv);

        let private_key = decrypt_private_key(
            &EncryptedString::parse(&encrypted_private_key)
                .expect("encrypted DER private key fixture should parse"),
            &keys.account_key,
        )
        .expect("DER private key bytes should decrypt");
        let org_key = decrypt_organization_key(
            &RsaEncryptedString::parse(&encrypted_org_key)
                .expect("legacy RSA organization key fixture should parse"),
            &private_key,
        )
        .expect("legacy RSA organization key should unwrap through the same OAEP path");

        assert_eq!(org_key, synthetic_org_key());

        let rendered = format!("{private_key:?} {org_key:?}");
        for secret in [
            STANDARD.encode(&private_der[..24]),
            STANDARD.encode(LEGACY_RSA_ORG_KEY_MAC),
            "505152535455565758595a5b5c5d5e5f".to_owned(),
        ] {
            assert!(
                !rendered.contains(&secret),
                "legacy RSA organization-key fixture output leaked secret material"
            );
        }
    }
}

#[test]
fn encrypted_fixtures_decrypt_supported_read_only_item_shapes() {
    let keys = encrypted_fixture_keys();
    let fixtures = [
        org_item(
            VaultItemType::Login,
            vec![
                encrypted_field(
                    "login.username",
                    "2.ZmllbGQtZml4dHVyZS0wMQ==|CJx7Hh9JzxXi0mYlnSqJyfHVr29XujJvV6UbZ0ByCwY=|4OUsdoJx68dSgunHnl5uedtCVB7V5tUeB7HHZz4/6dA=",
                ),
                encrypted_field(
                    "login.password",
                    "2.ZmllbGQtZml4dHVyZS0wMg==|54s4esk34MwBDjV9UTaVctbyPYRqqg3oTCGEwoIn3aA=|HRsiSyGMvQ+lP+xTNp91iNwfCY57HqFZAu1TiA+UT70=",
                ),
            ],
        ),
        org_item(
            VaultItemType::SecureNote,
            vec![encrypted_field(
                "secure_note.notes",
                "2.ZmllbGQtZml4dHVyZS0wMw==|32xToCyHoxxdwQB0ii/wzei4JfeJcFTi9ecDuxjLHJ8=|TqedIj4BeODDrZohdhFPwz2NFJ3LaV0dGlfACJ2+BT4=",
            )],
        ),
        org_item(
            VaultItemType::Card,
            vec![encrypted_field(
                "card.number",
                "2.ZmllbGQtZml4dHVyZS0wNA==|77+SDzSoP8qdJ+QMXbfcqtZNuA4i+rRBiVnUwxlNi04=|xxXupeycKUQfOQACiwAzgefUCFJOJ/AyUVr2fHzveDM=",
            )],
        ),
        org_item(
            VaultItemType::Identity,
            vec![
                encrypted_field(
                    "identity.name",
                    "2.ZmllbGQtZml4dHVyZS0wNQ==|9qCb6gdMBFPaf4oYFET/DalnSq3ZXKWEzUe5flerkM4=|HALbKvB0z9AJhhsZ/IhJ+cYJbXJlrZtpQDAn0EGx/w8=",
                ),
                encrypted_field(
                    "identity.secret",
                    "2.ZmllbGQtZml4dHVyZS0wNg==|bVM4C+5jj9drvP8yyI1AZA85iJzn4kYAXEtJNu7gujU=|Mx4bxCAcKuAj3AnYSNnm1aTsp0f+T0/JoIFw0/ZlT4I=",
                ),
            ],
        ),
        org_item(
            VaultItemType::SshKey,
            vec![
                encrypted_field(
                    "ssh_key.name",
                    "2.ZmllbGQtZml4dHVyZS0wNw==|6lS654lkvmpYRqBlHZKgf8VLNnsH9gd43r7RKG2m+u4=|GJGeg5TVADT9bgCFQzQAr4tYuDzja7Y9+xObvcrb3qA=",
                ),
                encrypted_field(
                    "ssh_key.private_key",
                    "2.ZmllbGQtZml4dHVyZS0wOA==|M6ZYOn/wXehPlMWCnFhcGghKxf5RGQTG9byTUdf2zKEymyMiLKRbOM1B3GcNuott|sal+K8l4/FwGNpwVrIrr5/tXSsdSOeNo45AijoHoj7A=",
                ),
            ],
        ),
        org_item(
            VaultItemType::PasskeyMetadata,
            vec![
                encrypted_field(
                    "passkey.rp_id",
                    "2.ZmllbGQtZml4dHVyZS0wOQ==|Wu+0mN1mAUY2qOPqQxo0RA==|J+W3+tkWtiBp7PGVIMppX1PPN7e88//Zw0+g70dk4Mc=",
                ),
                encrypted_field(
                    "passkey.credential_id",
                    "2.ZmllbGQtZml4dHVyZS0xMA==|gMYok1AtKxgBpm5/x0WaEVAweWW73HEelF2t3i78l0I=|l5eoyKHNMyNQlmAJ4GRVsEVSRKbOyQjXs3v2VrhaWr4=",
                ),
            ],
        ),
        personal_item(
            VaultItemType::SecureNote,
            vec![encrypted_field(
                "secure_note.notes",
                "2.cGVyc29uYWwtbm90ZS1pdg==|sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k=|/cSHGtMw6f6kg12awnTjaqK3CelEN7bQciN3NiJZgg8=",
            )],
        ),
    ];

    let decrypted: Vec<_> = fixtures
        .iter()
        .map(|fixture| decrypt_vault_item(fixture, &keys).expect("fixture should decrypt"))
        .collect();

    assert_field(&decrypted[0], "login.username", "reader@example.com");
    assert_field(&decrypted[0], "login.password", "synthetic-login-password");
    assert_field(
        &decrypted[1],
        "secure_note.notes",
        "synthetic secure note body",
    );
    assert_field(&decrypted[2], "card.number", "synthetic-card-number-shape");
    assert_field(&decrypted[3], "identity.name", "Synthetic Person");
    assert_field(
        &decrypted[3],
        "identity.secret",
        "synthetic-identity-secret",
    );
    assert_field(&decrypted[4], "ssh_key.name", "synthetic ssh key label");
    assert_field(
        &decrypted[4],
        "ssh_key.private_key",
        "synthetic-ssh-private-key-material",
    );
    assert_field(&decrypted[5], "passkey.rp_id", "example.com");
    assert_field(
        &decrypted[5],
        "passkey.credential_id",
        "synthetic-credential-id",
    );
    assert_field(
        &decrypted[6],
        "secure_note.notes",
        "personal account-key note",
    );

    let rendered = format!("{decrypted:?}");
    for secret in [
        "synthetic-login-password",
        "synthetic secure note body",
        "synthetic-card-number-shape",
        "synthetic-identity-secret",
        "synthetic-ssh-private-key-material",
        "synthetic-credential-id",
        "personal account-key note",
    ] {
        assert!(
            !rendered.contains(secret),
            "debug output for decrypted fixtures leaked a decrypted secret"
        );
    }
}

#[test]
fn encrypted_fixtures_decrypt_current_cose_field_without_secret_leaks() {
    let key_bytes = synthetic_xchacha_key_bytes();
    let key_id = b"synthetic-cose-key-id";
    let keys = VaultKeys {
        account_key: synthetic_cose_key(),
        organization_keys: BTreeMap::new(),
    };
    let encrypted_note = encrypt_cose_fixture(
        b"synthetic current COSE note",
        &key_bytes,
        key_id,
        b"cose-note-fixture-nonce!",
    );
    let tampered_note = {
        let (_, payload) = encrypted_note
            .split_once('.')
            .expect("type prefix should exist");
        let mut bytes = STANDARD
            .decode(payload)
            .expect("COSE fixture should decode");
        let last = bytes
            .last_mut()
            .expect("COSE fixture should contain ciphertext");
        *last ^= 0x01;
        format!("7.{}", STANDARD.encode(bytes))
    };

    let decrypted = decrypt_vault_item(
        &cose_item(vec![encrypted_field("secure_note.notes", &encrypted_note)]),
        &keys,
    )
    .expect("type 7 COSE fields should decrypt through the XChaCha key");
    assert_field(
        &decrypted,
        "secure_note.notes",
        "synthetic current COSE note",
    );

    let err = decrypt_vault_item(
        &cose_item(vec![encrypted_field("secure_note.notes", &tampered_note)]),
        &keys,
    )
    .expect_err("tampered COSE ciphertext should fail authentication");
    assert_eq!(err, CryptoError::AuthenticationFailed);

    let rendered = format!("{decrypted:?} {err:?} {err}");
    for secret in [
        "synthetic current COSE note",
        "synthetic-cose-key-id",
        "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaav",
        encrypted_note.as_str(),
    ] {
        assert!(
            !rendered.contains(secret),
            "COSE fixture output leaked synthetic secret material"
        );
    }
}

#[test]
fn encrypted_fixtures_reject_malformed_cose_content_type_headers_without_secret_leaks() {
    let key_bytes = synthetic_xchacha_key_bytes();
    let key_id = b"synthetic-cose-key-id";
    let keys = VaultKeys {
        account_key: synthetic_cose_key(),
        organization_keys: BTreeMap::new(),
    };

    let missing_protected_content_type = encrypt_cose_fixture_with_content_type(
        b"synthetic malformed COSE note",
        &key_bytes,
        key_id,
        b"cose-missing-type-nonce!",
        CoseContentTypePlacement::Missing,
    );
    let unprotected_only_content_type = encrypt_cose_fixture_with_content_type(
        b"synthetic unprotected COSE note",
        &key_bytes,
        key_id,
        b"cose-unprotected-type!!!",
        CoseContentTypePlacement::UnprotectedOnly,
    );

    for malformed in [
        missing_protected_content_type.as_str(),
        unprotected_only_content_type.as_str(),
    ] {
        let err = decrypt_vault_item(
            &cose_item(vec![encrypted_field("secure_note.notes", malformed)]),
            &keys,
        )
        .expect_err("malformed COSE content type headers should fail closed");
        assert_eq!(err, CryptoError::InvalidEncryptedString);

        let rendered = format!("{err:?} {err}");
        for secret in [
            "synthetic malformed COSE note",
            "synthetic unprotected COSE note",
            "synthetic-cose-key-id",
            malformed,
        ] {
            assert!(
                !rendered.contains(secret),
                "malformed COSE fixture output leaked synthetic secret material"
            );
        }
    }
}

#[test]
fn encrypted_fixtures_fail_closed_on_tampered_mac_without_plaintext_leaks() {
    let keys = encrypted_fixture_keys();
    let tampered = personal_item(
        VaultItemType::SecureNote,
        vec![encrypted_field(
            "secure_note.notes",
            "2.cGVyc29uYWwtbm90ZS1pdg==|sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k=|AcSHGtMw6f6kg12awnTjaqK3CelEN7bQciN3NiJZgg8=",
        )],
    );

    let err = decrypt_vault_item(&tampered, &keys).expect_err("tampered MAC should be rejected");
    let rendered = format!("{err:?} {err}");
    assert!(
        !rendered.contains("personal account-key note"),
        "decrypt error output leaked plaintext"
    );
    assert!(
        !rendered.contains("sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k"),
        "decrypt error output echoed ciphertext"
    );
}

#[test]
fn encrypted_fixtures_fail_closed_when_organization_key_is_missing_without_secret_leaks() {
    let keys = encrypted_fixture_keys();
    let missing_org_item = EncryptedVaultItem {
        item_type: VaultItemType::Login,
        organization_id: Some("org-missing-from-unlocked-keys".to_owned()),
        item_key: Some(EncryptedString::parse(ENCRYPTED_ITEM_KEY).expect("item key should parse")),
        fields: vec![encrypted_field(
            "login.password",
            "2.ZmllbGQtZml4dHVyZS0wMg==|54s4esk34MwBDjV9UTaVctbyPYRqqg3oTCGEwoIn3aA=|HRsiSyGMvQ+lP+xTNp91iNwfCY57HqFZAu1TiA+UT70=",
        )],
    };

    let err = decrypt_vault_item(&missing_org_item, &keys)
        .expect_err("organization items without an unlocked organization key should fail closed");
    assert_eq!(err, CryptoError::MissingOrganizationKey);

    let rendered = format!("{err:?} {err}");
    for secret in [
        "synthetic-login-password",
        "SvhxYcvkKZHLnNDQW6X/en7ETyJj4gZhnz7tUlCpDW38",
        "54s4esk34MwBDjV9UTaVctbyPYRqqg3oTCGEwoIn3aA",
    ] {
        assert!(
            !rendered.contains(secret),
            "missing organization key error output leaked fixture material"
        );
    }
}

#[test]
fn encrypted_fixtures_fail_closed_on_duplicate_fields_without_secret_leaks() {
    let keys = encrypted_fixture_keys();
    let duplicate = personal_item(
        VaultItemType::SecureNote,
        vec![
            encrypted_field(
                "secure_note.notes",
                "2.cGVyc29uYWwtbm90ZS1pdg==|sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k=|/cSHGtMw6f6kg12awnTjaqK3CelEN7bQciN3NiJZgg8=",
            ),
            encrypted_field(
                "secure_note.notes",
                "2.cGVyc29uYWwtbm90ZS1pdg==|sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k=|/cSHGtMw6f6kg12awnTjaqK3CelEN7bQciN3NiJZgg8=",
            ),
        ],
    );

    let err = decrypt_vault_item(&duplicate, &keys)
        .expect_err("duplicate encrypted field names should fail closed");
    assert_eq!(err, CryptoError::DuplicateFieldName);

    let rendered = format!("{err:?} {err}");
    for secret in [
        "personal account-key note",
        "sD8mAeE41o4csR0ibSJJaKm5VEfJmfuDnURAdvwks5k",
    ] {
        assert!(
            !rendered.contains(secret),
            "duplicate field error output leaked fixture material"
        );
    }
}
