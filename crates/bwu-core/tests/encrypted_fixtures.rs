use std::collections::BTreeMap;

use bwu_core::{
    crypto::{
        EncryptedField, EncryptedString, EncryptedVaultItem, KdfConfig, VaultItemType, VaultKeys,
        decrypt_account_key, decrypt_organization_key, decrypt_vault_item, derive_master_key,
        stretch_key,
    },
    redaction::SecretString,
};

const PROTECTED_ACCOUNT_KEY: &str = "2.YWNjb3VudC1rZXktaXYhIQ==|tgMg75OxorP0hiI5rt3T6bDyt0s9tcvtRQ2FxRGj7HPCjRRW598dqnq1EeWw7Cc+2hzuoLyWr4ZyW5fIKUMqLvsUwwWXa4BZg2aW4vrlfDI=|UeL8DxxJsZpeuTAkas560WEcuosQCwHL6Rk6PwUlzyU=";
const ENCRYPTED_ORG_KEY: &str = "2.b3JnYW5pei1rZXktaXYhIQ==|IGHGhkaMEkoeCY6BMIOmaPhEx7lpO+3ztBqCta+eM9TOUCo1vDGSxorpaODQfgooLnKeeQgh31NryMpV5wcyEhbGHSoE1xLDhjW06cGdIuA=|4uNcKIEFuX7Io0OCSdZ5wfU3jds4FU5B254+nq+pmKQ=";
const ENCRYPTED_ITEM_KEY: &str = "2.Y2lwaGVyLWtleS0taXYhIQ==|SvhxYcvkKZHLnNDQW6X/en7ETyJj4gZhnz7tUlCpDW38yu3VqmUzDew2LCZ5q6aZdo5+X+FseMfcwJ7NSpyZsMMoQXL2rcZV+RlnmbZ7+VU=|uDZgT7i1cwUYrDly8RK1548LPPm8Qg+INp0S8ATVF8k=";

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
    let org_key = decrypt_organization_key(
        &EncryptedString::parse(ENCRYPTED_ORG_KEY).expect("org key should parse"),
        &account_key,
    )
    .expect("organization key should decrypt");

    let mut organization_keys = BTreeMap::new();
    organization_keys.insert("org-1".to_owned(), org_key);
    VaultKeys {
        account_key,
        organization_keys,
    }
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
