use std::{fs, path::Path};

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bwu-core should live under crates/bwu-core")
}

#[test]
fn workspace_forbids_unsafe_code_for_every_member() {
    let root = workspace_root();
    let root_manifest =
        fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest should exist");

    assert!(
        root_manifest.contains("[workspace.lints.rust]"),
        "workspace manifest should define shared Rust lints"
    );
    assert!(
        root_manifest.contains("unsafe_code = \"forbid\""),
        "workspace manifest should forbid unsafe code"
    );

    for member in ["crates/bwu-core", "crates/bwu-cli", "crates/bwu-agent"] {
        let manifest = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap_or_else(|err| panic!("should read {member}/Cargo.toml: {err}"));
        assert!(
            manifest.contains("workspace = true"),
            "{member} should inherit workspace package metadata and lints"
        );
        assert!(
            manifest.contains("[lints]"),
            "{member} should opt into workspace lint policy"
        );
    }
}
