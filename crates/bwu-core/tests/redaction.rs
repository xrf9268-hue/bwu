use bwu_core::redaction::SecretString;

#[test]
fn redaction_secret_string_redacts_display_and_debug_output() {
    let secret = SecretString::new("synthetic-master-password");

    for rendered in [
        format!("{secret}"),
        format!("{secret:?}"),
        format!("{secret:#?}"),
    ] {
        assert!(
            rendered.contains("[REDACTED]"),
            "secret formatting should show a redaction marker: {rendered}"
        );
        assert!(
            !rendered.contains("synthetic-master-password"),
            "secret formatting leaked the wrapped value: {rendered}"
        );
    }
}
