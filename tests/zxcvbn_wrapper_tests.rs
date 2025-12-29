use rust_unique_pass::{MAX_PASSWORD_CHARS, zxcvbn_entropy_score};

#[test]
fn empty_password() {
    let res = zxcvbn_entropy_score("");
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), "password cannot be empty");
}

#[test]
fn too_long_password() {
    let long = "a".repeat(MAX_PASSWORD_CHARS + 1);
    let res = zxcvbn_entropy_score(&long);
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("character length"));
}

#[test]
fn too_long_password_bytes() {
    let long = "\u{1F980}".repeat(MAX_PASSWORD_CHARS);
    let res = zxcvbn_entropy_score(&long);
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("byte length"));
}

#[test]
fn valid_password() {
    let res = zxcvbn_entropy_score("correcthorsebatterystaple");
    assert!(res.is_ok());
    let (bits, score) = res.unwrap();
    assert!(bits > 0.0);
    assert!(score <= 4);
}
