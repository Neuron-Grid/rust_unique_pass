use rust_unique_pass::{MAX_PASSWORD_CHARS, zxcvbn_entropy_score};

type TestResult<T> = std::result::Result<T, String>;

#[test]
fn empty_password() -> TestResult<()> {
    match zxcvbn_entropy_score("") {
        Ok(_) => Err("expected error for empty password".to_string()),
        Err(err) => {
            if err == "password cannot be empty" {
                Ok(())
            } else {
                Err(format!("unexpected error: {err}"))
            }
        }
    }
}

#[test]
fn too_long_password() -> TestResult<()> {
    let long = "a".repeat(MAX_PASSWORD_CHARS + 1);
    match zxcvbn_entropy_score(&long) {
        Ok(_) => Err("expected error for long password".to_string()),
        Err(err_msg) => {
            if err_msg.contains("character length") {
                Ok(())
            } else {
                Err(format!("unexpected error: {err_msg}"))
            }
        }
    }
}

#[test]
fn too_long_password_bytes() -> TestResult<()> {
    let long = "\u{1F980}".repeat(MAX_PASSWORD_CHARS);
    match zxcvbn_entropy_score(&long) {
        Ok(_) => Err("expected error for long password bytes".to_string()),
        Err(err_msg) => {
            if err_msg.contains("byte length") {
                Ok(())
            } else {
                Err(format!("unexpected error: {err_msg}"))
            }
        }
    }
}

#[test]
fn valid_password() -> TestResult<()> {
    let (bits, score) = zxcvbn_entropy_score("correcthorsebatterystaple")
        .map_err(|e| format!("expected valid result: {e}"))?;
    assert!(bits > 0.0);
    assert!(score <= 4);
    Ok(())
}
