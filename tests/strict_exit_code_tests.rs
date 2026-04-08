use rust_unique_pass::{GenerationError, exit_code_for_error};

#[test]
fn strict_unmet_exit_code_is_3() {
    let err = GenerationError::StrictTargetUnmet;
    assert_eq!(exit_code_for_error(&err), 3);
}

#[test]
fn invalid_charset_exit_code_is_2() {
    let err = GenerationError::InvalidCharset("dummy".to_string());
    assert_eq!(exit_code_for_error(&err), 2);
}

#[test]
fn other_errors_exit_code_is_1() {
    let err = GenerationError::GenerationFailed;
    assert_eq!(exit_code_for_error(&err), 1);
}
