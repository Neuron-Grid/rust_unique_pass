use rust_unique_pass::{GenerationError, exit_code_for_error};

#[test]
fn strict_unmet_exit_code_is_3() {
    let err = GenerationError::StrictTargetUnmet;
    assert_eq!(exit_code_for_error(&err), 3);
}
