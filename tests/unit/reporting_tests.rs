use super::{parse_test_min_score_override, resolve_min_score_from_override};
use crate::cli::RupassArgs;

fn args_with_min_score(min_score: u8) -> RupassArgs {
    RupassArgs {
        language: None,
        password_length: None,
        all: false,
        no_prompt: false,
        numbers: false,
        no_numbers: false,
        uppercase: false,
        no_uppercase: false,
        lowercase: false,
        no_lowercase: false,
        symbols: false,
        no_symbols: false,
        symbols_set: None,
        timeout_ms: 150,
        min_score,
        strict: false,
        show_strength: false,
        quiet: false,
    }
}

#[test]
fn parse_override_accepts_valid_range() {
    assert_eq!(parse_test_min_score_override("0"), Some(0));
    assert_eq!(parse_test_min_score_override("4"), Some(4));
    assert_eq!(parse_test_min_score_override(" 3 "), Some(3));
}

#[test]
fn parse_override_rejects_invalid_input() {
    assert_eq!(parse_test_min_score_override("5"), None);
    assert_eq!(parse_test_min_score_override("-1"), None);
    assert_eq!(parse_test_min_score_override("abc"), None);
}

#[test]
fn resolve_min_score_uses_override_when_valid() {
    let args = args_with_min_score(2);
    let resolved = resolve_min_score_from_override(&args, Some("4"));
    assert_eq!(resolved, 4);
}

#[test]
fn resolve_min_score_falls_back_when_override_invalid_or_missing() {
    let args = args_with_min_score(2);
    let invalid = resolve_min_score_from_override(&args, Some("9"));
    let missing = resolve_min_score_from_override(&args, None);
    assert_eq!(invalid, 2);
    assert_eq!(missing, 2);
}
