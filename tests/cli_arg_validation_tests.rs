use clap::Parser;
use rust_unique_pass::RupassArgs;

type TestResult<T> = std::result::Result<T, String>;

#[test]
fn invalid_timeout_ms_is_rejected() {
    let res = RupassArgs::try_parse_from([
        "rupass",
        "--timeout-ms",
        "5", // < 10
    ]);
    assert!(
        res.is_err(),
        "timeout < 10 must be rejected with code 2 by clap"
    );
}

#[test]
fn invalid_min_score_is_rejected() {
    let res = RupassArgs::try_parse_from(["rupass", "--min-score", "5"]);
    assert!(
        res.is_err(),
        "min-score > 4 must be rejected with code 2 by clap"
    );
}

#[test]
fn porcelain_alias_for_quiet() -> TestResult<()> {
    let res = RupassArgs::try_parse_from(["rupass", "--porcelain"])
        .map_err(|e| format!("parse porcelain flag failed: {e:?}"))?;
    assert!(res.quiet);
    Ok(())
}

#[test]
fn symbols_set_requires_symbols_flag() {
    let res = RupassArgs::try_parse_from(["rupass", "--symbols-set", "!@#"]);
    assert!(
        res.is_err(),
        "--symbols-set without --symbols should be rejected"
    );
}

#[test]
fn symbols_set_with_symbols_parses() -> TestResult<()> {
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", "!@#"])
        .map_err(|e| format!("parse symbols flag failed: {e:?}"))?;
    assert!(res.symbols);
    assert_eq!(res.symbols_set.as_deref(), Some("!@#"));
    Ok(())
}

#[test]
fn symbols_set_empty_is_rejected() {
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", ""]);
    assert!(res.is_err(), "empty --symbols-set must be rejected by clap");
}

#[test]
fn symbols_set_exceeding_char_cap_is_rejected() {
    // 129 ASCII chars > SYMBOLS_SET_MAX_CHARS (128)
    let big = "a".repeat(129);
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", &big]);
    assert!(
        res.is_err(),
        "--symbols-set exceeding char cap must be rejected by clap"
    );
}

#[test]
fn symbols_set_at_char_cap_boundary_parses() -> TestResult<()> {
    // 128 ASCII chars == SYMBOLS_SET_MAX_CHARS (boundary inclusive)
    let at_cap = "a".repeat(128);
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", &at_cap])
        .map_err(|e| format!("parse symbols-set at cap failed: {e:?}"))?;
    assert_eq!(res.symbols_set.as_deref(), Some(at_cap.as_str()));
    Ok(())
}

#[test]
fn symbols_set_exceeding_byte_cap_is_rejected() {
    // 65 four-byte chars = 65 chars / 260 bytes; 65 ≤ 128 chars OK,
    // but 260 > 256 bytes → must be rejected by the byte cap.
    let big_bytes: String = "🌟".repeat(65);
    assert!(big_bytes.chars().count() <= 128);
    assert!(big_bytes.len() > 256);
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", &big_bytes]);
    assert!(
        res.is_err(),
        "--symbols-set exceeding byte cap must be rejected by clap"
    );
}
