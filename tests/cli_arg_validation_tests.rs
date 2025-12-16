use clap::Parser;
use rust_unique_pass::RupassArgs;

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
fn porcelain_alias_for_quiet() {
    let res = RupassArgs::try_parse_from(["rupass", "--porcelain"]).unwrap();
    assert!(res.quiet);
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
fn symbols_set_with_symbols_parses() {
    let res = RupassArgs::try_parse_from(["rupass", "--symbols", "--symbols-set", "!@#"]).unwrap();
    assert!(res.symbols);
    assert_eq!(res.symbols_set.as_deref(), Some("!@#"));
}
