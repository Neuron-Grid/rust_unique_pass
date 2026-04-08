# Changelog

All notable changes to this project will be documented in this file.

## [0.11.0]

### Security
- **Local DoS hardening for `--symbols-set`**: A multi-byte custom symbols
  set combined with a large `--password-length` could previously cause every
  candidate to be rejected by the byte-length cap and burn the entire time
  budget on a useless search loop. The CLI now applies a two-layer defense:
  - **CLI hard cap**: `--symbols-set` is rejected by clap if it exceeds 128
    characters or 256 bytes. These limits are independent of zxcvbn's
    `MAX_PASSWORD_CHARS`/`MAX_PASSWORD_BYTES` and exist solely as a DoS guard.
  - **Feasibility pre-check**: Before entering the search loop, the assembled
    character set is checked against `MAX_PASSWORD_BYTES` using the lower
    bound `Σ min_utf8(req_set_i) + (length − non_empty_req_count) ×
    min_utf8(all_vec)`. If even this lower bound exceeds the cap, the run
    aborts immediately with the new `GenerationError::InvalidCharset`
    (exit code `2`).

### Added
- `GenerationError::InvalidCharset(String)` variant.
- `validate_charset_feasibility(...)` helper used by both the time-budgeted
  generation flow and the legacy `produce_secure_password` API so that the
  DoS guard applies uniformly to every public entry point.
- `SYMBOLS_SET_MAX_CHARS` / `SYMBOLS_SET_MAX_BYTES` constants documented as
  CLI hard caps for DoS defense.
- New translation key `error_infeasible_charset` for English, Japanese, and
  German bundles.

### Changed
- **Breaking**: `GenerationError` gained a new variant. External callers
  performing exhaustive `match` on this enum must add an arm for
  `InvalidCharset`.
- `exit_code_for_error` now maps `InvalidCharset` to exit code `2`
  (`StrictTargetUnmet` remains `3`).

### Deprecated
- `produce_secure_password` is now `#[deprecated]`. It still runs and now
  benefits from the new feasibility pre-check, but the time-budgeted API
  (`produce_password_within_time` / `generate_password_flow`) is the
  recommended entry point and the legacy function will be removed in a
  future release.
