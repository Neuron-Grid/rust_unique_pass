/* Copyright 2024-2025 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use clap::Parser;
use fluent::FluentArgs;
use rust_unique_pass::{GenerationError, RupassArgs, get_translation, initialize_bundle};

type TestResult<T> = std::result::Result<T, String>;

/// ショートエイリアス（-lや-pなど）のテスト
#[test]
fn test_parse_args_short_aliases() {
    let args = vec!["test_app", "-L", "eng", "-p", "20", "-n", "-u", "-w", "-s"];
    let parsed = parse_args_from_iter(args);
    assert_eq!(parsed.language.as_deref(), Some("eng"));
    assert_eq!(parsed.password_length, Some(20));
    assert!(parsed.numbers);
    assert!(parsed.uppercase);
    assert!(parsed.lowercase);
    assert!(parsed.symbols);
}

#[test]
fn test_parse_args_negative_flags() {
    let args = vec![
        "test_app",
        "--no-numbers",
        "--no-uppercase",
        "--no-lowercase",
        "--no-symbols",
    ];
    let parsed = parse_args_from_iter(args);
    assert!(parsed.no_numbers);
    assert!(parsed.no_uppercase);
    assert!(parsed.no_lowercase);
    assert!(parsed.no_symbols);
    assert!(!parsed.numbers);
    assert!(!parsed.uppercase);
    assert!(!parsed.lowercase);
    assert!(!parsed.symbols);
}

/// Helper: clapの引数パース関数を呼び出す。
fn parse_args_from_iter<I, T>(iter: I) -> RupassArgs
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    rust_unique_pass::RupassArgs::parse_from(iter)
}

/// サポートされない言語指定時のエラー
#[test]
fn test_initialize_bundle_unsupported_language() {
    let args = RupassArgs {
        language: Some("xxx".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };
    let result = initialize_bundle(&args);
    assert!(matches!(result, Err(GenerationError::UnsupportedLanguage)));
}

/// 翻訳キーが存在しない場合 -> TranslationMissing エラー
#[test]
fn test_get_translation_missing_key() -> TestResult<()> {
    let args = RupassArgs {
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };
    // デフォルト言語(eng)でロード
    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;
    let res = get_translation(&bundle, "this_key_does_not_exist", None);
    assert!(matches!(res, Err(GenerationError::TranslationMissing(_))));
    Ok(())
}

/// FluentArgsの挿入テスト
#[test]
fn test_get_translation_with_args() -> TestResult<()> {
    let args = RupassArgs {
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };
    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;

    let mut fluent_args = FluentArgs::new();
    fluent_args.set("specialChars", "!@#$");
    let text = get_translation(&bundle, "default_special_chars_message", Some(&fluent_args))
        .map_err(|e| format!("translation failed: {e:?}"))?;
    // eng.ftl には "The special character used by default is { $specialChars }." 等が定義
    assert!(
        text.contains("!@#$"),
        "Should contain the special chars in the message"
    );
    Ok(())
}

/// 明示的に "jpn" を指定して翻訳バンドルを初期化
/// 一部のキーを取り出して日本語になっていることを確認。
#[test]
fn test_initialize_bundle_jpn() -> TestResult<()> {
    let args = RupassArgs {
        language: Some("jpn".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };

    // jpn.ftl がちゃんと埋め込まれていればロードできるはず
    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;

    // "question_special_chars" のキーを取り出す
    let question_special_chars = get_translation(&bundle, "question_special_chars", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;
    // jpn.ftl の定義では「特殊文字を含めますか？」になっている
    assert!(
        question_special_chars.contains("特殊文字を含めますか？"),
        "Should contain Japanese text"
    );
    Ok(())
}

/// ISO639-1コードのエイリアスでも英語リソースを取得できることを確認
#[test]
fn test_initialize_bundle_en_alias() -> TestResult<()> {
    let args = RupassArgs {
        language: Some("en".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };

    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;
    let message = get_translation(&bundle, "generated_password", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;
    assert!(
        message.contains("Password Generation Result"),
        "English translation should be returned for alias en"
    );
    Ok(())
}

/// 新規テスト2: jpn翻訳でのエラーメッセージ比較
#[test]
fn test_jpn_translation_error_message() -> TestResult<()> {
    let args = RupassArgs {
        language: Some("jpn".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };

    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;
    // jpn.ftl は "error_password_too_short" = "パスワードは15文字以上を推奨します。" など
    let too_short = get_translation(&bundle, "error_password_too_short", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;
    assert!(
        too_short.contains("パスワードは15文字以上を推奨します。"),
        "Japanese short password error message should match"
    );
    Ok(())
}

/// 新規テスト3: 英語と日本語で同一キーを取得し、文言が異なることを確認する
#[test]
fn test_compare_eng_and_jpn_translations() -> TestResult<()> {
    let eng_args = RupassArgs {
        language: Some("eng".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };
    let jpn_args = RupassArgs {
        language: Some("jpn".to_string()),
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };

    let eng_bundle =
        initialize_bundle(&eng_args).map_err(|e| format!("bundle init failed: {e:?}"))?;
    let jpn_bundle =
        initialize_bundle(&jpn_args).map_err(|e| format!("bundle init failed: {e:?}"))?;

    // 同じキー "error_no_charset_selected" を取得して比較
    let eng_text = get_translation(&eng_bundle, "error_no_charset_selected", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;
    let jpn_text = get_translation(&jpn_bundle, "error_no_charset_selected", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;

    assert_ne!(
        eng_text, jpn_text,
        "English and Japanese messages for the same key should differ"
    );
    // 簡易的な確認: 英文は "Error: No character set selected" を含み、日本語は「文字セットが選択されていません」を含むこと
    assert!(
        eng_text.contains("Error: No character set selected"),
        "English error_no_charset_selected should contain the English phrase"
    );
    assert!(
        jpn_text.contains("エラー: 文字セットが選択されていません"),
        "Japanese error_no_charset_selected should contain the Japanese phrase"
    );
    Ok(())
}

/// 言語が指定されない場合はデフォルトのengが読み込まれる
#[test]
fn test_default_language_is_eng() -> TestResult<()> {
    // 言語オプションがNoneの場合
    let args = RupassArgs {
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
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
    };
    let bundle = initialize_bundle(&args).map_err(|e| format!("bundle init failed: {e:?}"))?;

    // eng.ftl にあるキーを確認
    let eng_text = get_translation(&bundle, "question_change_special_chars", None)
        .map_err(|e| format!("translation failed: {e:?}"))?;
    assert!(
        eng_text.contains("Change the special characters used?"),
        "Default language (eng) message should contain 'Change the special characters used?'"
    );
    Ok(())
}
