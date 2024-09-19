/* Copyright 2024 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use rust_unique_pass::generate_pass::*;
use rust_unique_pass::i18n::RupassArgs;
use fluent::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

// ヘルパー関数: テスト用のダミーのFluentBundleを作成
fn get_bundle() -> FluentBundle<FluentResource> {
    let ftl_string = String::from("key = value");
    let resource = FluentResource::try_new(ftl_string).expect("Failed to parse FTL string.");
    let langid: LanguageIdentifier = "en-US".parse().expect("Parsing language failed.");
    let mut bundle = FluentBundle::new(vec![langid]);
    bundle.add_resource(resource).expect("Failed to add resource.");
    bundle
}

#[test]
fn test_validate_password_length() {
    // 正常な入力
    assert_eq!(validate_password_length("15"), Ok(15));
    // 非数値入力
    assert_eq!(
        validate_password_length("abc"),
        Err(PasswordLengthError::NonNumericInput)
    );
    // 負の数
    assert_eq!(
        validate_password_length("-5"),
        Err(PasswordLengthError::NegativeNumber)
    );
    // 短すぎるパスワード
    assert_eq!(
        validate_password_length("5"),
        Err(PasswordLengthError::TooShort)
    );
}

#[test]
fn assemble_password() {
    let args = TestArgs {
        numbers: true,
        uppercase: true,
        lowercase: true,
    };
    let assembled_charset = [
        (args.numbers, "0123456789"),
        (args.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (args.lowercase, "abcdefghijklmnopqrstuvwxyz"),
    ]
    .iter()
    .filter_map(|&(flag, charset)| if flag { Some(charset) } else { None })
    .collect::<String>();
    let length = 10;
    let password = assemble_random_password(&assembled_charset, length)
        .expect("Password generation failed.");
    assert_eq!(password.len(), length);
    for c in password.chars() {
        assert!(assembled_charset.contains(c));
    }
}
struct TestArgs {
    numbers: bool,
    uppercase: bool,
    lowercase: bool,
}

#[test]
fn test_is_strong() {
    // 弱いパスワード
    assert!(!is_strong("password"));
    // 強いパスワード
    assert!(is_strong("of5dwg6)B5*eIfG"));
}

#[test]
fn produce_secure_password_success() -> Result<(), String> {
    let chars = "ZC%M5ihKwHhn7V3";
    let length = 15;
    match produce_secure_password(chars, length) {
        Ok(password) => {
            assert_eq!(password.len(), length);
            assert!(is_strong(&password));
            Ok(())
        },
        Err(e) => Err(format!("Failed to produce secure password: {:?}", e)),
    }
}

#[test]
fn produce_secure_password_too_short() {
    let chars = "ZC%M5ihKwHhn7V3";
    let length = 10;
    let result = produce_secure_password(chars, length);
    assert!(matches!(result, Err(PasswordLengthError::TooShort)));
}

#[test]
fn handle_special_characters_with_args() {
    let bundle = get_bundle();
    let args = RupassArgs {
        language: None,
        symbols: true,
        password_length: Some(12),
        numbers: true,
        uppercase: true,
        lowercase: true,
    };
    let result = assemble_character_set(&bundle, &args);
    match result {
        Ok(char_set) => assert!(char_set.contains("!?@#$%^&*()")),
        Err(e) => panic!("Failed to assemble character set: {:?}", e),
    }
}