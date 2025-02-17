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

use fluent::{FluentBundle, FluentResource};
use rust_unique_pass::user_interface::UserInterface;
use rust_unique_pass::{generate_password_flow, GenerationError, Result, RupassArgs};

/// テスト用のMock UI
/// 指定された入力列を順番に返し、printの内容は内部に保存する。
struct MockUI {
    /// promptで返す入力のキュー
    inputs: Vec<String>,
    /// printされた内容を保存するバッファ
    outputs: Vec<String>,
}

impl MockUI {
    fn new(inputs: Vec<&str>) -> Self {
        Self {
            inputs: inputs.into_iter().map(|s| s.to_string()).collect(),
            outputs: Vec::new(),
        }
    }

    /// テスト後に出力内容を確認しやすくするためのヘルパー
    fn get_outputs(&self) -> &[String] {
        &self.outputs
    }
}

impl UserInterface for MockUI {
    fn prompt(&mut self, _message: &str) -> Result<String> {
        if let Some(input) = self.inputs.pop() {
            Ok(input)
        } else {
            // 入力が尽きたらエラーを返す
            Err(GenerationError::InvalidInput)
        }
    }

    fn print(&mut self, message: &str) {
        self.outputs.push(message.to_string());
    }
}

/// 実際の翻訳バンドルを読み込みたくない/できない場合のため、
/// モック的なBundleを作るヘルパー関数
fn mock_fluent_bundle() -> FluentBundle<FluentResource> {
    // ここでは最小限の翻訳データを直接文字列定義
    let ftl_string = r#"
generated_password = Generated password:
error_no_charset_selected = No valid character set was selected.
error_generation = Error generating password.
error_password_too_short = Password is too short.
question_password_length = Enter password length:
question_uppercase = Include uppercase letters?
question_lowercase = Include lowercase letters?
question_numbers = Include numbers?
default_special_chars_message = Default special chars: { $specialChars }
question_special_chars = Use special characters?
question_change_special_chars = Change the default special chars?
question_enter_special_chars = Enter special chars:
error_invalid_input = Invalid input. Please enter yes or no.
"#;
    let resource = FluentResource::try_new(ftl_string.to_string()).expect("Failed to parse FTL");
    let mut bundle = FluentBundle::new(vec![]);
    bundle
        .add_resource(resource)
        .expect("Failed to add FTL resource");
    bundle
}

/// テスト1: 正常系 (15文字, uppercase/numbersフラグのみtrue)
#[test]
fn test_generate_password_flow_normal() {
    // コマンドライン引数を想定
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: true,
        uppercase: true,
        lowercase: false,
        symbols: false,
    };

    // バンドルはモック化
    let bundle = mock_fluent_bundle();

    // uppercase+numbersのみの文字セットで15文字パスが生成される想定
    let mut ui = MockUI::new(vec![
        "n", // lowercase
        "n", // symbols
    ]);

    let result = generate_password_flow(&mut ui, &bundle, &args);
    assert!(result.is_ok());

    // 出力に "Generated password:" が含まれているか
    let out = ui.get_outputs().join("\n");
    assert!(
        out.contains("Generated password:"),
        "Should contain 'Generated password:' text"
    );

    // 返されたパスワードの長さ確認
    let generated_password = result.unwrap();
    assert_eq!(generated_password.len(), 15);
}

/// パスワード長が短い場合のエラー (対話モード)
#[test]
fn test_generate_password_flow_too_short_interactive() {
    // 対話入力をしない (CLI引数なし) 場合 -> get_password_length が最初に呼ばれる
    let args = RupassArgs {
        language: None,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
        symbols: false,
    };
    let bundle = mock_fluent_bundle(); // テスト用バンドル

    // 入力の順序に注意
    // 最初の3回の入力はパスワード長用 (10 -> エラー, 14 -> エラー, 15 -> OK)
    // その後 uppercase? -> n, lowercase? -> y, numbers? -> n, special chars? -> n
    let mut ui = MockUI::new(vec![
        "n",  // 7th pop -> special chars
        "n",  // 6th pop -> numbers?
        "y",  // 5th pop -> lowercase?
        "n",  // 4th pop -> uppercase?
        "15", // 3rd pop -> password length = 15
        "14", // 2nd pop -> password length = 14
        "10", // 1st pop -> password length = 10
    ]);

    let result = generate_password_flow(&mut ui, &bundle, &args);
    assert!(result.is_ok(), "Should eventually succeed with length 15");

    // 短すぎるパスワード時に2回エラーメッセージが表示されるはず
    let out = ui.get_outputs().join("\n");
    let count_too_short = out.matches("Password is too short.").count();
    assert_eq!(count_too_short, 2, "Should show 'too short' message twice");
}

/// 引数でパスワード長 10 (15未満) を指定した場合 -> 即エラー
#[test]
fn test_generate_password_flow_too_short_args() {
    let args = RupassArgs {
        language: None,
        password_length: Some(10),
        numbers: true,
        uppercase: true,
        lowercase: true,
        symbols: false,
    };
    let bundle = mock_fluent_bundle();
    let mut ui = MockUI::new(vec![]);

    let result = generate_password_flow(&mut ui, &bundle, &args);
    assert!(result.is_err());
    match result {
        Err(GenerationError::InvalidLength) => {}
        other => panic!("Expected InvalidLength, got {:?}", other),
    }
}

/// 文字種を一切選ばず空集合 -> NoCharacterSetエラー
#[test]
fn test_no_charset() {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: false,
        uppercase: false,
        lowercase: false,
        symbols: false,
    };
    let bundle = mock_fluent_bundle();

    // uppercase? -> n
    // lowercase? -> n
    // numbers? -> n
    // use special chars? -> n
    let mut ui = MockUI::new(vec!["n", "n", "n", "n"]);

    let result = generate_password_flow(&mut ui, &bundle, &args);
    assert!(matches!(result, Err(GenerationError::NoCharacterSet)));
}

/// 特殊文字を指定 (対話入力で変更) し、強度判定に通るパスワードが生成されるか
/// 実際のzxcvbnスコアが4に到達するかどうかはランダムの要素が大きいため、厳密には検証しない。
#[test]
fn test_generate_password_with_symbols() {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: true,
        uppercase: true,
        lowercase: true,
        symbols: false, // フラグはfalseでも後から"y"と答えると使える
    };
    let bundle = mock_fluent_bundle();

    // ユーザー入力
    //  1) question_lowercase? => すでにtrueなので聞かれない (実際のコードでは聞かれない想定)
    //  2) question_special_chars? => "y"
    //  3) question_change_special_chars? => "y"
    //  4) question_enter_special_chars? => "!?@#$%^&*()"
    let mut ui = MockUI::new(vec!["!?@#$%^&*()", "y", "y"]);

    let result = generate_password_flow(&mut ui, &bundle, &args);
    assert!(
        result.is_ok(),
        "Should generate a password with custom symbols"
    );

    let generated_password = result.unwrap();
    assert_eq!(generated_password.len(), 15);
    // "!?@#$%^&*()" のいずれかが含まれているか(必須文字セット)
    let contains_custom_symbol = generated_password
        .chars()
        .any(|c| "!?@#$%^&*()".contains(c));
    assert!(
        contains_custom_symbol,
        "Generated password should contain custom symbols"
    );
}
