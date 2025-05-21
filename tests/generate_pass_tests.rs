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

use async_trait::async_trait;
use fluent::{FluentBundle, FluentResource};
use rust_unique_pass::{
    RupassArgs,
    app_errors::{GenerationError, Result},
    generate_password_flow,
    user_interface::UserInterface,
};
use std::collections::VecDeque;

// Mock UI
#[derive(Default)]
struct MockUI {
    inputs: VecDeque<String>,
    outputs: Vec<String>,
}

impl MockUI {
    fn new(src: Vec<&str>) -> Self {
        Self {
            inputs: src.into_iter().map(String::from).collect(),
            outputs: Vec::new(),
        }
    }
    fn outputs_joined(&self) -> String {
        self.outputs.join("")
    }
}

#[async_trait(?Send)]
impl UserInterface for MockUI {
    async fn prompt(&mut self, _msg: &str) -> Result<String> {
        self.inputs.pop_front().ok_or(GenerationError::InvalidInput)
    }
    async fn print(&mut self, msg: &str) -> Result<()> {
        self.outputs.push(msg.to_owned());
        Ok(())
    }
}

// Fluent bundle
// 最小の疑似翻訳
fn mock_bundle() -> FluentBundle<FluentResource> {
    let ftl = r#"
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
    let res = FluentResource::try_new(ftl.to_owned()).unwrap();
    let mut b = FluentBundle::new(vec![]);
    b.add_resource(res).unwrap();
    b
}

// Helper
// 生成されたパスワード行を取り出す
fn extract_password(output: &str) -> Option<String> {
    output
        .split("Generated password:")
        // 末尾側
        .last()
        // 改行と空白を除去
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
}
// Tests
#[tokio::test(flavor = "current_thread")]
async fn normal_flow() {
    // 事前に長さ + フラグを固定
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: true,
        uppercase: true,
        lowercase: false,
        symbols: false,
    };

    // lowercase? → "n"だけ回答
    let mut ui = MockUI::new(vec!["n", "n"]);
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap();

    let out = ui.outputs_joined();
    let pwd = extract_password(&out).expect("password not found");
    assert_eq!(pwd.len(), 15);
    assert!(out.contains("Generated password:"));
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_interactive() {
    // すべてフラグ無しで対話
    let args = RupassArgs {
        language: None,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
        symbols: false,
    };

    // ①10 → too short ②14 → too short ③15 → OK
    // その後：uppercase? n / lowercase? n / numbers? y / symbols? n
    let inputs = vec!["10", "14", "15", "n", "n", "y", "n"];
    let mut ui = MockUI::new(inputs);

    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap();

    let short_msg_count = ui
        .outputs_joined()
        .matches("Password is too short.")
        .count();
    assert_eq!(short_msg_count, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_args() {
    let args = RupassArgs {
        language: None,
        // 不正
        password_length: Some(10),
        numbers: true,
        uppercase: true,
        lowercase: true,
        symbols: false,
    };
    let mut ui = MockUI::default();
    let err = generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap_err();
    assert!(matches!(err, GenerationError::InvalidLength));
}

#[tokio::test(flavor = "current_thread")]
async fn no_charset() {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: false,
        uppercase: false,
        lowercase: false,
        symbols: false,
    };
    // uppercase? n / lowercase? n / numbers? n / symbols? n
    let mut ui = MockUI::new(vec!["n", "n", "n", "n"]);
    let err = generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap_err();
    assert!(matches!(err, GenerationError::NoCharacterSet));
}

#[tokio::test(flavor = "current_thread")]
async fn custom_symbols() {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        numbers: true,
        uppercase: true,
        lowercase: true,
        symbols: false,
    };
    // symbols? y → change? y → enter custom set
    let mut ui = MockUI::new(vec!["y", "y", "!?@#$%^&*()"]);
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap();

    let out = ui.outputs_joined();
    let pwd = extract_password(&out).expect("password not found");
    assert_eq!(pwd.len(), 15);
    assert!(pwd.chars().any(|c| "!?@#$%^&*()".contains(c)));
}
