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
    GenerationError, Result, RupassArgs, UserInterface, generate_password_flow,
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
// 実際の翻訳ファイル (`translation/eng.ftl`) をテスト時にも読み込み、
// プロダクションと同一のリソースで検証できるようにする。
// これにより **翻訳キーの逸脱** をテスト段階で検出でき、
// i18n 機能の信頼性が向上する。  (評価項目: テスト/保守性)
fn mock_bundle() -> FluentBundle<FluentResource> {
    // ビルド時に埋め込むことで CI でもパスを気にせず利用可能
    // ※ include_str! はリテラルパス必須のため相対指定
    static FTL_ENG: &str = include_str!("../translation/eng.ftl");

    let res =
        FluentResource::try_new(FTL_ENG.to_owned()).expect("Failed to parse eng.ftl for tests");
    let mut bundle = FluentBundle::new(vec![]);
    bundle
        .add_resource(res)
        .expect("Failed to add resource to FluentBundle");
    bundle
}

// Helper
// 生成されたパスワード行を取り出す
fn extract_password(output: &str) -> Option<String> {
    output
        .split("Password Generation Result")
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
        all: false,
        no_prompt: false,
        numbers: true,
        no_numbers: false,
        uppercase: true,
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

    // lowercase? → "n"だけ回答
    let mut ui = MockUI::new(vec!["n", "n"]);
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap();

    let out = ui.outputs_joined();
    let pwd = extract_password(&out).expect("password not found");
    assert_eq!(pwd.len(), 15);
    assert!(out.contains("Password Generation Result"));
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_interactive() {
    // すべてフラグ無しで対話
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

    // ①10 → too short ②14 → too short ③15 → OK
    // その後：uppercase? n / lowercase? n / numbers? y / symbols? n
    let inputs = vec!["10", "14", "15", "n", "n", "y", "n"];
    let mut ui = MockUI::new(inputs);

    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .unwrap();

    let short_msg_count = ui
        .outputs_joined()
        .matches("A minimum of 15 characters is recommended for passwords.")
        .count();
    assert_eq!(short_msg_count, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_args() {
    let args = RupassArgs {
        language: None,
        // 不正
        password_length: Some(10),
        all: false,
        no_prompt: false,
        numbers: true,
        no_numbers: false,
        uppercase: true,
        no_uppercase: false,
        lowercase: true,
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
        no_numbers: false,
        uppercase: true,
        no_uppercase: false,
        lowercase: true,
        no_lowercase: false,
        symbols: false,
        no_symbols: false,
        symbols_set: None,
        timeout_ms: 150,
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
        all: false,
        no_prompt: false,
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

#[tokio::test(flavor = "current_thread")]
async fn custom_symbols_via_option() {
    let args = RupassArgs {
        language: None,
        password_length: Some(16),
        numbers: true,
        no_numbers: false,
        uppercase: true,
        no_uppercase: false,
        lowercase: true,
        no_lowercase: false,
        symbols: true,
        no_symbols: false,
        symbols_set: Some("[]{}".to_string()),
        timeout_ms: 150,
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
        all: false,
        no_prompt: false,
    };
    let mut ui = MockUI::default();
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .expect("generation should succeed with custom symbols option");
    let out = ui.outputs_joined();
    let pwd = extract_password(&out).expect("password not found");
    assert!(pwd.chars().any(|c| "[]{}".contains(c)));
}

#[tokio::test(flavor = "current_thread")]
async fn negative_flags_skip_prompts() {
    let args = RupassArgs {
        language: None,
        password_length: Some(16),
        numbers: true,
        no_numbers: false,
        uppercase: false,
        no_uppercase: true,
        lowercase: true,
        no_lowercase: false,
        symbols: false,
        no_symbols: true,
        symbols_set: None,
        timeout_ms: 150,
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: false,
        all: false,
        no_prompt: false,
    };
    // 否定フラグにより対話無しで進行するはず
    let mut ui = MockUI::default();
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .expect("generation should succeed without prompts");
    let out = ui.outputs_joined();
    assert!(out.contains("Password Generation Result"));
    let pwd = extract_password(&out).expect("password not found");
    assert_eq!(pwd.len(), 16);
}
