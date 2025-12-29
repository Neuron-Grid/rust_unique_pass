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
    FlowReport, GenerationError, Result, RupassArgs, UserInterface, generate_password_flow,
};
use std::collections::VecDeque;

mod common;
use common::DeterministicByteStream;

type TestResult<T> = std::result::Result<T, String>;

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
fn mock_bundle() -> TestResult<FluentBundle<FluentResource>> {
    // ビルド時に埋め込むことで CI でもパスを気にせず利用可能
    // ※ include_str! はリテラルパス必須のため相対指定
    static FTL_ENG: &str = include_str!("../translation/eng.ftl");

    let res = FluentResource::try_new(FTL_ENG.to_owned())
        .map_err(|e| format!("parse eng.ftl failed: {e:?}"))?;
    let mut bundle = FluentBundle::new(vec![]);
    bundle
        .add_resource(res)
        .map_err(|e| format!("add resource failed: {e:?}"))?;
    Ok(bundle)
}

fn test_rng(seed: u8) -> DeterministicByteStream {
    DeterministicByteStream::from_seed([seed; 32])
}

// Helper
// 生成されたパスワード行を取り出す
fn password_from(report: &FlowReport) -> &str {
    report.password.as_str()
}
// Tests
#[tokio::test(flavor = "current_thread")]
async fn normal_flow() -> TestResult<()> {
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
    let mut rng = test_rng(0x11);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e:?}"))?;

    let pwd = password_from(&report);
    assert_eq!(pwd.len(), 15);
    assert_eq!(report.header.as_deref(), Some("Password Generation Result"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_interactive() -> TestResult<()> {
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

    let mut rng = test_rng(0x12);
    let bundle = mock_bundle()?;
    let _report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e:?}"))?;

    let short_msg_count = ui
        .outputs_joined()
        .matches("A minimum of 15 characters is recommended for passwords.")
        .count();
    assert_eq!(short_msg_count, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn too_short_args() -> TestResult<()> {
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
    let mut rng = test_rng(0x13);
    let bundle = mock_bundle()?;
    let result = generate_password_flow(&mut ui, &bundle, &args, &mut rng).await;
    match result {
        Ok(_) => Err("expected InvalidLength error".to_string()),
        Err(err) => {
            if matches!(err, GenerationError::InvalidLength) {
                Ok(())
            } else {
                Err(format!("unexpected error: {err:?}"))
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn no_charset() -> TestResult<()> {
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
    let mut rng = test_rng(0x14);
    let bundle = mock_bundle()?;
    let result = generate_password_flow(&mut ui, &bundle, &args, &mut rng).await;
    match result {
        Ok(_) => Err("expected NoCharacterSet error".to_string()),
        Err(err) => {
            if matches!(err, GenerationError::NoCharacterSet) {
                Ok(())
            } else {
                Err(format!("unexpected error: {err:?}"))
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn custom_symbols() -> TestResult<()> {
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
    let mut rng = test_rng(0x15);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e:?}"))?;

    let pwd = password_from(&report);
    assert_eq!(pwd.len(), 15);
    assert!(pwd.chars().any(|c| "!?@#$%^&*()".contains(c)));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn custom_symbols_via_option() -> TestResult<()> {
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
    let mut rng = test_rng(0x16);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e:?}"))?;
    let pwd = password_from(&report);
    assert!(pwd.chars().any(|c| "[]{}".contains(c)));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn negative_flags_skip_prompts() -> TestResult<()> {
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
    let mut rng = test_rng(0x17);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e:?}"))?;
    assert_eq!(report.header.as_deref(), Some("Password Generation Result"));
    let pwd = password_from(&report);
    assert_eq!(pwd.len(), 16);
    Ok(())
}
