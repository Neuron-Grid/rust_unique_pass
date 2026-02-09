/* Copyright 2023-2025 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use crate::cli::{RupassArgs, StdioInterface, UserInterface, parse_args};
use crate::core::app_errors::GenerationError;
use crate::core::utils::fallback_translation;
use crate::crypto::global_rng::GlobalRngStream;
use crate::password::FlowReport;
use crate::{
    exit_code_for_error, generate_password_flow_with_min_score, get_global_rng, initialize_bundle,
};
use fluent::{FluentArgs, FluentBundle, FluentResource};
use std::process::ExitCode;

/// CLI 出力の組み立て結果
pub struct ReportOutput<'a> {
    pub stdout: Vec<&'a str>,
    pub stderr: Vec<String>,
}

/// # Overview
/// CLI 実行フローをまとめて実行します。
pub async fn run_cli() -> ExitCode {
    let args = parse_args();
    run_cli_with_args(args).await
}

// CLI 実行フローを分割し、main からの呼び出しを単純化する
async fn run_cli_with_args(args: RupassArgs) -> ExitCode {
    let bundle = match init_bundle_or_exit(&args) {
        Ok(bundle) => bundle,
        Err(code) => return code,
    };
    let mut ui = StdioInterface::default();
    let min_score = resolve_min_score(&args);
    let mut rng_stream = match init_rng_stream_or_exit() {
        Ok(stream) => stream,
        Err(code) => return code,
    };

    match run_generation_flow(&mut ui, &bundle, &args, min_score, &mut rng_stream).await {
        Ok(report) => render_report_or_exit(&mut ui, &report, &args, &bundle).await,
        Err(e) => handle_generation_error(&e, &args, &bundle, min_score),
    }
}

// バンドル初期化の共通化
fn init_bundle_or_exit(
    args: &RupassArgs,
) -> std::result::Result<FluentBundle<FluentResource>, ExitCode> {
    match initialize_bundle(args) {
        Ok(bundle) => Ok(bundle),
        Err(e) => {
            eprintln!("{e}");
            Err(exit_code_from_i32(exit_code_for_error(&e)))
        }
    }
}

// グローバルRNGストリームの初期化
fn init_rng_stream_or_exit() -> std::result::Result<GlobalRngStream, ExitCode> {
    match get_global_rng() {
        Ok(rng) => Ok(rng.stream()),
        Err(e) => {
            eprintln!("{e}");
            Err(exit_code_from_i32(exit_code_for_error(&e)))
        }
    }
}

// 生成処理の呼び出しを分離
async fn run_generation_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    min_score: u8,
    rng_stream: &mut impl crate::crypto::global_rng::ByteStream,
) -> Result<FlowReport, GenerationError> {
    generate_password_flow_with_min_score(ui, bundle, args, min_score, rng_stream).await
}

// レポート出力のエラーハンドリングを共通化
async fn render_report_or_exit(
    ui: &mut dyn UserInterface,
    report: &FlowReport,
    args: &RupassArgs,
    bundle: &FluentBundle<FluentResource>,
) -> ExitCode {
    match render_report(ui, report, args, bundle).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            exit_code_from_i32(exit_code_for_error(&e))
        }
    }
}

// 生成失敗時のメッセージ整形と終了コードを集約
fn handle_generation_error(
    err: &GenerationError,
    args: &RupassArgs,
    bundle: &FluentBundle<FluentResource>,
    min_score: u8,
) -> ExitCode {
    let code = exit_code_for_error(err);
    let err_msg = format_generation_error(err, args, bundle, min_score);
    eprintln!("{err_msg}");
    exit_code_from_i32(code)
}

/// # Overview
/// レポートから CLI 出力内容を組み立てます。
pub fn build_report_output<'a>(
    report: &'a FlowReport,
    args: &RupassArgs,
    bundle: &FluentBundle<FluentResource>,
) -> ReportOutput<'a> {
    let mut stdout: Vec<&'a str> = Vec::new();
    if args.quiet {
        stdout.push(report.password.as_str());
    } else {
        if let Some(header) = report.header.as_deref() {
            stdout.push(header);
        }
        stdout.push(report.password.as_str());
        if report.show_blank_line {
            stdout.push("");
        }
        if let Some(line) = report.strength_line.as_deref() {
            stdout.push(line);
        }
    }

    let stderr = report
        .warnings
        .iter()
        .map(|warning| warning.to_message(bundle))
        .collect();

    ReportOutput { stdout, stderr }
}

/// # Overview
/// 生成結果レポートを標準出力/標準エラーに書き出します。
async fn render_report(
    ui: &mut dyn UserInterface,
    report: &FlowReport,
    args: &RupassArgs,
    bundle: &FluentBundle<FluentResource>,
) -> crate::core::app_errors::Result<()> {
    let output = build_report_output(report, args, bundle);
    for line in output.stdout {
        ui.print(line).await?;
    }
    for warning in output.stderr {
        eprintln!("{warning}");
    }
    Ok(())
}

/// CLI 向けエラーメッセージの種別
enum UserFacingError {
    StrictTargetUnmet {
        min_score: u8,
        timeout_ms: u64,
        quiet: bool,
    },
    NoCharacterSet,
    Other(String),
}

impl UserFacingError {
    fn from_generation_error(err: &GenerationError, args: &RupassArgs, min_score: u8) -> Self {
        match err {
            GenerationError::StrictTargetUnmet => UserFacingError::StrictTargetUnmet {
                min_score,
                timeout_ms: args.timeout_ms,
                quiet: args.quiet,
            },
            GenerationError::NoCharacterSet => UserFacingError::NoCharacterSet,
            _ => UserFacingError::Other(err.to_string()),
        }
    }

    fn to_message(&self, bundle: &FluentBundle<FluentResource>) -> String {
        match self {
            UserFacingError::StrictTargetUnmet {
                min_score,
                timeout_ms,
                quiet,
            } => {
                let default_msg = format!(
                    "Error: Could not reach target score {} within {} ms.",
                    min_score, timeout_ms
                );
                if *quiet {
                    return default_msg;
                }
                let mut eargs = FluentArgs::new();
                eargs.set("targetScore", *min_score as i64);
                eargs.set("budgetMs", *timeout_ms as i64);
                fallback_translation(
                    bundle,
                    "error_target_unmet_strict",
                    &default_msg,
                    Some(&eargs),
                )
            }
            UserFacingError::NoCharacterSet => fallback_translation(
                bundle,
                "error_no_charset_selected",
                "Error: No character set selected.",
                None,
            ),
            UserFacingError::Other(msg) => msg.clone(),
        }
    }
}

/// # Overview
/// 生成エラーを CLI 向けメッセージに変換します。
pub fn format_generation_error(
    err: &GenerationError,
    args: &RupassArgs,
    bundle: &FluentBundle<FluentResource>,
    min_score: u8,
) -> String {
    let user_error = UserFacingError::from_generation_error(err, args, min_score);
    user_error.to_message(bundle)
}

// 本番経路では、常にCLI引数の値を使用する。
#[cfg(not(test))]
fn resolve_min_score(args: &RupassArgs) -> u8 {
    args.min_score
}

// テスト時のみ、環境変数による上書きを許可する。
#[cfg(test)]
fn resolve_min_score(args: &RupassArgs) -> u8 {
    let override_raw = std::env::var("RUPASS_TEST_MIN_SCORE").ok();
    resolve_min_score_from_override(args, override_raw.as_deref())
}

#[cfg(test)]
fn resolve_min_score_from_override(args: &RupassArgs, override_raw: Option<&str>) -> u8 {
    match override_raw.and_then(parse_test_min_score_override) {
        Some(score) => score,
        None => args.min_score,
    }
}

#[cfg(test)]
fn parse_test_min_score_override(raw: &str) -> Option<u8> {
    let parsed = match raw.trim().parse::<u8>() {
        Ok(value) => value,
        Err(_) => return None,
    };
    if parsed <= 4 { Some(parsed) } else { None }
}

// 終了コードの範囲をu8へ正規化する
fn exit_code_from_i32(code: i32) -> ExitCode {
    let code_u8 = if (0..=u8::MAX as i32).contains(&code) {
        code as u8
    } else {
        1
    };
    ExitCode::from(code_u8)
}

#[cfg(test)]
#[path = "../../tests/unit/reporting_tests.rs"]
mod reporting_tests;
