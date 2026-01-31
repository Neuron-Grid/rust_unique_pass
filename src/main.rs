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

use fluent::FluentArgs;
use rust_unique_pass::{
    FlowReport, GenerationError, Result, StdioInterface, exit_code_for_error, fallback_translation,
    generate_password_flow_with_min_score, get_global_rng, initialize_bundle, parse_args,
};
use std::process::ExitCode;

/// # Overview
/// アプリケーションのエントリポイント。
/// コマンドライン引数をパースし、国際化対応バンドルを初期化し、
/// パスワード生成フローを実行します。
/// Tokioランタイムは current_thread を明示的に使用します。
///
/// # Returns
/// 処理結果に応じて [`ExitCode`] を返します。
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = parse_args();
    let bundle = match initialize_bundle(&args) {
        Ok(bundle) => bundle,
        Err(e) => {
            eprintln!("{e}");
            return exit_code_from_i32(exit_code_for_error(&e));
        }
    };
    let mut ui = StdioInterface::default();
    let min_score = resolve_min_score(&args);
    let global_rng = match get_global_rng() {
        Ok(rng) => rng,
        Err(e) => {
            eprintln!("{e}");
            return exit_code_from_i32(exit_code_for_error(&e));
        }
    };
    let mut rng_stream = global_rng.stream();
    match generate_password_flow_with_min_score(&mut ui, &bundle, &args, min_score, &mut rng_stream)
        .await
    {
        Ok(report) => {
            if let Err(e) = render_report(&mut ui, report, &args).await {
                eprintln!("{e}");
                return exit_code_from_i32(exit_code_for_error(&e));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            // エラーコードのマッピング
            // 0: success
            // 1: 生成失敗/内部I/O 等の一般エラー
            // 2: 引数バリデーションエラー (clap が処理)
            // 3: strict未達
            let code = exit_code_for_error(&e);
            // strict未達はここでメッセージを生成してstderrに出力する
            if matches!(e, GenerationError::StrictTargetUnmet) {
                let err_msg = if args.quiet {
                    format!(
                        "Error: Could not reach target score {} within {} ms.",
                        min_score, args.timeout_ms
                    )
                } else {
                    let mut eargs = FluentArgs::new();
                    eargs.set("targetScore", min_score as i64);
                    eargs.set("budgetMs", args.timeout_ms as i64);
                    fallback_translation(
                        &bundle,
                        "error_target_unmet_strict",
                        &format!(
                            "Error: Could not reach target score {} within {} ms.",
                            min_score, args.timeout_ms
                        ),
                        Some(&eargs),
                    )
                };
                eprintln!("{err_msg}");
            } else if matches!(e, GenerationError::NoCharacterSet) {
                let err_msg = fallback_translation(
                    &bundle,
                    "error_no_charset_selected",
                    "Error: No character set selected.",
                    None,
                );
                eprintln!("{err_msg}");
            } else {
                eprintln!("{e}");
            }
            exit_code_from_i32(code)
        }
    }
}

// debug ビルド時のみ、テスト用に min_score を上書きする。
// 環境変数: RUPASS_TEST_MIN_SCORE (u8)
fn resolve_min_score(args: &rust_unique_pass::RupassArgs) -> u8 {
    let mut min_score = args.min_score;
    if cfg!(debug_assertions)
        && let Ok(raw) = std::env::var("RUPASS_TEST_MIN_SCORE")
        && let Ok(value) = raw.trim().parse::<u8>()
    {
        min_score = value;
    }
    min_score
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

async fn render_report(
    ui: &mut dyn rust_unique_pass::UserInterface,
    report: FlowReport,
    args: &rust_unique_pass::RupassArgs,
) -> Result<()> {
    if args.quiet {
        ui.print(report.password.as_str()).await?;
    } else {
        if let Some(header) = report.header.as_ref() {
            ui.print(header).await?;
        }
        ui.print(report.password.as_str()).await?;
        if report.show_blank_line {
            ui.print("").await?;
        }
        if let Some(line) = report.strength_line.as_ref() {
            ui.print(line).await?;
        }
    }

    for warning in report.warnings {
        eprintln!("{warning}");
    }

    Ok(())
}
