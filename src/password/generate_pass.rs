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

use crate::cli::RupassArgs;
use crate::cli::UserInterface;
use crate::core::app_errors::GenerationError;
use crate::core::app_errors::Result;
use crate::core::utils::fallback_translation;
use crate::password::character_set::assemble_character_set;
use crate::password::password_generation::{
    PasswordStrengthEvaluator, ZxcvbnEvaluator, produce_password_within_time,
    produce_password_within_time_sync,
};
use crate::password::password_length::get_password_length;
use fluent::{FluentBundle, FluentResource};

// debug ビルド時のみ、テスト用に min_score を上書きする。
// 環境変数: RUPASS_TEST_MIN_SCORE (u8)
fn resolve_min_score(args: &RupassArgs) -> u8 {
    let mut min_score = args.min_score;
    if cfg!(debug_assertions)
        && let Ok(raw) = std::env::var("RUPASS_TEST_MIN_SCORE")
        && let Ok(value) = raw.trim().parse::<u8>()
    {
        min_score = value;
    }
    min_score
}

#[doc(alias = "generate")]
/// # Overview
/// パスワード生成の主要なフローを実行します。
/// ユーザーインターフェースを通じてパスワード長と使用文字セットを取得し、
/// 安全なパスワードを生成して表示します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// パスワード生成フローが成功した場合は `Ok(())` を返します。
///
/// # Errors
/// パスワード長の取得、文字セットの組み立て、またはパスワード生成中にエラーが発生した場合、
/// [`GenerationError`] を含む [`Result`] を返します。
///
/// # Notes
/// パスワード生成処理は計算コストが高いため、ブロッキングスレッドプール
/// (`tokio::task::spawn_blocking`) で実行されます。
/// 生成されたパスワードは [`Zeroizing<String>`] でラップされ、スコープを離れる際に自動的にゼロクリアされます。
// パスワード生成フローのエントリポイント
pub async fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<()> {
    generate_password_flow_internal(ui, bundle, args, GenerationMode::SpawnBlocking).await
}

#[doc(alias = "generate")]
/// # Overview
/// 評価器を差し替えてパスワード生成フローを実行します。
/// 生成時の評価ロジックをテストや実験用途で差し替えるための入口です。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
/// * `evaluator`: パスワード強度評価に使用する評価器。
///
/// # Returns
/// パスワード生成フローが成功した場合は `Ok(())` を返します。
///
/// # Errors
/// パスワード長の取得、文字セットの組み立て、またはパスワード生成中にエラーが発生した場合、
/// [`GenerationError`] を含む [`Result`] を返します。
pub async fn generate_password_flow_with_evaluator(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<()> {
    generate_password_flow_internal(ui, bundle, args, GenerationMode::Inline(evaluator)).await
}

enum GenerationMode<'a> {
    Inline(&'a dyn PasswordStrengthEvaluator),
    SpawnBlocking,
}

async fn generate_password_flow_internal(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    mode: GenerationMode<'_>,
) -> Result<()> {
    // テスト用の上書きは debug ビルドのみで有効
    let min_score = resolve_min_score(args);
    let gen_msg = fallback_translation(bundle, "generated_password", "Generated password:", None);
    let length = get_password_length(ui, bundle, args).await?;
    let (all_chars, req_sets) = assemble_character_set(ui, bundle, args).await?;

    let all_vec: Vec<char> = all_chars.chars().collect();
    let req_vec: Vec<Vec<char>> = req_sets.iter().map(|s| s.chars().collect()).collect();

    // min-score が 0/1 の場合は弱さを警告（stderr）。quiet時は抑制
    if (min_score == 0 || min_score == 1) && !args.quiet {
        eprintln!(
            "Warning: very weak target score {} requested (0/1)",
            min_score
        );
    }

    let outcome = match mode {
        GenerationMode::Inline(eval) => {
            produce_password_within_time(
                &all_vec,
                &req_vec,
                length,
                args.timeout_ms,
                min_score,
                args.strict,
                eval,
            )
            .await
        }
        GenerationMode::SpawnBlocking => {
            let all_vec = all_vec.clone();
            let req_vec = req_vec.clone();
            let timeout_ms = args.timeout_ms;
            let strict = args.strict;
            tokio::task::spawn_blocking(move || {
                let evaluator = ZxcvbnEvaluator;
                produce_password_within_time_sync(
                    &all_vec, &req_vec, length, timeout_ms, min_score, strict, &evaluator,
                )
            })
            .await
            .map_err(|e| {
                GenerationError::IoError(std::io::Error::other(format!(
                    "spawn_blocking failed: {e}"
                )))
            })?
        }
    };

    match outcome {
        Ok(res) => {
            // 通常出力
            if args.quiet {
                // パスワードのみ（stdout）。警告は抑制
                ui.print(res.password.as_str()).await?;
            } else {
                // 見出し + パスワードを逐次出力して複製を避ける
                ui.print(gen_msg.as_str()).await?;
                ui.print(res.password.as_str()).await?;
                ui.print("").await?;

                // --show-strength 指定時のみ強度行を stdout に追加
                if args.show_strength {
                    use fluent::FluentArgs;
                    let mut fargs = FluentArgs::new();
                    fargs.set("score", res.score as i64);
                    let entropy_str = format!("{:.1}", res.entropy_bits);
                    fargs.set("entropyBits", entropy_str.as_str());
                    let strength_line = crate::core::utils::fallback_translation(
                        bundle,
                        "info_strength_line",
                        &format!(
                            "Strength: {}/4 (entropy: {:.1} bits)",
                            res.score, res.entropy_bits
                        ),
                        Some(&fargs),
                    );
                    ui.print(&strength_line).await?;
                }

                // 目標未達かつ非strictの場合のみ警告（stderr）
                if !res.reached_target && !args.strict {
                    use fluent::FluentArgs;
                    let mut wargs = FluentArgs::new();
                    wargs.set("targetScore", min_score as i64);
                    wargs.set("budgetMs", args.timeout_ms as i64);
                    wargs.set("bestScore", res.score as i64);
                    let entropy_str = format!("{:.1}", res.entropy_bits);
                    wargs.set("entropyBits", entropy_str.as_str());
                    let warn_msg = crate::core::utils::fallback_translation(
                        bundle,
                        "warning_best_effort_used",
                        &format!(
                            "Warning: Could not reach target score {} within {} ms. Using best candidate: score {} ({} bits).",
                            min_score, args.timeout_ms, res.score, entropy_str
                        ),
                        Some(&wargs),
                    );
                    eprintln!("{}", warn_msg);
                }
            }

            // スコープ離脱で自動zeroize
            drop(res);
            Ok(())
        }
        Err(e) => {
            // strict 未達等のエラー処理（stderr）
            match e {
                GenerationError::StrictTargetUnmet => {
                    if !args.quiet {
                        use fluent::FluentArgs;
                        let mut eargs = FluentArgs::new();
                        eargs.set("targetScore", min_score as i64);
                        eargs.set("budgetMs", args.timeout_ms as i64);
                        let err_msg = crate::core::utils::fallback_translation(
                            bundle,
                            "error_target_unmet_strict",
                            &format!(
                                "Error: Could not reach target score {} within {} ms.",
                                min_score, args.timeout_ms
                            ),
                            Some(&eargs),
                        );
                        eprintln!("{}", err_msg);
                    } else {
                        // quietでもエラーは stderr に出す
                        eprintln!(
                            "Error: Could not reach target score {} within {} ms.",
                            min_score, args.timeout_ms
                        );
                    }
                    Err(GenerationError::StrictTargetUnmet)
                }
                other => Err(other),
            }
        }
    }
}
