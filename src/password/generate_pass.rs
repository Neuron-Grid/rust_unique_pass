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
use crate::password::password_generation::produce_password_within_time;
use crate::password::password_length::get_password_length;
use fluent::{FluentBundle, FluentResource};

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
    let gen_msg = fallback_translation(bundle, "generated_password", "Generated password:", None);
    let length = get_password_length(ui, bundle, args).await?;
    let (all_chars, req_sets) = assemble_character_set(ui, bundle, args).await?;

    let all_vec: Vec<char> = all_chars.chars().collect();
    let req_vec: Vec<Vec<char>> = req_sets.iter().map(|s| s.chars().collect()).collect();

    // min-score が 0/1 の場合は弱さを警告（stderr）。quiet時は抑制
    if (args.min_score == 0 || args.min_score == 1) && !args.quiet {
        eprintln!(
            "Warning: very weak target score {} requested (0/1)",
            args.min_score
        );
    }

    let outcome = produce_password_within_time(
        &all_vec,
        &req_vec,
        length,
        args.timeout_ms,
        args.min_score,
        args.strict,
        args.max_attempts,
    )
    .await;

    match outcome {
        Ok(res) => {
            // 通常出力
            if args.quiet {
                // パスワードのみ（stdout）。警告は抑制
                ui.print(res.password.as_str()).await?;
            } else {
                // 見出し + パスワード
                let output_msg = format!("{gen_msg}\n{}\n", res.password.as_str());
                ui.print(&output_msg).await?;

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
                    wargs.set("targetScore", args.min_score as i64);
                    wargs.set("budgetMs", args.timeout_ms as i64);
                    wargs.set("bestScore", res.score as i64);
                    let entropy_str = format!("{:.1}", res.entropy_bits);
                    wargs.set("entropyBits", entropy_str.as_str());
                    let warn_msg = crate::core::utils::fallback_translation(
                        bundle,
                        "warning_best_effort_used",
                        &format!(
                            "Warning: Could not reach target score {} within {} ms. Using best candidate: score {} ({} bits).",
                            args.min_score, args.timeout_ms, res.score, entropy_str
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
                        eargs.set("targetScore", args.min_score as i64);
                        eargs.set("budgetMs", args.timeout_ms as i64);
                        let err_msg = crate::core::utils::fallback_translation(
                            bundle,
                            "error_target_unmet_strict",
                            &format!(
                                "Error: Could not reach target score {} within {} ms.",
                                args.min_score, args.timeout_ms
                            ),
                            Some(&eargs),
                        );
                        eprintln!("{}", err_msg);
                    } else {
                        // quietでもエラーは stderr に出す
                        eprintln!(
                            "Error: Could not reach target score {} within {} ms.",
                            args.min_score, args.timeout_ms
                        );
                    }
                    Err(GenerationError::StrictTargetUnmet)
                }
                other => Err(other),
            }
        }
    }
}
