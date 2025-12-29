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
use crate::core::app_errors::Result;
use crate::core::utils::fallback_translation;
use crate::crypto::global_rng::ByteStream;
use crate::password::character_set::assemble_character_set;
use crate::password::password_generation::{
    GenerationOutcome, PasswordStrengthEvaluator, ZxcvbnEvaluator, produce_password_within_time,
};
use crate::password::password_length::get_password_length;
use fluent::{FluentBundle, FluentResource};
use std::fmt;
use zeroize::Zeroizing;

/// パスワード生成結果レポート
pub struct FlowReport {
    pub password: Zeroizing<String>,
    pub header: Option<String>,
    pub strength_line: Option<String>,
    pub warnings: Vec<String>,
    pub reached_target: bool,
    pub score: u8,
    pub entropy_bits: f64,
    pub show_blank_line: bool,
}

impl fmt::Debug for FlowReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowReport")
            .field("header", &self.header)
            .field("strength_line", &self.strength_line)
            .field("warnings", &self.warnings)
            .field("reached_target", &self.reached_target)
            .field("score", &self.score)
            .field("entropy_bits", &self.entropy_bits)
            .field("show_blank_line", &self.show_blank_line)
            .finish()
    }
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
/// * `rng`: バイトストリームを提供する乱数ソース。
///
/// # Returns
/// パスワード生成フローが成功した場合は [`FlowReport`] を返します。
///
/// # Errors
/// パスワード長の取得、文字セットの組み立て、またはパスワード生成中にエラーが発生した場合、
/// [`GenerationError`] を含む [`Result`] を返します。
///
/// # Notes
/// 生成されたパスワードは [`Zeroizing<String>`] でラップされ、スコープを離れる際に自動的にゼロクリアされます。
/// 出力文字列は [`FlowReport`] として返却され、表示は呼び出し元で行います。
// パスワード生成フローのエントリポイント
pub async fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    rng: &mut impl ByteStream,
) -> Result<FlowReport> {
    generate_password_flow_internal(ui, bundle, args, args.min_score, &ZxcvbnEvaluator, rng).await
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
/// * `rng`: バイトストリームを提供する乱数ソース。
///
/// # Returns
/// パスワード生成フローが成功した場合は [`FlowReport`] を返します。
///
/// # Errors
/// パスワード長の取得、文字セットの組み立て、またはパスワード生成中にエラーが発生した場合、
/// [`GenerationError`] を含む [`Result`] を返します。
pub async fn generate_password_flow_with_evaluator(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    evaluator: &dyn PasswordStrengthEvaluator,
    rng: &mut impl ByteStream,
) -> Result<FlowReport> {
    generate_password_flow_internal(ui, bundle, args, args.min_score, evaluator, rng).await
}

/// # Overview
/// 最小スコアを明示的に指定してパスワード生成フローを実行します。
///
/// # Arguments
/// * `min_score`: 早期終了判定に使用する目標スコア。
/// * `rng`: バイトストリームを提供する乱数ソース。
pub async fn generate_password_flow_with_min_score(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    min_score: u8,
    rng: &mut impl ByteStream,
) -> Result<FlowReport> {
    generate_password_flow_internal(ui, bundle, args, min_score, &ZxcvbnEvaluator, rng).await
}

async fn generate_password_flow_internal(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    min_score: u8,
    evaluator: &dyn PasswordStrengthEvaluator,
    rng: &mut impl ByteStream,
) -> Result<FlowReport> {
    let mut warnings: Vec<String> = Vec::new();
    let length = get_password_length(ui, bundle, args).await?;
    let (all_chars, req_sets) = assemble_character_set(ui, bundle, args).await?;

    let all_vec: Vec<char> = all_chars.chars().collect();
    let req_vec: Vec<Vec<char>> = req_sets.iter().map(|s| s.chars().collect()).collect();

    // min-score が 0/1 の場合は弱さを警告（stderr）。quiet時は抑制
    if (min_score == 0 || min_score == 1) && !args.quiet {
        warnings.push(format!(
            "Warning: very weak target score {} requested (0/1)",
            min_score
        ));
    }

    let outcome = produce_password_within_time(
        rng,
        &all_vec,
        &req_vec,
        length,
        args.timeout_ms,
        min_score,
        args.strict,
        evaluator,
    )
    .await;

    let outcome = outcome?;
    let GenerationOutcome {
        password,
        score,
        entropy_bits,
        reached_target,
    } = outcome;

    let header = if args.quiet {
        None
    } else {
        Some(fallback_translation(
            bundle,
            "generated_password",
            "Generated password:",
            None,
        ))
    };

    let strength_line = if !args.quiet && args.show_strength {
        use fluent::FluentArgs;
        let mut fargs = FluentArgs::new();
        fargs.set("score", score as i64);
        let entropy_str = format!("{:.1}", entropy_bits);
        fargs.set("entropyBits", entropy_str.as_str());
        Some(crate::core::utils::fallback_translation(
            bundle,
            "info_strength_line",
            &format!("Strength: {}/4 (entropy: {:.1} bits)", score, entropy_bits),
            Some(&fargs),
        ))
    } else {
        None
    };

    // 目標未達かつ非strictの場合のみ警告（stderr）
    if !reached_target && !args.strict && !args.quiet {
        use fluent::FluentArgs;
        let mut wargs = FluentArgs::new();
        wargs.set("targetScore", min_score as i64);
        wargs.set("budgetMs", args.timeout_ms as i64);
        wargs.set("bestScore", score as i64);
        let entropy_str = format!("{:.1}", entropy_bits);
        wargs.set("entropyBits", entropy_str.as_str());
        let warn_msg = crate::core::utils::fallback_translation(
            bundle,
            "warning_best_effort_used",
            &format!(
                "Warning: Could not reach target score {} within {} ms. Using best candidate: score {} ({} bits).",
                min_score, args.timeout_ms, score, entropy_str
            ),
            Some(&wargs),
        );
        warnings.push(warn_msg);
    }

    Ok(FlowReport {
        password,
        header,
        strength_line,
        warnings,
        reached_target,
        score,
        entropy_bits,
        show_blank_line: !args.quiet,
    })
}
