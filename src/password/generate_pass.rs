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
use crate::crypto::global_rng::ByteStream;
use crate::password::character_set::assemble_character_set;
use crate::password::password_generation::{
    GenerationOutcome, PasswordStrengthEvaluator, ZxcvbnEvaluator, produce_password_within_time,
    validate_charset_feasibility,
};
use crate::password::password_length::get_password_length;
use crate::password::reporting::{FlowReport, build_header, build_strength_line, build_warnings};
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
    let length = get_password_length(ui, bundle, args).await?;
    let (all_chars, req_sets) = assemble_character_set(ui, bundle, args).await?;

    let all_vec: Vec<char> = all_chars.chars().collect();
    let req_vec: Vec<Vec<char>> = req_sets.iter().map(|s| s.chars().collect()).collect();

    // 到達可能性の事前検査: DoS 防御。この構成では MAX_PASSWORD_BYTES を
    // 超える候補しか出ないケースを探索ループの前に弾く。
    validate_charset_feasibility(&all_vec, &req_vec, length)?;

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

    let header = build_header(bundle, args);
    let strength_line = build_strength_line(bundle, args, score, entropy_bits);
    let warnings = build_warnings(args, min_score, reached_target, score, entropy_bits);

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
