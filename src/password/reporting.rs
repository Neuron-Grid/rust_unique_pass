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
use crate::core::utils::fallback_translation;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use std::fmt;
use zeroize::Zeroizing;

/// パスワード生成結果レポート
pub struct FlowReport {
    pub password: Zeroizing<String>,
    pub header: Option<String>,
    pub strength_line: Option<String>,
    pub warnings: Vec<Warning>,
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

/// 警告の種別
#[derive(Debug, Clone)]
pub enum Warning {
    WeakTargetScore(u8),
    BestEffort {
        target_score: u8,
        budget_ms: u64,
        best_score: u8,
        entropy_bits: f64,
    },
}

impl Warning {
    pub(crate) fn to_message(&self, bundle: &FluentBundle<FluentResource>) -> String {
        match self {
            Warning::WeakTargetScore(score) => {
                format!("Warning: very weak target score {} requested (0/1)", score)
            }
            Warning::BestEffort {
                target_score,
                budget_ms,
                best_score,
                entropy_bits,
            } => {
                let mut wargs = FluentArgs::new();
                wargs.set("targetScore", *target_score as i64);
                wargs.set("budgetMs", *budget_ms as i64);
                wargs.set("bestScore", *best_score as i64);
                let entropy_str = format!("{:.1}", entropy_bits);
                wargs.set("entropyBits", entropy_str.as_str());
                fallback_translation(
                    bundle,
                    "warning_best_effort_used",
                    &format!(
                        "Warning: Could not reach target score {} within {} ms. Using best candidate: score {} ({} bits).",
                        target_score, budget_ms, best_score, entropy_str
                    ),
                    Some(&wargs),
                )
            }
        }
    }
}

/// # Overview
/// 成功時ヘッダーを構築します。
pub(crate) fn build_header(
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Option<String> {
    if args.quiet {
        None
    } else {
        Some(fallback_translation(
            bundle,
            "generated_password",
            "Generated password:",
            None,
        ))
    }
}

/// # Overview
/// 強度行の表示可否と内容を決定します。
pub(crate) fn build_strength_line(
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    score: u8,
    entropy_bits: f64,
) -> Option<String> {
    if args.quiet || !args.show_strength {
        return None;
    }

    let mut fargs = FluentArgs::new();
    fargs.set("score", score as i64);
    let entropy_str = format!("{:.1}", entropy_bits);
    fargs.set("entropyBits", entropy_str.as_str());
    Some(fallback_translation(
        bundle,
        "info_strength_line",
        &format!("Strength: {}/4 (entropy: {:.1} bits)", score, entropy_bits),
        Some(&fargs),
    ))
}

/// # Overview
/// 警告メッセージをまとめて構築します（出力は呼び出し元）。
pub(crate) fn build_warnings(
    args: &RupassArgs,
    min_score: u8,
    reached_target: bool,
    score: u8,
    entropy_bits: f64,
) -> Vec<Warning> {
    let weak_warning = weak_score_warning(min_score, args.quiet);
    let best_effort_warning =
        best_effort_warning(args, min_score, reached_target, score, entropy_bits);

    [weak_warning, best_effort_warning]
        .into_iter()
        .flatten()
        .collect()
}

/// # Overview
/// min_score が低すぎる場合の警告を生成します。
fn weak_score_warning(min_score: u8, quiet: bool) -> Option<Warning> {
    if quiet {
        return None;
    }
    if min_score == 0 || min_score == 1 {
        Some(Warning::WeakTargetScore(min_score))
    } else {
        None
    }
}

/// # Overview
/// 目標未達のベストエフォート警告を生成します。
fn best_effort_warning(
    args: &RupassArgs,
    min_score: u8,
    reached_target: bool,
    score: u8,
    entropy_bits: f64,
) -> Option<Warning> {
    if reached_target || args.strict || args.quiet {
        return None;
    }

    Some(Warning::BestEffort {
        target_score: min_score,
        budget_ms: args.timeout_ms,
        best_score: score,
        entropy_bits,
    })
}
