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

use crate::core::app_errors::{GenerationError, Result};
use crate::crypto::global_rng::get_global_rng;
use crate::crypto::zxcvbn_wrapper::zxcvbn_entropy_score;
use crate::password::password_length::validate_password_length;
use std::convert::TryInto;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::{Score, zxcvbn};

const MAX_GENERATION_ATTEMPTS: usize = 500000;
const STRENGTH_CHECK_INTERVAL: usize = 10;

/// N回に1回だけ`Instant::now()`を評価するための間引き係数
const NOW_CHECK_INTERVAL: u64 = 32;

/// 時間予算による生成結果
pub struct GenerationOutcome {
    pub password: Zeroizing<String>,
    pub score: u8,
    pub entropy_bits: f64,
    pub reached_target: bool,
}

/// 強度評価抽象化トレイト
pub trait PasswordStrengthEvaluator {
    fn score_entropy(&self, pwd: &str) -> (u8, f64);
}

/// 実装: zxcvbn を用いた評価器
pub struct ZxcvbnEvaluator;

impl PasswordStrengthEvaluator for ZxcvbnEvaluator {
    fn score_entropy(&self, pwd: &str) -> (u8, f64) {
        match zxcvbn_entropy_score(pwd) {
            Ok((bits, score)) => (score, bits),
            Err(_e) => (0, 0.0),
        }
    }
}

/// # Overview
/// 指定の時間予算と最大試行回数の範囲で、zxcvbnスコア/エントロピーに基づいて
/// パスワードを探索します。`min_score` 到達で早期終了します。
pub async fn produce_password_within_time(
    all_vec: &[char],
    req: &[Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
    max_attempts: u64,
) -> Result<GenerationOutcome> {
    validate_password_length(len)?;
    if all_vec.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }
    if req.len() > len {
        return Err(GenerationError::InvalidLength);
    }

    let evaluator = ZxcvbnEvaluator;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut attempts: u64 = 0;
    let mut best_pwd: Option<Zeroizing<String>> = None;
    let mut best_score: u8 = 0;
    let mut best_bits: f64 = 0.0;

    while attempts < max_attempts {
        attempts += 1;

        if let Some(mut candidate) = assemble_random_password(all_vec, len, req).await {
            if candidate.len() != len {
                candidate.zeroize();
                continue;
            }
            // 軽量フィルタ: ごく弱い候補をスキップ
            if candidate.len() < 8 {
                candidate.zeroize();
                continue;
            } else if candidate
                .chars()
                .all(|c| c == candidate.chars().next().unwrap_or('\0'))
            {
                // 全て同一文字
                candidate.zeroize();
            } else {
                let (score, bits) = evaluator.score_entropy(&candidate);

                // ベスト更新ルール: スコア優先、同点ならエントロピー優先
                if score > best_score || (score == best_score && bits > best_bits) {
                    best_score = score;
                    best_bits = bits;
                    best_pwd = Some(Zeroizing::new(candidate.clone()));
                }

                if score >= min_score {
                    let pwd = Zeroizing::new(candidate);
                    return Ok(GenerationOutcome {
                        password: pwd,
                        score,
                        entropy_bits: bits,
                        reached_target: true,
                    });
                }

                candidate.zeroize();
            }
        }

        // 時間チェック（間引き）
        #[allow(clippy::manual_is_multiple_of)] // modulus-based check keeps MSRV compatibility
        if attempts % NOW_CHECK_INTERVAL == 0 && Instant::now() >= deadline {
            break;
        }
    }

    // 期限切れ/回数到達
    if let Some(pwd) = best_pwd {
        if strict && best_score < min_score {
            return Err(GenerationError::StrictTargetUnmet);
        }
        return Ok(GenerationOutcome {
            password: pwd,
            score: best_score,
            entropy_bits: best_bits,
            reached_target: false,
        });
    }

    Err(GenerationError::GenerationFailed)
}

/// # Overview
/// 指定された文字セットと長さに基づいて、安全なパスワードを生成します。
///
/// # Arguments
/// * `all_vec`: パスワードに使用可能な全ての文字を含むスライス。
/// * `len`: 生成するパスワードの長さ。
/// * `req`: パスワードに最低1文字含める必要がある文字セットのリストを含むスライス。
///
/// # Returns
/// 安全なパスワードが生成された場合、[`Zeroizing<String>`] でラップされたパスワードを返します。
#[doc(alias = "generate")]
#[doc(alias = "password")]
#[doc(alias = "secure")]
pub async fn produce_secure_password(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Zeroizing<String>> {
    validate_password_length(len)?;

    // 入力検証の強化
    if all_vec.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }
    if req.len() > len {
        return Err(GenerationError::InvalidLength);
    }

    let mut candidates = Vec::with_capacity(STRENGTH_CHECK_INTERVAL);

    for attempt in 1..=MAX_GENERATION_ATTEMPTS {
        if let Some(pwd) = assemble_random_password(all_vec, len, req).await {
            candidates.push(pwd);

            // 定期的にバッチで強度チェック - CPU効率改善
            if attempt % STRENGTH_CHECK_INTERVAL == 0 || attempt == MAX_GENERATION_ATTEMPTS {
                for candidate in candidates.drain(..) {
                    if is_strong(&candidate) {
                        return Ok(Zeroizing::new(candidate));
                    }
                }
            }
        }

        // 進捗報告（大量の試行時の可視性向上）
        if attempt % 10_000 == 0 {}
    }

    Err(GenerationError::GenerationFailed)
}

pub async fn assemble_random_password(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Option<String> {
    if all_vec.is_empty() {
        return None;
    }

    // グローバルRNGインスタンスを使用
    // パフォーマンス向上
    let global_rng = match get_global_rng() {
        Ok(rng) => rng,
        Err(_) => return None,
    };

    // 乱数バッファ準備
    // secure_random_index は 8 バイト単位で消費し、
    // リジェクションが発生すると追加でバイトを消費する。
    // 予備を十分に確保してバッファ枯渇による None を防ぐ。
    let mut random_bytes = vec![0u8; len * 16]; // 以前: len*4
    if global_rng.generate_bytes(&mut random_bytes).is_err() {
        return None;
    }

    let mut rng_adapter = BytesToIndexAdapter::new(&random_bytes);

    // 各必須セットから1文字ずつ
    let need: Vec<char> = req
        .iter()
        .filter_map(|set| {
            if set.is_empty() {
                return None;
            }
            let index = rng_adapter.next_index(set.len())?;
            set.get(index).copied()
        })
        .collect();

    if need.len() > len {
        return None;
    }

    let rest = len - need.len();
    let mut pwd: Vec<char> = need;

    // 残りの文字をランダム選択
    for _ in 0..rest {
        if let Some(index) = rng_adapter.next_index(all_vec.len())
            && let Some(&ch) = all_vec.get(index)
        {
            pwd.push(ch);
        }
    }

    // Fisher-Yatesアルゴリズムでシャッフル
    for i in (1..pwd.len()).rev() {
        if let Some(j) = rng_adapter.next_index(i + 1) {
            pwd.swap(i, j);
        }
    }

    Some(pwd.iter().collect())
}

/// バイト配列をインデックスに変換するアダプタ
/// 偏りの少ない変換を提供
struct BytesToIndexAdapter<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BytesToIndexAdapter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn next_index(&mut self, max: usize) -> Option<usize> {
        if max == 0 {
            return None;
        }

        // 2 の累乗に切り上げたマスクを計算
        let mask = max.next_power_of_two().saturating_sub(1);

        loop {
            // 可能な限り usize 長 (8バイト) をまとめて読み取る
            let value: usize = if self.position + std::mem::size_of::<usize>() <= self.bytes.len() {
                let slice =
                    &self.bytes[self.position..self.position + std::mem::size_of::<usize>()];
                self.position += std::mem::size_of::<usize>();
                usize::from_le_bytes(slice.try_into().expect("slice with incorrect length"))
            } else if self.position < self.bytes.len() {
                // 残バイトが 8 未満の場合は 1 バイトだけ使用
                let byte = self.bytes[self.position];
                self.position += 1;
                byte as usize
            } else {
                // 乱数バイトを使い切った
                return None;
            };

            let candidate = value & mask;
            if candidate < max {
                return Some(candidate);
            }
            // candidate >= max の場合はリトライしてバイアスを排除
        }
    }
}

/// # Overview
/// 指定されたパスワードが十分に強力であるかを確認します。
/// `zxcvbn` ライブラリを使用してパスワードの強度を評価し、最高評価であるスコア4に達した場合にのみ `true` を返します。
///
/// # Arguments
/// * `pwd`: 評価するパスワード文字列。
///
/// # Returns
/// パスワードが十分に強力であると評価された場合 `true`、そうでない場合 `false` を返します。
fn is_strong(pwd: &str) -> bool {
    // 基本的な品質チェックを追加
    if pwd.len() < 8 {
        return false;
    }

    // 全て同じ文字でないことを確認
    if pwd.chars().all(|c| c == pwd.chars().next().unwrap_or('a')) {
        return false;
    }

    zxcvbn(pwd, &[]).score() == Score::Four
}

// テスト用補助: 外部RNG差し替えや決定性テストを可能にする
#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use rand::RngCore;

    pub fn assemble_random_password_with_rng(
        rng: &mut impl RngCore,
        all_vec: &[char],
        len: usize,
        req: &[Vec<char>],
    ) -> Option<String> {
        if all_vec.is_empty() {
            return None;
        }

        let mut random_bytes = vec![0u8; len * 16];
        rng.fill_bytes(&mut random_bytes);
        let mut rng_adapter = BytesToIndexAdapter::new(&random_bytes);

        let need: Vec<char> = req
            .iter()
            .filter_map(|set| {
                if set.is_empty() {
                    return None;
                }
                let index = rng_adapter.next_index(set.len())?;
                set.get(index).copied()
            })
            .collect();

        if need.len() > len {
            return None;
        }
        let rest = len - need.len();
        let mut pwd: Vec<char> = need;
        for _ in 0..rest {
            if let Some(index) = rng_adapter.next_index(all_vec.len())
                && let Some(&ch) = all_vec.get(index)
            {
                pwd.push(ch);
            }
        }
        for i in (1..pwd.len()).rev() {
            if let Some(j) = rng_adapter.next_index(i + 1) {
                pwd.swap(i, j);
            }
        }
        Some(pwd.iter().collect())
    }

    /// テスト用: 時間依存を避け、決定論的に評価関数/乱数で検証
    pub fn produce_password_within_time_test(
        all_vec: &[char],
        req: &[Vec<char>],
        len: usize,
        min_score: u8,
        evaluator: &impl PasswordStrengthEvaluator,
        rng: &mut impl RngCore,
        max_attempts: u64,
    ) -> Option<(String, u8, f64, bool)> {
        // 時間制約は無視し、max_attempts まで探索
        let mut attempts: u64 = 0;
        let mut best_pwd: Option<String> = None;
        let mut best_score: u8 = 0;
        let mut best_bits: f64 = 0.0;

        while attempts < max_attempts {
            attempts += 1;
            if let Some(candidate) = assemble_random_password_with_rng(rng, all_vec, len, req) {
                if candidate.len() != len {
                    continue;
                }
                if candidate.len() < 8 {
                    continue;
                }
                if candidate
                    .chars()
                    .all(|c| c == candidate.chars().next().unwrap_or('\0'))
                {
                    continue;
                }
                let (score, bits) = evaluator.score_entropy(&candidate);
                if score >= min_score {
                    return Some((candidate, score, bits, true));
                }
                if score > best_score || (score == best_score && bits > best_bits) {
                    best_score = score;
                    best_bits = bits;
                    best_pwd = Some(candidate);
                }
            }
        }

        best_pwd.map(|pwd| (pwd, best_score, best_bits, false))
    }
}
