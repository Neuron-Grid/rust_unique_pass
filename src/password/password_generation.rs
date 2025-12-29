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
use crate::crypto::global_rng::{ByteStream, get_global_rng};
use crate::crypto::zxcvbn_wrapper::zxcvbn_entropy_score;
use crate::password::password_length::{validate_password_byte_length, validate_password_length};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::{Score, zxcvbn};

const MAX_GENERATION_ATTEMPTS: usize = 500000;
const STRENGTH_CHECK_INTERVAL: usize = 10;
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;

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

fn assemble_random_password_sync(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Option<String>> {
    if all_vec.is_empty() {
        return Ok(None);
    }

    let global_rng = get_global_rng()?;
    let mut sampler = StreamingIndexSampler::new(global_rng.stream());
    assemble_random_password_internal(&mut sampler, all_vec, len, req, None)
}

pub(crate) fn produce_password_within_time_sync(
    all_vec: &[char],
    req: &[Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<GenerationOutcome> {
    validate_password_length(len)?;
    if timeout_ms > MAX_TIMEOUT_MS {
        return Err(GenerationError::InvalidTimeout);
    }
    if all_vec.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }
    if req.len() > len {
        return Err(GenerationError::InvalidLength);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or(GenerationError::InvalidTimeout)?;
    let mut attempts: u64 = 0;
    let mut best_pwd: Option<Zeroizing<String>> = None;
    let mut best_score: u8 = 0;
    let mut best_bits: f64 = 0.0;

    loop {
        attempts += 1;

        if let Some(mut candidate) = assemble_random_password_sync(all_vec, len, req)? {
            if candidate.chars().count() != len {
                candidate.zeroize();
                continue;
            }
            // 軽量フィルタ: ごく弱い候補をスキップ
            if candidate.chars().count() < 8 {
                candidate.zeroize();
                continue;
            }
            if validate_password_byte_length(&candidate).is_err() {
                candidate.zeroize();
                continue;
            }
            if candidate
                .chars()
                .all(|c| c == candidate.chars().next().unwrap_or('\0'))
            {
                // 全て同一文字
                candidate.zeroize();
                continue;
            }

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
/// 指定の時間予算内で、zxcvbnスコア/エントロピーに基づいてパスワードを探索します。
/// `min_score` 到達で早期終了します。
#[allow(clippy::unused_async)]
pub async fn produce_password_within_time(
    all_vec: &[char],
    req: &[Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<GenerationOutcome> {
    produce_password_within_time_sync(all_vec, req, len, timeout_ms, min_score, strict, evaluator)
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
#[allow(clippy::unused_async)]
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

    let mut candidates: Vec<Zeroizing<String>> = Vec::with_capacity(STRENGTH_CHECK_INTERVAL);

    for attempt in 1..=MAX_GENERATION_ATTEMPTS {
        if let Some(pwd) = assemble_random_password_sync(all_vec, len, req)? {
            candidates.push(Zeroizing::new(pwd));

            // 定期的にバッチで強度チェック - CPU効率改善
            if attempt % STRENGTH_CHECK_INTERVAL == 0 || attempt == MAX_GENERATION_ATTEMPTS {
                for candidate in candidates.drain(..) {
                    if is_strong(&candidate) {
                        return Ok(candidate);
                    }
                }
            }
        }
    }

    Err(GenerationError::GenerationFailed)
}

#[allow(clippy::unused_async)]
pub async fn assemble_random_password(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Option<String>> {
    assemble_random_password_sync(all_vec, len, req)
}

fn assemble_random_password_internal<S: ByteStream>(
    sampler: &mut StreamingIndexSampler<S>,
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
    mut swap_counter: Option<&mut usize>,
) -> Result<Option<String>> {
    if all_vec.is_empty() {
        return Ok(None);
    }

    let mut need: Vec<char> = Vec::with_capacity(req.len());
    for set in req {
        if set.is_empty() {
            continue;
        }
        let index = sampler.next_index(set.len())?;
        let ch = match set.get(index).copied() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        need.push(ch);
    }

    if need.len() > len {
        return Ok(None);
    }

    let rest = match len.checked_sub(need.len()) {
        Some(rest) => rest,
        None => return Ok(None),
    };
    let mut pwd: Zeroizing<Vec<char>> = Zeroizing::new(need);

    for _ in 0..rest {
        let index = sampler.next_index(all_vec.len())?;
        let ch = match all_vec.get(index).copied() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        pwd.push(ch);
    }

    for i in (1..pwd.len()).rev() {
        let j = sampler.next_index(i + 1)?;
        pwd.swap(i, j);
        if let Some(counter) = swap_counter.as_mut() {
            **counter += 1;
        }
    }

    let out: String = pwd.iter().collect();
    pwd.zeroize();
    Ok(Some(out))
}

struct StreamingIndexSampler<S: ByteStream> {
    stream: S,
}

impl<S: ByteStream> StreamingIndexSampler<S> {
    fn new(stream: S) -> Self {
        Self { stream }
    }

    fn next_index(&mut self, max: usize) -> Result<usize> {
        if max == 0 {
            return Err(GenerationError::GenerationFailed);
        }

        let mask = match max.checked_next_power_of_two() {
            Some(power) => power.saturating_sub(1) as u64,
            None => u64::MAX,
        };

        loop {
            let value = self.fetch_u64()?;
            let candidate = (value & mask) as usize;
            if candidate < max {
                return Ok(candidate);
            }
        }
    }

    fn fetch_u64(&mut self) -> Result<u64> {
        const WORD: usize = std::mem::size_of::<u64>();
        let mut word = [0u8; WORD];
        let mut filled = 0;

        while filled < WORD {
            if self.stream.remaining_bytes().is_empty() {
                self.stream.fill_next_block()?;
                if self.stream.remaining_bytes().is_empty() {
                    return Err(GenerationError::GenerationFailed);
                }
            }

            let available = self.stream.remaining_bytes();
            let take = (WORD - filled).min(available.len());
            word[filled..filled + take].copy_from_slice(&available[..take]);
            self.stream.consume(take);
            filled += take;
        }

        Ok(u64::from_le_bytes(word))
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
    if pwd.chars().count() < 8 {
        return false;
    }
    if validate_password_byte_length(pwd).is_err() {
        return false;
    }

    // 全て同じ文字でないことを確認
    if pwd.chars().all(|c| c == pwd.chars().next().unwrap_or('a')) {
        return false;
    }

    zxcvbn(pwd, &[]).score() == Score::Four
}

#[cfg(test)]
#[path = "../../tests/unit/password_generation_tests.rs"]
mod password_generation_tests;