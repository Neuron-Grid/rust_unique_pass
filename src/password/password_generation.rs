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
use crate::crypto::global_rng::ByteStream;
use crate::crypto::zxcvbn_wrapper::zxcvbn_entropy_score;
use crate::password::password_length::{validate_password_byte_length, validate_password_length};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::{Score, zxcvbn};

// 将来の拡張用に保持
#[allow(dead_code)]
const MAX_GENERATION_ATTEMPTS: usize = 500000;
// 将来の拡張用に保持
#[allow(dead_code)]
const STRENGTH_CHECK_INTERVAL: usize = 10;
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;

const MIN_PASSWORD_CHARS: usize = 8;

/// # Overview
/// 与えられた文字集合構成で `length` 文字のパスワードが
/// [`crate::crypto::zxcvbn_wrapper::MAX_PASSWORD_BYTES`] 以内に
/// 収まる可能性があるかを事前検査する。
///
/// 下限バイト数の計算:
/// - 非空の `required set` は必ず1文字ずつ含まれるので、各セットの最小 UTF-8
///   バイト長の合計が下限の一部となる。
/// - 残りの `length - 非空req数` 文字は `all_vec` から選ばれるため、
///   `all_vec` の最小 UTF-8 バイト長 × 残り文字数 を加算する。
///
/// この下限すら `MAX_PASSWORD_BYTES` を超える場合、どの候補も
/// バイト長超過で棄却されるため、探索ループに入らず即エラーとする。
/// DoS 防御を目的とした事前検査であり、パスワード強度評価とは独立している。
///
/// # Errors
/// - `length` が `all_vec`/`req` に対して論理的に成立しない場合
///   ([`GenerationError::InvalidLength`])
/// - 下限バイト数が [`MAX_PASSWORD_BYTES`] を超える場合
///   ([`GenerationError::InvalidCharset`])
pub(crate) fn validate_charset_feasibility(
    all_vec: &[char],
    req: &[Vec<char>],
    length: usize,
) -> Result<()> {
    if all_vec.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }

    // 非空の required set を数え、各セットの最小バイト長を集める。
    let mut nonempty_req_count: usize = 0;
    let mut req_min_bytes_sum: usize = 0;
    for set in req {
        if set.is_empty() {
            continue;
        }
        nonempty_req_count += 1;
        let min_in_set = set.iter().map(|c| c.len_utf8()).min().unwrap_or(0);
        req_min_bytes_sum = req_min_bytes_sum.saturating_add(min_in_set);
    }

    if nonempty_req_count > length {
        return Err(GenerationError::InvalidLength);
    }

    let all_min_bytes = all_vec.iter().map(|c| c.len_utf8()).min().unwrap_or(0);

    let remaining = length - nonempty_req_count;
    let min_possible_bytes =
        req_min_bytes_sum.saturating_add(remaining.saturating_mul(all_min_bytes));

    if min_possible_bytes > crate::crypto::zxcvbn_wrapper::MAX_PASSWORD_BYTES {
        return Err(GenerationError::InvalidCharset(format!(
            "minimum possible byte length {} exceeds MAX_PASSWORD_BYTES {} for password length {}",
            min_possible_bytes,
            crate::crypto::zxcvbn_wrapper::MAX_PASSWORD_BYTES,
            length
        )));
    }

    Ok(())
}

/// 時間予算による生成結果
pub(crate) struct GenerationOutcome {
    pub password: Zeroizing<String>,
    pub score: u8,
    pub entropy_bits: f64,
    pub reached_target: bool,
}

/// 候補スコア情報
struct CandidateScore {
    score: u8,
    entropy_bits: f64,
}

/// 強度評価抽象化トレイト
pub trait PasswordStrengthEvaluator {
    fn score_entropy(&self, pwd: &str) -> Result<(u8, f64)>;
}

/// 実装: zxcvbn を用いた評価器
pub struct ZxcvbnEvaluator;

impl PasswordStrengthEvaluator for ZxcvbnEvaluator {
    fn score_entropy(&self, pwd: &str) -> Result<(u8, f64)> {
        let (bits, score) =
            zxcvbn_entropy_score(pwd).map_err(GenerationError::StrengthEvaluationError)?;
        Ok((score, bits))
    }
}

/// 候補文字列の解析結果
struct CandidateAnalysis {
    char_len: usize,
    byte_len: usize,
    all_same: bool,
}

/// 候補文字列を1回走査で解析する
fn analyze_candidate(candidate: &str) -> CandidateAnalysis {
    let mut char_len = 0usize;
    let mut first_char: Option<char> = None;
    let mut all_same = true;

    for ch in candidate.chars() {
        char_len = char_len.saturating_add(1);
        if let Some(first) = first_char {
            if ch != first {
                all_same = false;
            }
        } else {
            first_char = Some(ch);
        }
    }

    if char_len == 0 {
        all_same = false;
    }

    CandidateAnalysis {
        char_len,
        byte_len: candidate.len(),
        all_same,
    }
}

/// 候補の基本検証と強度評価を行う
fn evaluate_candidate(
    candidate: &str,
    config: &StrengthSearchConfig<'_>,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<Option<CandidateScore>> {
    let analysis = analyze_candidate(candidate);
    if analysis.char_len != config.len {
        return Ok(None);
    }
    if analysis.char_len < MIN_PASSWORD_CHARS {
        return Ok(None);
    }
    if analysis.byte_len > crate::crypto::zxcvbn_wrapper::MAX_PASSWORD_BYTES {
        return Ok(None);
    }
    if analysis.all_same {
        return Ok(None);
    }

    let (score, bits) = evaluator.score_entropy(candidate)?;
    Ok(Some(CandidateScore {
        score,
        entropy_bits: bits,
    }))
}

/// 時刻依存を分離するためのクロック抽象化
trait Clock {
    fn now(&self) -> Duration;
}

/// 実運用向けの単調時間クロック
struct SystemClock {
    start: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

/// 強度探索の設定
struct StrengthSearchConfig<'a> {
    all_vec: &'a [char],
    req: &'a [Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
}

/// ベスト候補の保持
struct BestCandidate {
    password: Option<Zeroizing<String>>,
    score: u8,
    entropy_bits: f64,
}

impl BestCandidate {
    fn new() -> Self {
        Self {
            password: None,
            score: 0,
            entropy_bits: 0.0,
        }
    }

    fn should_replace(&self, scored: &CandidateScore) -> bool {
        scored.score > self.score
            || (scored.score == self.score && scored.entropy_bits > self.entropy_bits)
    }

    fn update(&mut self, candidate: Zeroizing<String>, scored: &CandidateScore) {
        self.score = scored.score;
        self.entropy_bits = scored.entropy_bits;
        self.password = Some(candidate);
    }
}

fn assemble_random_password_with_sampler<S: ByteStream>(
    sampler: &mut StreamingIndexSampler<S>,
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Option<String>> {
    if all_vec.is_empty() {
        return Ok(None);
    }
    assemble_random_password_internal(sampler, all_vec, len, req, None)
}

fn produce_password_within_time_sync_with_sampler_and_clock<S: ByteStream, C: Clock>(
    sampler: &mut StreamingIndexSampler<S>,
    config: &StrengthSearchConfig<'_>,
    evaluator: &dyn PasswordStrengthEvaluator,
    clock: &C,
) -> Result<GenerationOutcome> {
    validate_password_length(config.len)?;
    if config.timeout_ms > MAX_TIMEOUT_MS {
        return Err(GenerationError::InvalidTimeout);
    }
    if config.all_vec.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }
    if config.req.len() > config.len {
        return Err(GenerationError::InvalidLength);
    }
    let deadline = clock
        .now()
        .checked_add(Duration::from_millis(config.timeout_ms))
        .ok_or(GenerationError::InvalidTimeout)?;
    let mut attempts: u64 = 0;
    let mut best = BestCandidate::new();

    loop {
        // 最低1回は候補生成を試しつつ、2回目以降は期限を超えたら即終了する。
        if attempts > 0 && clock.now() >= deadline {
            break;
        }
        attempts = attempts.saturating_add(1);

        if let Some(candidate) =
            assemble_random_password_with_sampler(sampler, config.all_vec, config.len, config.req)?
        {
            let candidate = Zeroizing::new(candidate);
            let scored = evaluate_candidate(candidate.as_str(), config, evaluator)?;

            if let Some(scored) = scored {
                if scored.score >= config.min_score {
                    return Ok(GenerationOutcome {
                        password: candidate,
                        score: scored.score,
                        entropy_bits: scored.entropy_bits,
                        reached_target: true,
                    });
                }
                if best.should_replace(&scored) {
                    best.update(candidate, &scored);
                }
            }
        }

        // 試行後にも期限を確認し、超過を1試行分に限定する。
        if clock.now() >= deadline {
            break;
        }
    }

    // 期限切れ/回数到達
    if let Some(pwd) = best.password {
        if config.strict && best.score < config.min_score {
            return Err(GenerationError::StrictTargetUnmet);
        }
        return Ok(GenerationOutcome {
            password: pwd,
            score: best.score,
            entropy_bits: best.entropy_bits,
            reached_target: false,
        });
    }

    Err(GenerationError::GenerationFailed)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn produce_password_within_time_sync<S: ByteStream + ?Sized>(
    rng: &mut S,
    all_vec: &[char],
    req: &[Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<GenerationOutcome> {
    let mut sampler = StreamingIndexSampler::new(rng);
    let clock = SystemClock::new();
    let config = StrengthSearchConfig {
        all_vec,
        req,
        len,
        timeout_ms,
        min_score,
        strict,
    };
    produce_password_within_time_sync_with_sampler_and_clock(
        &mut sampler,
        &config,
        evaluator,
        &clock,
    )
}

/// # Overview
/// 指定の時間予算内で、zxcvbnスコア/エントロピーに基づいてパスワードを探索します。
/// `min_score` 到達で早期終了します。
///
/// # Arguments
/// * `rng`: バイトストリームを提供する乱数ソース。
#[allow(clippy::unused_async)]
#[allow(clippy::too_many_arguments)]
pub async fn produce_password_within_time(
    rng: &mut impl ByteStream,
    all_vec: &[char],
    req: &[Vec<char>],
    len: usize,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
    evaluator: &dyn PasswordStrengthEvaluator,
) -> Result<GenerationOutcome> {
    produce_password_within_time_sync(
        rng, all_vec, req, len, timeout_ms, min_score, strict, evaluator,
    )
}

/// # Overview
/// 指定された文字セットと長さに基づいて、安全なパスワードを生成します。
///
/// # Arguments
/// * `rng`: バイトストリームを提供する乱数ソース。
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
// 将来の拡張用に保持
#[allow(dead_code)]
#[deprecated(
    since = "0.11.0",
    note = "Use produce_password_within_time instead. This legacy API runs a fixed-attempt loop and is kept only for source compatibility; it will be removed in a future release."
)]
pub async fn produce_secure_password(
    rng: &mut impl ByteStream,
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

    // 到達可能性の事前検査: 旧 API でも DoS 抜け道を作らないため、
    // 新 API と同じ helper を呼び出して到達不能な構成を即座に弾く。
    validate_charset_feasibility(all_vec, req, len)?;

    let mut sampler = StreamingIndexSampler::new(rng);
    let mut candidates: Vec<Zeroizing<String>> = Vec::with_capacity(STRENGTH_CHECK_INTERVAL);

    for attempt in 1..=MAX_GENERATION_ATTEMPTS {
        if let Some(pwd) = assemble_random_password_with_sampler(&mut sampler, all_vec, len, req)? {
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
// 将来の拡張用に保持
#[allow(dead_code)]
fn assemble_random_password(
    rng: &mut impl ByteStream,
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Option<String>> {
    let mut sampler = StreamingIndexSampler::new(rng);
    assemble_random_password_with_sampler(&mut sampler, all_vec, len, req)
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
// 将来の拡張用に保持
#[allow(dead_code)]
fn is_strong(pwd: &str) -> bool {
    // 基本的な品質チェックを追加
    let analysis = analyze_candidate(pwd);
    if analysis.char_len < MIN_PASSWORD_CHARS {
        return false;
    }
    if validate_password_byte_length(pwd).is_err() {
        return false;
    }
    if analysis.all_same {
        // 全て同じ文字でないことを確認
        return false;
    }

    zxcvbn(pwd, &[]).score() == Score::Four
}

#[cfg(test)]
#[path = "../../tests/unit/password_generation_tests.rs"]
mod password_generation_tests;
