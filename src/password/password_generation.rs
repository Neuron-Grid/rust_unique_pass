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
use crate::password::password_length::validate_password_length;
use std::convert::TryInto;
use zeroize::Zeroizing;
use zxcvbn::{Score, zxcvbn};

const MAX_GENERATION_ATTEMPTS: usize = 500000;
const STRENGTH_CHECK_INTERVAL: usize = 10;

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
        if let Some(index) = rng_adapter.next_index(all_vec.len()) {
            if let Some(&ch) = all_vec.get(index) {
                pwd.push(ch);
            }
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
