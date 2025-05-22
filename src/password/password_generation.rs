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
use crate::password::password_length::validate_password_length;
use rand::prelude::IndexedRandom;
use rand::prelude::SliceRandom;
use zeroize::Zeroizing;
use zxcvbn::{Score, zxcvbn};

const MAX_GENERATION_ATTEMPTS: usize = 100_000;

/// # Overview
/// 指定された文字セットと長さに基づいて、安全なパスワードを生成します。
/// 必須文字セットからの文字を必ず含み、生成されたパスワードが十分に強力であるかを確認します。
/// 指定された試行回数内に安全なパスワードが生成できない場合はエラーを返します。
///
/// # Arguments
/// * `all_vec`: パスワードに使用可能な全ての文字を含むスライス。
/// * `len`: 生成するパスワードの長さ。
/// * `req`: パスワードに最低1文字含める必要がある文字セットのリストを含むスライス。
///
/// # Returns
/// 安全なパスワードが生成された場合、[`Zeroizing<String>`] でラップされたパスワードを返します。
///
/// # Errors
/// パスワード長が不正な場合、[`GenerationError::InvalidPasswordLength`] を返します。
/// 指定された試行回数内に安全なパスワードが生成できなかった場合、[`GenerationError::GenerationFailed`] を返します。
///
/// # Notes
/// この関数は同期的に実行されるため、非同期コンテキストで呼び出す場合はブロッキングスレッドプールを使用してください。
/// 生成されたパスワードはメモリから安全に消去するために [`Zeroizing`] でラップされています。
#[doc(alias = "generate")]
#[doc(alias = "password")]
#[doc(alias = "secure")]
pub fn produce_secure_password(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Zeroizing<String>> {
    validate_password_length(len)?;
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        if let Some(pwd) = assemble_random_password(all_vec, len, req) {
            if is_strong(&pwd) {
                return Ok(Zeroizing::new(pwd));
            }
        }
    }
    Err(GenerationError::GenerationFailed)
}

/// # Overview
/// 指定された文字セットと長さ、必須文字セットに基づいてランダムなパスワードを組み立てます。
///
/// # Arguments
/// * `all_vec`: パスワードに使用可能な全ての文字を含むスライス。
/// * `len`: 組み立てるパスワードの長さ。
/// * `req`: パスワードに最低1文字含める必要がある文字セットのリストを含むスライス。
///
/// # Returns
/// 組み立てられたパスワードを含む [`Option<String>`] を返します。
/// 使用可能な文字セットが空の場合、または必須文字セットの数がパスワード長より大きい場合は `None` を返します。
pub fn assemble_random_password(all_vec: &[char], len: usize, req: &[Vec<char>]) -> Option<String> {
    if all_vec.is_empty() {
        return None;
    }
    let mut rng = rand::rng();

    // 各必須セットから1文字ずつ
    let need: Vec<char> = req
        .iter()
        .filter_map(|set| set.choose(&mut rng).copied())
        .collect();

    if need.len() > len {
        return None;
    }

    let rest = len - need.len();
    let mut pwd: Vec<char> = need
        .into_iter()
        .chain((0..rest).filter_map(|_| all_vec.choose(&mut rng).copied()))
        .collect();

    pwd.shuffle(&mut rng);
    Some(pwd.iter().collect())
}

/// # Overview
/// 指定されたパスワードが十分に強力であるかを確認します。
/// zxcvbn ライブラリを使用してパスワードの強度を評価します。
///
/// # Arguments
/// * `pwd`: 評価するパスワード文字列。
///
/// # Returns
/// パスワードが十分に強力であると評価された場合 `true`、そうでない場合 `false` を返します。
fn is_strong(pwd: &str) -> bool {
    zxcvbn(pwd, &[]).score() == Score::Four
}
