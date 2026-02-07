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

///
/// # Timing Safe Operations モジュール
///
/// 本モジュールはタイミング攻撃・キャッシュ攻撃・電力解析攻撃などのサイドチャネル攻撃対策を目的とした各種セキュア操作を提供します。
///
/// ## セキュリティ設計方針
/// - 比較・選択・シャッフルは可能な範囲で定時間に近づける
/// - 固定回数の処理でタイミング差を平坦化し、必要に応じて一様性を優先
/// - subtleクレート等の業界標準技術を活用
///
use crate::core::app_errors::{GenerationError, Result};
use rand::{CryptoRng, RngCore, TryRngCore};
use subtle::{Choice, ConstantTimeEq};

/// タイミング攻撃対策を施したセキュア操作
pub struct TimingSafeOps;

impl TimingSafeOps {
    const HYBRID_ATTEMPTS: usize = 8;

    /// 定時間文字選択
    ///
    /// # セキュリティ
    /// - インデックスに関わらず、常に同じ時間で文字を選択
    /// - タイミング攻撃を防止
    pub fn constant_time_select(chars: &[char], index: usize) -> Option<char> {
        if chars.is_empty() {
            return None;
        }

        // インデックスを安全な範囲に制限
        let len = chars.len();
        let safe_index = index % len;

        // 全要素を走査し、条件付きで選択
        let mut result = chars[0];
        for (i, &ch) in chars.iter().enumerate() {
            // i == safe_indexの場合に1、そうでない場合に0
            let is_target = Choice::from((i == safe_index) as u8);
            // 定時間で選択
            result = Self::conditional_select_char(result, ch, is_target);
        }

        Some(result)
    }

    /// 条件付き文字選択
    fn conditional_select_char(a: char, b: char, choice: Choice) -> char {
        let a_val = a as u32;
        let b_val = b as u32;

        // choiceが1の場合はb、0の場合はaを選択
        let mask = u32::from(choice.unwrap_u8()).wrapping_neg();
        let result = (a_val & !mask) | (b_val & mask);

        // char::from_u32は無効なUnicodeコードポイントでNoneを返す可能性があるが、
        // a_valとb_valは既に有効なcharから来ているため、resultも有効なはず
        char::from_u32(result).unwrap_or(a)
    }

    /// 定時間比較
    ///
    /// # セキュリティ
    /// - 文字列長が異なる場合も定時間で比較
    /// - subtleクレートによる定時間比較
    /// - タイミング攻撃を防止
    /// - 入力長に比例して処理量が変わるため、長さの情報は漏れる可能性がある
    pub fn constant_time_compare(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            // 長さが異なる場合も、定時間で比較を行う
            return Self::constant_time_compare_bytes(a.as_bytes(), b.as_bytes());
        }

        a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
    }

    /// バイト列の定時間比較
    /// 長さが異なる場合も対応
    /// 入力長に比例して処理量が変わるため、長さの情報は漏れる可能性がある
    fn constant_time_compare_bytes(a: &[u8], b: &[u8]) -> bool {
        let len = a.len().max(b.len());
        let mut result = Choice::from(1u8);

        // 長さの比較
        result &= a.len().ct_eq(&b.len());

        // 内容の比較
        // パディングして同じ長さにする
        for i in 0..len {
            let a_byte = if i < a.len() { a[i] } else { 0 };
            let b_byte = if i < b.len() { b[i] } else { 0 };
            result &= a_byte.ct_eq(&b_byte);
        }

        result.unwrap_u8() == 1
    }

    /// ダミー操作によるタイミングノイズ追加
    ///
    /// # 注意
    /// この処理は「定時間保証」を提供しません。
    /// 互換目的で残す軽量な処理であり、可変遅延は導入しません。
    pub fn add_timing_noise() {
        let mut dummy = 0u64;
        for _ in 0..4 {
            dummy = dummy
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // 最適化防止
            std::hint::black_box(dummy);
        }
    }

    /// セキュアなインデックス生成
    ///
    /// # セキュリティ
    /// - 固定回数の試行で候補を探索し、失敗時は一様性を優先するハイブリッド方式
    /// - ハイブリッドで候補が得られない場合はリジェクションサンプリングでバイアス排除を優先
    /// - 定時間性は近似であり、厳密保証ではない
    ///
    /// # Errors
    /// RNGが失敗した場合はエラーを返します。
    pub fn secure_random_index<R>(rng: &mut R, max: usize) -> Result<usize>
    where
        R: RngCore + CryptoRng + ?Sized,
    {
        if max == 0 {
            return Ok(0);
        }

        // 2の累乗に切り上げ
        let mask = match max.checked_next_power_of_two() {
            Some(power) => power - 1,
            None => usize::MAX,
        };

        // ハイブリッド方式: 固定回数での候補探索（定時間に近づける）
        let mut selected = 0usize;
        let mut selected_flag = 0u8;

        for _ in 0..Self::HYBRID_ATTEMPTS {
            let random_value = Self::next_random_usize(rng)?;
            let candidate = random_value & mask;
            let valid = (candidate < max) as u8;
            let take = valid & (selected_flag ^ 1);
            let choose_mask = (take as usize).wrapping_neg();
            selected = (selected & !choose_mask) | (candidate & choose_mask);
            selected_flag |= valid;
        }

        if selected_flag == 1 {
            return Ok(selected);
        }

        // フォールバック: バイアス排除を優先
        loop {
            let random_value = Self::next_random_usize(rng)?;
            let candidate = random_value & mask;
            if candidate < max {
                return Ok(candidate);
            }
        }
    }

    fn next_random_usize<R>(rng: &mut R) -> Result<usize>
    where
        R: RngCore + CryptoRng + ?Sized,
    {
        const USIZE_BYTES: usize = std::mem::size_of::<usize>();
        let mut bytes = [0u8; USIZE_BYTES];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|err| GenerationError::RngFailure(err.to_string()))?;
        Ok(usize::from_le_bytes(bytes))
    }
}

impl TimingSafeOps {
    /// 文字列を連結します。
    ///
    /// # 注意
    /// この関数は、入力文字列の長さに比例した時間で実行されます（O(n)）。
    /// UTF-8の可変長文字エンコーディングの性質上、真の定時間での文字列操作は非常に複雑です。
    /// この関数はタイミング攻撃に対する耐性を提供しないため、セキュリティクリティカルな文脈での使用には注意が必要です。
    pub fn constant_time_concat(s1: &str, s2: &str, max_len: usize) -> String {
        let mut result = String::with_capacity(max_len);
        let mut iter = s1.chars().chain(s2.chars());

        // 常に最大長まで処理
        for _ in 0..max_len {
            if let Some(ch) = iter.next() {
                result.push(ch);
            } else {
                // パディング
                // 実際には追加されない
                let _ = result.capacity();
            }
        }

        result
    }

    /// セキュアなシャッフル
    ///
    /// # セキュリティ
    /// - Fisher-Yatesアルゴリズムを用い、バイアスを抑えたインデックス選択を行う
    /// - 定時間性は近似であり、必要に応じて一様性を優先
    pub fn secure_shuffle<T, R>(items: &mut [T], rng: &mut R) -> Result<()>
    where
        R: RngCore + CryptoRng + ?Sized,
    {
        let len = items.len();

        for i in (1..len).rev() {
            // セキュアなインデックス生成
            let j = TimingSafeOps::secure_random_index(rng, i + 1)?;
            items.swap(i, j);
        }

        Ok(())
    }
}
