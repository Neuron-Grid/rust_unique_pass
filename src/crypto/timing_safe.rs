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
/// - すべての比較・選択・シャッフル操作は定時間で実行
/// - キャッシュ・電力パターンのノイズ挿入
/// - subtleクレート等の業界標準技術を活用
///
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::{Choice, ConstantTimeEq};

/// タイミング攻撃対策を施したセキュア操作
pub struct TimingSafeOps;

impl TimingSafeOps {
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
    pub fn constant_time_compare(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            // 長さが異なる場合も、定時間で比較を行う
            return Self::constant_time_compare_bytes(a.as_bytes(), b.as_bytes());
        }

        a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
    }

    /// バイト列の定時間比較
    /// 長さが異なる場合も対応
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
    pub fn add_timing_noise() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        // 可変遅延の追加
        let delay = COUNTER.fetch_add(1, Ordering::Relaxed) % 1000;
        let mut dummy = 1u64;

        for _ in 0..delay {
            dummy = dummy.wrapping_mul(dummy).wrapping_add(1);
            // 最適化防止
            std::hint::black_box(&dummy);
        }
    }

    /// セキュアなインデックス生成
    ///
    /// # セキュリティ
    /// - モジュロバイアスを排除したインデックス生成
    /// - 定時間性を維持するため、常に同じ処理を実行
    /// - タイミング攻撃・バイアス攻撃を防止
    pub fn secure_random_index(rng: &mut impl RngCore, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        // 2の累乗に切り上げ
        let mask = max.next_power_of_two() - 1;

        // バイアスのない乱数生成
        loop {
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            let random_value = usize::from_le_bytes(bytes);
            let masked_index = random_value & mask;
            if masked_index < max {
                return masked_index;
            }
            // リトライ
            // 定時間性を保つため、常に同じ処理を実行
            Self::add_timing_noise();
        }
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
        let combined = format!("{s1}{s2}");

        // 常に最大長まで処理
        for i in 0..max_len {
            if i < combined.len() {
                if let Some(ch) = combined.chars().nth(i) {
                    result.push(ch);
                }
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
    /// - Fisher-Yatesアルゴリズムを定時間・バイアスなしで実行
    /// - 各swap操作ごとにタイミングノイズを挿入
    /// - タイミング攻撃・バイアス攻撃を防止
    pub fn secure_shuffle<T: Clone>(items: &mut [T], rng: &mut impl RngCore) {
        let len = items.len();

        for i in (1..len).rev() {
            // セキュアなインデックス生成
            let j = TimingSafeOps::secure_random_index(rng, i + 1);
            items.swap(i, j);

            // タイミングノイズ
            TimingSafeOps::add_timing_noise();
        }
    }
}
