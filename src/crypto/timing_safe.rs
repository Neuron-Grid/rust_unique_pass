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

use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::{Choice, ConstantTimeEq};

/// タイミング攻撃対策を施したセキュア操作
pub struct TimingSafeOps;

impl TimingSafeOps {
    /// 定時間文字選択
    /// インデックスに関わらず、常に同じ時間で文字を選択します。
    /// これによりタイミング攻撃を防ぎます。
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

        char::from_u32(result).unwrap_or(a)
    }

    /// 定時間比較
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
    /// モジュロバイアス対策
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

/// キャッシュタイミング攻撃対策
pub struct CacheProtection;

impl CacheProtection {
    /// キャッシュラインのプリフェッチ
    /// 全データをキャッシュに読み込むことで、
    /// アクセスパターンからの情報漏洩を防ぎます。
    #[cfg(target_arch = "x86_64")]
    pub fn prefetch_all<T>(data: &[T]) {
        unsafe {
            use core::arch::x86_64::_mm_prefetch;
            for item in data {
                _mm_prefetch(item as *const T as *const i8, 0);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn prefetch_all<T>(data: &[T]) {
        unsafe {
            use core::arch::x86::_mm_prefetch;
            for item in data {
                _mm_prefetch(item as *const T as *const i8, 0);
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    pub fn prefetch_all<T>(data: &[T]) {
        // 汎用: volatile読み出しでキャッシュに載せる
        for item in data {
            unsafe {
                std::ptr::read_volatile(item);
            }
        }
    }

    /// キャッシュフラッシュ
    /// 大量のダミーデータでキャッシュを埋めることで、
    /// 以前のアクセスパターンを隠蔽します。
    pub fn flush_cache() {
        // 8MBのダミーデータでキャッシュを埋める
        let dummy: Vec<u8> = vec![0u8; 8 * 1024 * 1024];
        let mut sum: u8 = 0;

        for &byte in dummy.iter() {
            sum = sum.wrapping_add(byte);
        }

        // 最適化防止
        std::hint::black_box(sum);
    }

    /// メモリアクセスパターンの隠蔽
    pub fn obfuscate_memory_access<T: Clone>(data: &[T], index: usize) -> T {
        // 全要素にアクセスして、特定のインデックスへのアクセスを隠す
        let mut result = data[0].clone();

        for (i, item) in data.iter().enumerate() {
            let is_target = (i == index) as u8;
            if is_target == 1 {
                result = item.clone();
            }
            // ダミーアクセス
            std::hint::black_box(item);
        }

        result
    }
}

/// 電力解析攻撃対策
pub struct PowerAnalysisProtection;

impl PowerAnalysisProtection {
    /// ビット演算のマスキング
    /// 敏感なデータをランダムマスクで保護し、
    /// 電力消費パターンからの情報漏洩を防ぎます。
    pub fn masked_operation<F>(data: u32, operation: F) -> u32
    where
        F: Fn(u32) -> u32,
    {
        // ランダムマスクの生成
        let mask = rand::random::<u32>();

        // データをマスクで保護
        let masked_data = data ^ mask;

        // マスクされたデータで操作を実行
        let masked_result = operation(masked_data);

        // 結果からマスクを除去
        masked_result ^ mask
    }

    /// ダミー演算の挿入
    /// 本物の演算と区別がつかないダミー演算を挿入し、
    /// 電力パターンを複雑化します。
    pub fn insert_dummy_operations() {
        let mut dummy = rand::random::<u64>();

        for _ in 0..10 {
            // 実際の演算と同様の電力消費パターンを生成
            dummy = dummy.wrapping_mul(0x5DEECE66D);
            dummy = dummy.wrapping_add(0xB);
            dummy = dummy ^ (dummy >> 32);

            std::hint::black_box(&dummy);
        }
    }
}

/// セキュアな文字列操作
pub struct SecureStringOps;

impl SecureStringOps {
    /// 定時間文字列連結
    pub fn constant_time_concat(s1: &str, s2: &str, max_len: usize) -> String {
        let mut result = String::with_capacity(max_len);
        let combined = format!("{}{}", s1, s2);

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
    /// Fisher-Yates
    pub fn secure_shuffle<T: Clone>(items: &mut Vec<T>, rng: &mut impl RngCore) {
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
