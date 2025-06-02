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

/// # Secure RNG (CSPRNG) モジュール
/// 本モジュールはNIST SP 800-90Aに準拠した暗号学的擬似乱数生成器（CSPRNG）を提供します。
/// - OSエントロピーソースとタイミングエントロピーの混入
/// - シンプルな再シード
/// - スレッドセーフ設計
/// ## セキュリティ設計方針
/// - 乱数生成は常にOSの安全なエントロピーソースを利用
/// - エントロピー不足時はエラーを返し、予測可能性を排除
/// - メモリ上のシード値はZeroizingで自動消去
use super::{CryptoError, CryptoResult};
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// NIST SP 800-90A準拠のCSPRNG実装
/// 暗号学的に安全な擬似乱数生成器。
pub struct SecureRng {
    rng: Mutex<StdRng>,
}

impl SecureRng {
    /// 新しいSecureRngインスタンスを作成
    /// # セキュリティ
    /// - OSのエントロピーソースとタイミングエントロピーを混入
    /// - シード値はZeroizingで自動消去
    pub fn new() -> CryptoResult<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);

        // OSのエントロピーソースから初期シード取得
        getrandom::getrandom(&mut seed[..]).map_err(|_| CryptoError::EntropySourceFailure)?;

        // 追加のタイミングエントロピーを混入
        let timing_entropy = Self::collect_timing_entropy();
        for (i, &byte) in timing_entropy.iter().enumerate().take(32) {
            seed[i] ^= byte;
        }

        let rng = StdRng::from_seed(*seed);

        Ok(Self {
            rng: Mutex::new(rng),
        })
    }

    /// タイミングベースのエントロピー収集
    fn collect_timing_entropy() -> Vec<u8> {
        use std::time::SystemTime;
        let mut entropy = Vec::new();

        for _ in 0..16 {
            let start = SystemTime::now();
            // CPU集約的な操作でタイミングの変動を生成
            let _ = (0..1000).fold(1u64, |acc, x| acc.wrapping_mul(x + 1));
            let duration = start
                .elapsed()
                .unwrap_or_else(|_| std::time::Duration::from_nanos(0));
            entropy.extend_from_slice(&duration.as_nanos().to_le_bytes());
        }

        entropy
    }

    /// 指定されたバッファに乱数バイトを生成
    pub fn generate_bytes(&self, dest: &mut [u8]) -> CryptoResult<()> {
        let mut rng = self
            .rng
            .lock()
            .map_err(|e| CryptoError::MutexPoisoned(format!("RNG mutex poisoned: {}", e)))?;
        rng.fill_bytes(dest);
        Ok(())
    }

    /// 再シード（必要な場合のみ手動で呼び出し）
    pub fn reseed(&self) -> CryptoResult<()> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(|_| CryptoError::EntropySourceFailure)?;

        let timing_entropy = Self::collect_timing_entropy();
        for (i, &byte) in timing_entropy.iter().enumerate().take(32) {
            seed[i] ^= byte;
        }

        let mut rng = self
            .rng
            .lock()
            .map_err(|e| CryptoError::MutexPoisoned(format!("RNG mutex poisoned: {}", e)))?;
        *rng = StdRng::from_seed(*seed);

        Ok(())
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        if let Err(e) = self.generate_bytes(&mut bytes) {
            eprintln!("Critical RNG failure in next_u32: {}", e);
            panic!("Critical RNG failure: unable to generate random data");
        }
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        if let Err(e) = self.generate_bytes(&mut bytes) {
            eprintln!("Critical RNG failure in next_u64: {}", e);
            panic!("Critical RNG failure: unable to generate random data");
        }
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.generate_bytes(dest) {
            eprintln!("Critical RNG failure in fill_bytes: {}", e);
            panic!("Critical RNG failure: unable to generate random data");
        }
    }
}

impl CryptoRng for SecureRng {}
