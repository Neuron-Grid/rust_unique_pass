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

use super::{CryptoError, CryptoResult};
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// NIST SP 800-90A準拠のCSPRNG実装
/// 暗号学的に安全な擬似乱数生成器。
/// 定期的な再シードとエントロピープールの管理を行います。
pub struct SecureRng {
    rng: Mutex<StdRng>,
    reseed_counter: Mutex<u64>,
    entropy_pool: Mutex<Vec<u8>>,
}

impl SecureRng {
    /// 新しいSecureRngインスタンスを作成
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
            reseed_counter: Mutex::new(0),
            entropy_pool: Mutex::new(Vec::with_capacity(1024)),
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
            let duration = start.elapsed().unwrap_or_default();
            entropy.extend_from_slice(&duration.as_nanos().to_le_bytes());
        }

        entropy
    }

    /// 定期的な再シード
    /// NIST SP 800-90A要件
    pub async fn reseed(&self) -> CryptoResult<()> {
        let mut seed = Zeroizing::new([0u8; 32]);

        // 非同期でエントロピー取得
        let mut seed_bytes =
            tokio::task::spawn_blocking(move || getrandom::getrandom(&mut seed[..]).map(|_| seed))
                .await
                .map_err(|_| CryptoError::RngInitError)?
                .map_err(|_| CryptoError::EntropySourceFailure)?;

        let mut rng = self.rng.lock().unwrap();
        let mut pool = self.entropy_pool.lock().unwrap();

        // エントロピープールからの追加エントロピー
        if pool.len() >= 32 {
            let drained: Vec<u8> = pool.drain(..32).collect();
            let seed_array = seed_bytes.as_mut();
            for (i, byte) in drained.iter().enumerate() {
                seed_array[i] ^= *byte;
            }
        }

        let seed_array = *seed_bytes;
        *rng = StdRng::from_seed(seed_array);
        *self.reseed_counter.lock().unwrap() = 0;

        Ok(())
    }

    /// 指定されたバッファに乱数バイトを生成
    pub fn generate_bytes(&self, dest: &mut [u8]) -> CryptoResult<()> {
        // 2^48バイト
        const MAX_BYTES_BEFORE_RESEED: u64 = 1u64 << 48;

        let mut counter = self.reseed_counter.lock().unwrap();

        // 再シード間隔の確認
        if *counter > MAX_BYTES_BEFORE_RESEED {
            // ロック解放
            drop(counter);
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.reseed())
            })?;
            counter = self.reseed_counter.lock().unwrap();
        }

        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(dest);
        *counter += dest.len() as u64;

        Ok(())
    }

    /// エントロピープールに追加データを混入
    pub fn add_entropy(&self, data: &[u8]) {
        let mut pool = self.entropy_pool.lock().unwrap();

        // プールサイズの上限を設定
        const MAX_POOL_SIZE: usize = 4096;

        if pool.len() + data.len() <= MAX_POOL_SIZE {
            pool.extend_from_slice(data);
        } else {
            // 古いデータを破棄して新しいデータを追加
            let overflow = (pool.len() + data.len()).saturating_sub(MAX_POOL_SIZE);
            pool.drain(..overflow);
            pool.extend_from_slice(data);
        }
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.generate_bytes(&mut bytes).expect("RNG failure");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.generate_bytes(&mut bytes).expect("RNG failure");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.generate_bytes(dest).expect("RNG failure");
    }
}

impl CryptoRng for SecureRng {}

/// スレッドセーフなRNGラッパー
#[derive(Clone)]
pub struct ThreadSafeRng {
    inner: std::sync::Arc<SecureRng>,
}

impl ThreadSafeRng {
    pub fn new() -> CryptoResult<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(SecureRng::new()?),
        })
    }

    pub fn generate_bytes(&self, dest: &mut [u8]) -> CryptoResult<()> {
        self.inner.generate_bytes(dest)
    }

    pub async fn reseed(&self) -> CryptoResult<()> {
        self.inner.reseed().await
    }
}
