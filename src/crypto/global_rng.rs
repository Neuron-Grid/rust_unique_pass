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

use crate::core::app_errors::Result as AppResult;
use crate::crypto::rng::SecureRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

/// グローバルRNGインスタンスの管理
/// OS RNGの読み出しを共有し、統計と再取得タイミングを管理
pub struct GlobalRng {
    rng: Arc<SecureRng>,
    output_counter: AtomicU64,
    reseed_threshold: u64,
    last_reseed: AtomicU64,
}

/// バイトストリーム抽象化
pub trait ByteStream {
    /// バッファを補充する。失敗した場合は [`GenerationError`] を返す。
    fn fill_next_block(&mut self) -> AppResult<()>;

    /// 未消費のバイトスライスを取得する。
    fn remaining_bytes(&self) -> &[u8];

    /// 先頭から `n` バイトを消費する。利用可能バイト数を超える場合は切り詰める。
    fn consume(&mut self, n: usize);
}

impl GlobalRng {
    // 1MB
    const DEFAULT_RESEED_THRESHOLD: u64 = 1_048_576;
    // 1時間
    const RESEED_TIME_THRESHOLD: u64 = 3600;

    pub fn new() -> AppResult<Self> {
        Ok(Self {
            rng: Arc::new(SecureRng::new()?),
            output_counter: AtomicU64::new(0),
            reseed_threshold: Self::DEFAULT_RESEED_THRESHOLD,
            last_reseed: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        })
    }

    /// 指定されたバッファに乱数バイトを生成
    /// 統計に基づく再取得タイミング管理付き
    pub fn generate_bytes(&self, dest: &mut [u8]) -> AppResult<()> {
        // 再シード判定
        if self.should_reseed()? {
            self.reseed()?;
        }

        // バイト数カウント更新
        self.output_counter
            .fetch_add(dest.len() as u64, Ordering::Relaxed);

        self.rng.generate_bytes(dest)
    }

    fn should_reseed(&self) -> AppResult<bool> {
        let output_count = self.output_counter.load(Ordering::Relaxed);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                crate::core::app_errors::GenerationError::IoError(std::io::Error::other(
                    "Time error",
                ))
            })?
            .as_secs();
        let last_reseed = self.last_reseed.load(Ordering::Relaxed);

        let elapsed = current_time.saturating_sub(last_reseed);
        Ok(output_count >= self.reseed_threshold || elapsed >= Self::RESEED_TIME_THRESHOLD)
    }

    fn reseed(&self) -> AppResult<()> {
        self.rng.reseed()?;
        self.output_counter.store(0, Ordering::Relaxed);
        self.last_reseed.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
        Ok(())
    }

    /// 統計情報を取得
    pub fn get_statistics(&self) -> GlobalRngStatistics {
        GlobalRngStatistics {
            output_bytes: self.output_counter.load(Ordering::Relaxed),
            last_reseed: self.last_reseed.load(Ordering::Relaxed),
            reseed_threshold: self.reseed_threshold,
        }
    }

    /// グローバルRNGをオンデマンドで読み出すストリームを生成
    pub fn stream(self: &Arc<Self>) -> GlobalRngStream {
        GlobalRngStream::new(self.clone())
    }
}

const GLOBAL_STREAM_BLOCK_SIZE: usize = 256;

/// [`GlobalRng`] からチャンクごとに乱数を取得するストリーム
pub struct GlobalRngStream {
    rng: Arc<GlobalRng>,
    cache: Zeroizing<[u8; GLOBAL_STREAM_BLOCK_SIZE]>,
    cursor: usize,
    available: usize,
}

impl GlobalRngStream {
    pub fn new(rng: Arc<GlobalRng>) -> Self {
        Self {
            rng,
            cache: Zeroizing::new([0u8; GLOBAL_STREAM_BLOCK_SIZE]),
            cursor: 0,
            available: 0,
        }
    }
}

impl ByteStream for GlobalRngStream {
    fn fill_next_block(&mut self) -> AppResult<()> {
        if let Err(err) = self.rng.generate_bytes(self.cache.as_mut()) {
            self.cache.as_mut().zeroize();
            self.cursor = 0;
            self.available = 0;
            return Err(err);
        }
        self.cursor = 0;
        self.available = self.cache.len();
        Ok(())
    }

    fn remaining_bytes(&self) -> &[u8] {
        let end = self
            .cursor
            .saturating_add(self.available)
            .min(self.cache.len());
        &self.cache[self.cursor..end]
    }

    fn consume(&mut self, n: usize) {
        let take = n.min(self.available);
        self.cursor = (self.cursor + take).min(self.cache.len());
        self.available = self.available.saturating_sub(take);
        if self.available == 0 {
            self.cursor = 0;
        }
    }
}

impl Drop for GlobalRngStream {
    fn drop(&mut self) {
        self.cache.as_mut().zeroize();
        self.cursor = 0;
        self.available = 0;
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRngStatistics {
    pub output_bytes: u64,
    pub last_reseed: u64,
    pub reseed_threshold: u64,
}

// シングルトンパターン（thread-safe）
use std::sync::Mutex;

static GLOBAL_RNG: Mutex<Option<Arc<GlobalRng>>> = Mutex::new(None);

/// グローバルRNGインスタンスを取得
pub fn get_global_rng() -> AppResult<Arc<GlobalRng>> {
    let mut guard = match GLOBAL_RNG.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            let mut guard = poison.into_inner();
            if let Some(rng) = guard.as_ref() {
                if rng.reseed().is_ok() {
                    return Ok(rng.clone());
                }
                *guard = None;
            }
            guard
        }
    };

    if let Some(rng) = guard.as_ref() {
        return Ok(rng.clone());
    }

    let rng = Arc::new(GlobalRng::new()?);
    *guard = Some(rng.clone());
    Ok(rng)
}
