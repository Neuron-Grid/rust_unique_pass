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

/// グローバルRNGインスタンスの管理
/// パフォーマンス向上と自動再シード機能を提供
pub struct GlobalRng {
    rng: Arc<SecureRng>,
    output_counter: AtomicU64,
    reseed_threshold: u64,
    last_reseed: AtomicU64,
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
    /// 自動再シード機能付き
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

        Ok(output_count >= self.reseed_threshold
            || (current_time - last_reseed) >= Self::RESEED_TIME_THRESHOLD)
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
}

#[derive(Debug, Clone)]
pub struct GlobalRngStatistics {
    pub output_bytes: u64,
    pub last_reseed: u64,
    pub reseed_threshold: u64,
}

// シングルトンパターン（thread-safe）
use std::sync::{Mutex, Once};

static GLOBAL_RNG: Mutex<Option<Arc<GlobalRng>>> = Mutex::new(None);
static INIT: Once = Once::new();

/// グローバルRNGインスタンスを取得
pub fn get_global_rng() -> AppResult<Arc<GlobalRng>> {
    INIT.call_once(|| {
        if let Ok(rng) = GlobalRng::new()
            && let Ok(mut guard) = GLOBAL_RNG.lock()
        {
            *guard = Some(Arc::new(rng));
        }
    });

    let guard = GLOBAL_RNG.lock().map_err(|_| {
        crate::core::app_errors::GenerationError::IoError(std::io::Error::other(
            "Global RNG mutex poisoned",
        ))
    })?;

    guard.clone().ok_or_else(|| {
        crate::core::app_errors::GenerationError::IoError(std::io::Error::other(
            "Failed to initialize global RNG",
        ))
    })
}
