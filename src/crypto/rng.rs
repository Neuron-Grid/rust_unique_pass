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

/// - 乱数生成は常にOSの安全なエントロピーソースを利用
/// - エントロピー不足時はエラーを返し、予測可能性を排除
/// - 一時バッファはZeroizingで自動消去
use crate::core::app_errors::Result as AppResult;
use getrandom;
use rand::{CryptoRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// CSPRNGモジュール
/// 本モジュールはOSの暗号学的乱数生成器から毎バイト取得するラッパーを提供します。
/// - OSエントロピーソースの利用（生成ごとに直接取得）
/// - 自動再シード判定（統計カウンタのリセット）
/// - 基本的なランタイム検証
/// - スレッドセーフ設計
/// ## セキュリティ設計方針
/// - 生成失敗時はエラーで通知し、再試行判断を呼び出し側に委ねる。
pub struct SecureRng {
    // 出力監視機能
    output_counter: AtomicU64,
    request_counter: AtomicU64,
    last_reseed_time: AtomicU64,
    // 設定可能しきい値
    reseed_threshold_bytes: u64,
    reseed_threshold_requests: u64,
    reseed_threshold_time: u64,
}

impl SecureRng {
    const DEFAULT_RESEED_BYTES: u64 = 1_048_576; // 1MB
    const DEFAULT_RESEED_REQUESTS: u64 = 10_000;
    const DEFAULT_RESEED_TIME: u64 = 3600; // 1時間

    /// 新しいSecureRngインスタンスを作成
    /// # セキュリティ
    /// - OSのエントロピーソースを利用
    /// - 一時バッファはZeroizingで自動消去
    /// - 自動再シード判定付き
    pub fn new() -> AppResult<Self> {
        let mut probe = Zeroizing::new([0u8; 32]);
        getrandom::fill(probe.as_mut())?;

        Ok(Self {
            output_counter: AtomicU64::new(0),
            request_counter: AtomicU64::new(0),
            last_reseed_time: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            reseed_threshold_bytes: Self::DEFAULT_RESEED_BYTES,
            reseed_threshold_requests: Self::DEFAULT_RESEED_REQUESTS,
            reseed_threshold_time: Self::DEFAULT_RESEED_TIME,
        })
    }

    /// 指定されたバッファに乱数バイトを生成
    /// OSエントロピーを直接使用し、基本的な品質チェック付き
    pub fn generate_bytes(&self, dest: &mut [u8]) -> AppResult<()> {
        // 自動再シード判定
        if self.should_auto_reseed()? {
            self.reseed()?;
        }

        // 乱数生成（OS RNG直読み）
        getrandom::fill(dest)?;

        // 基本的な品質チェック（全ゼロでないことを確認）
        if !dest.is_empty() && dest.iter().all(|&b| b == 0) {
            return Err(crate::core::app_errors::GenerationError::IoError(
                std::io::Error::other("Generated all-zero bytes - potential RNG failure"),
            ));
        }

        // カウンタ更新
        self.output_counter
            .fetch_add(dest.len() as u64, Ordering::Relaxed);
        self.request_counter.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// 自動再シード判定
    fn should_auto_reseed(&self) -> AppResult<bool> {
        let output_bytes = self.output_counter.load(Ordering::Relaxed);
        let requests = self.request_counter.load(Ordering::Relaxed);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                crate::core::app_errors::GenerationError::IoError(std::io::Error::other(
                    "Time error",
                ))
            })?
            .as_secs();
        let last_reseed = self.last_reseed_time.load(Ordering::Relaxed);

        let elapsed = current_time.saturating_sub(last_reseed);
        Ok(output_bytes >= self.reseed_threshold_bytes
            || requests >= self.reseed_threshold_requests
            || elapsed >= self.reseed_threshold_time)
    }

    /// 再シード
    /// 手動呼び出しまたは自動実行
    pub fn reseed(&self) -> AppResult<()> {
        let mut probe = Zeroizing::new([0u8; 32]);
        getrandom::fill(probe.as_mut())?;

        // カウンタリセット
        self.output_counter.store(0, Ordering::Relaxed);
        self.request_counter.store(0, Ordering::Relaxed);
        self.last_reseed_time.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );

        Ok(())
    }

    /// 統計情報取得
    pub fn get_statistics(&self) -> RngStatistics {
        RngStatistics {
            output_bytes: self.output_counter.load(Ordering::Relaxed),
            requests: self.request_counter.load(Ordering::Relaxed),
            last_reseed: self.last_reseed_time.load(Ordering::Relaxed),
        }
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// RNG 生成バイトの低レベル API
    /// 内部で[`generate_bytes`]を呼び出し、失敗時は即座にパニックして
    /// 予測可能な乱数列の流出を防ぐ。
    /// ライブラリ利用者向け注意
    /// 失敗時の制御を行いたい場合は [`generate_bytes`] を直接呼び出し
    /// `Result` を処理すること。
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.generate_bytes(dest) {
            if self.reseed().is_ok() && self.generate_bytes(dest).is_ok() {
                return;
            }
            panic!("Secure RNG failure: {e}");
        }
    }
}
impl CryptoRng for SecureRng {}

#[derive(Debug, Clone)]
pub struct RngStatistics {
    pub output_bytes: u64,
    pub requests: u64,
    pub last_reseed: u64,
}
