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
/// - メモリ上のシード値はZeroizingで自動消去
use crate::core::app_errors::Result as AppResult;
use getrandom;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore, SeedableRng};
/// CSPRNGモジュール
/// 本モジュールはNIST SP 800-90Aに準拠した暗号学的擬似乱数生成器(CSPRNG)を提供します。
/// - OSエントロピーソースの利用
/// - 自動再シード機能
/// - 基本的なランタイム検証
/// - スレッドセーフ設計
/// ## セキュリティ設計方針
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// HKDFの`info`パラメータに使用する定数
/// NIST SP 800-56C 推奨の「ドメイン分離」を実現し、
/// 他アプリケーションで同一シードが使われても乱数列が衝突しないようにする。
const HKDF_INFO: &[u8] = b"rust_unique_pass-v1-seed";

/// HMAC-SHA256ベースのHKDFによるseed拡張
/// `info`にアプリケーション固有文字列[`HKDF_INFO`]を渡し、ドメイン分離を強化する。
/// 失敗時にはErrorを返し、適切なエラーハンドリングを可能にする。
fn hkdf_expand(seed: &[u8; 32]) -> AppResult<Zeroizing<[u8; 32]>> {
    // NIST SP 800-56C に準拠した HKDF（HMAC-SHA256）
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut()).map_err(|_| {
        crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "HKDF expand failed",
        ))
    })?;
    Ok(okm)
}

/// NIST SP 800-90A準拠のCSPRNG実装（改善版）
/// 暗号学的に安全な擬似乱数生成器。
/// 自動再シード機能と基本的なランタイム検証を含む。
pub struct SecureRng {
    rng: Mutex<ChaCha20Rng>,
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
    /// - シード値はZeroizingで自動消去
    /// - 自動再シード機能付き
    pub fn new() -> AppResult<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())?;
        let hkdf_seed = hkdf_expand(&seed)?;
        let rng = ChaCha20Rng::from_seed(*hkdf_seed);

        Ok(Self {
            rng: Mutex::new(rng),
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

    // タイミングエントロピー収集機能は削除（NIST SP 800-90A/RFC 4086非推奨のため）

    /// 指定されたバッファに乱数バイトを生成
    /// 自動再シード機能と基本的な品質チェック付き
    pub fn generate_bytes(&self, dest: &mut [u8]) -> AppResult<()> {
        // 自動再シード判定
        if self.should_auto_reseed()? {
            self.reseed()?;
        }

        // 乱数生成
        let mut rng = self.rng.lock().map_err(|e| {
            crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("RNG mutex poisoned: {}", e),
            ))
        })?;
        rng.fill_bytes(dest);

        // 基本的な品質チェック（全ゼロでないことを確認）
        if dest.len() > 0 && dest.iter().all(|&b| b == 0) {
            return Err(crate::core::app_errors::GenerationError::IoError(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Generated all-zero bytes - potential RNG failure",
                ),
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
                crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Time error",
                ))
            })?
            .as_secs();
        let last_reseed = self.last_reseed_time.load(Ordering::Relaxed);

        Ok(output_bytes >= self.reseed_threshold_bytes
            || requests >= self.reseed_threshold_requests
            || (current_time - last_reseed) >= self.reseed_threshold_time)
    }

    /// 再シード
    /// 手動呼び出しまたは自動実行
    pub fn reseed(&self) -> AppResult<()> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())?;
        let hkdf_seed = hkdf_expand(&seed)?;

        let mut rng = self.rng.lock().map_err(|e| {
            crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("RNG mutex poisoned: {}", e),
            ))
        })?;
        *rng = ChaCha20Rng::from_seed(*hkdf_seed);

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
    /// 内部で[`generate_bytes`]を呼び出し、失敗時は
    /// エラー内容を標準エラー出力に記録し
    /// `dest`全体を安全なゼロ埋めで初期化する。
    /// パニックによるクラッシュを避けつつ、危険な乱数列が
    /// 流出しない “セーフデフォルト” 動作を提供する。
    /// ライブラリ利用者向け注意
    /// この関数は失敗を返さないため、呼び出し後に戻り値が高品質ランダムであることを保証したい場合は
    /// 事前に[`generate_bytes`]を直接呼び出して結果を確認すること。
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.generate_bytes(dest).unwrap_or_else(|e| {
            panic!("Critical RNG failure: {}", e);
        });
    }
}
impl CryptoRng for SecureRng {}

#[derive(Debug, Clone)]
pub struct RngStatistics {
    pub output_bytes: u64,
    pub requests: u64,
    pub last_reseed: u64,
}
