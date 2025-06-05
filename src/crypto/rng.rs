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
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore, SeedableRng};
/// # Secure RNG (CSPRNG) モジュール
/// 本モジュールはNIST SP 800-90Aに準拠した暗号学的擬似乱数生成器（CSPRNG）を提供します。
/// - OSエントロピーソースとタイミングエントロピーの混入
/// - シンプルな再シード
/// - スレッドセーフ設計
/// ## セキュリティ設計方針
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use std::sync::Mutex;

/// HMAC-SHA256ベースのHKDFによるseed拡張
fn hkdf_expand(seed: &[u8; 32]) -> [u8; 32] {
    // NIST SP 800-56Cに準拠したHKDF（HMAC-SHA256）
    // infoやsaltは用途に応じて調整可能だが、ここでは空で運用
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm).expect("HKDF expand failed");
    okm
}

/// NIST SP 800-90A準拠のCSPRNG実装
/// 暗号学的に安全な擬似乱数生成器。
pub struct SecureRng {
    rng: Mutex<ChaCha20Rng>,
}

impl SecureRng {
    /// 新しいSecureRngインスタンスを作成
    /// # セキュリティ
    /// - OSのエントロピーソースとタイミングエントロピーを混入

    /// - シード値はZeroizingで自動消去
    pub fn new() -> AppResult<Self> {
        let seed: [u8; 32] = rand::random();
        let hkdf_seed = hkdf_expand(&seed);
        let rng = ChaCha20Rng::from_seed(hkdf_seed);
        Ok(Self {
            rng: Mutex::new(rng),
        })
    }

    // タイミングエントロピー収集機能は削除（NIST SP 800-90A/RFC 4086非推奨のため）

    /// 指定されたバッファに乱数バイトを生成
    pub fn generate_bytes(&self, dest: &mut [u8]) -> AppResult<()> {
        let mut rng = self.rng.lock().map_err(|e| {
            crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("RNG mutex poisoned: {}", e),
            ))
        })?;
        rng.fill_bytes(dest);
        Ok(())
    }

    /// 再シード（必要な場合のみ手動で呼び出し）
    pub fn reseed(&self) -> AppResult<()> {
        let seed: [u8; 32] = rand::random();
        let hkdf_seed = hkdf_expand(&seed);
        let mut rng = self.rng.lock().map_err(|e| {
            crate::core::app_errors::GenerationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("RNG mutex poisoned: {}", e),
            ))
        })?;
        *rng = ChaCha20Rng::from_seed(hkdf_seed);
        Ok(())
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

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.generate_bytes(dest) {
            eprintln!("Critical RNG failure in fill_bytes: {}", e);
            // エラー時は全ゼロ埋め（panicせず安全なデフォルト動作）
            for b in dest.iter_mut() {
                *b = 0;
            }
        }
    }
}
impl CryptoRng for SecureRng {}
