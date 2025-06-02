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

/// 暗号学的セキュリティモジュール
pub mod rng;
pub mod secure_memory;
pub mod timing_safe;
pub use rng::SecureRng;
pub use secure_memory::{SecureMemory, SecureString};
pub use timing_safe::{SecureStringOps, TimingSafeOps};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to obtain entropy source")]
    EntropySourceFailure,

    #[error("Insufficient entropy")]
    InsufficientEntropy,

    #[error("Requested size is too large")]
    RequestTooLarge,

    #[error("Reseed required")]
    ReseedRequired,

    #[error("RNG initialization error")]
    RngInitError,

    #[error("Memory security error: {0}")]
    MemoryError(String),

    #[error("Mutex poisoned: {0}")]
    MutexPoisoned(String),
}

/// Crypto モジュール専用のResult型
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
