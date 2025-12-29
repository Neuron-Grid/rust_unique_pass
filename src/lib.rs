/* Copyright 2024-2025 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

mod cli;
mod core;
mod crypto;
mod password;

/// コマンドライン引数の解析に関連する機能を提供します。
pub use cli::{RupassArgs, parse_args};
/// 標準入出力によるユーザーインターフェースを提供します。
pub use cli::{StdioInterface, UserInterface};
/// CLI の終了コードマッピングを提供します。
pub use core::exit_code_for_error;
/// アプリケーション固有のエラー型とResultエイリアスを提供します。
pub use core::{GenerationError, Result};
/// 様々なユーティリティ関数を提供します。
pub use core::{ask_user_yes_no, fallback_translation, parse_yes_no_input, prompt_loop};
/// 国際化対応のためのロケールバンドルを初期化します。
pub use core::{get_translation, initialize_bundle};
/// 暗号/ユーティリティ系の公開API。
pub use crypto::{CryptoError, GlobalRngStatistics, RngStatistics, SecureMemory, SecureRng};
pub use crypto::{MAX_PASSWORD_BYTES, MAX_PASSWORD_CHARS, zxcvbn_entropy_score};
pub use crypto::{MemoryProtection, SecureString, TimingSafeOps, get_global_rng};
pub use crypto::global_rng::{ByteStream, GlobalRng, GlobalRngStream};
/// パスワード生成の主要なフローを処理します。
pub use password::{
    FlowReport, PasswordStrengthEvaluator, generate_password_flow,
    generate_password_flow_with_evaluator, generate_password_flow_with_min_score,
    produce_secure_password, validate_password_length,
};
