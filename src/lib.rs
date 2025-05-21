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

pub mod app_errors;
pub mod character_set;
pub mod cli;
pub mod generate_pass;
pub mod i18n;
pub mod password_generation;
pub mod password_length;
pub mod user_interface;
pub mod utils;

/// アプリケーション固有のエラー型とResultエイリアスを提供します。
pub use app_errors::{GenerationError, Result};
/// コマンドライン引数の解析に関連する機能を提供します。
pub use cli::{RupassArgs, parse_args};
/// パスワード生成の主要なフローを処理します。
pub use generate_pass::generate_password_flow;
/// 国際化対応のためのロケールバンドルを初期化します。
pub use i18n::initialize_bundle;
/// パスワード長のバリデーション機能を提供します。
pub use password_length::validate_password_length;
/// 標準入出力によるユーザーインターフェースを提供します。
pub use user_interface::StdioInterface;
/// 様々なユーティリティ関数を提供します。
pub use utils::{ask_user_yes_no, fallback_translation, parse_yes_no_input, prompt_loop};
