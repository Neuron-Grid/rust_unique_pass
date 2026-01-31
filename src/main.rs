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

use rust_unique_pass::run_cli;
use std::process::ExitCode;

/// # Overview
/// アプリケーションのエントリポイント。
/// 実処理は外部モジュールに委譲します。
/// Tokioランタイムは current_thread を明示的に使用します。
///
/// # Returns
/// 処理結果に応じて [`ExitCode`] を返します。
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    run_cli().await
}
