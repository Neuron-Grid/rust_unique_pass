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

use rust_unique_pass::{
    Result, StdioInterface, generate_password_flow, initialize_bundle, parse_args,
};

/// # Overview
/// アプリケーションのエントリポイント。
/// コマンドライン引数をパースし、国際化対応バンドルを初期化し、
/// パスワード生成フローを実行します。
///
/// # Returns
/// 処理が成功した場合、`Ok(())` を返します。
///
/// # Errors
/// コマンドライン引数のパース、バンドルの初期化、またはパスワード生成フローの実行中に
/// エラーが発生した場合、[`Result`] を返します。
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = parse_args();
    let bundle = initialize_bundle(&args)?;
    let mut ui = StdioInterface::default();
    generate_password_flow(&mut ui, &bundle, &args).await?;
    Ok(())
}
