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
    generate_password_flow, initialize_bundle, parse_args, Result, StdioInterface,
};

fn main() -> Result<()> {
    // コマンドライン引数をパース
    let args = parse_args();
    // 翻訳バンドルの初期化
    let bundle = initialize_bundle(&args)?;
    // CLI入出力（標準入出力）インターフェース
    let mut ui = StdioInterface;
    // パスワードの生成
    generate_password_flow(&mut ui, &bundle, &args)?;
    Ok(())
}
