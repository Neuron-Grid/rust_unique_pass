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

use crate::app_errors::{GenerationError, Result};
use crate::character_set::assemble_character_set;
use crate::cli::RupassArgs;
use crate::password_generation::produce_secure_password;
use crate::password_length::get_password_length;
use crate::user_interface::UserInterface;
use crate::utils::fallback_translation;
use fluent::{FluentBundle, FluentResource};
use tokio::task;

#[doc(alias = "generate")]
/// # Overview
/// パスワード生成の主要なフローを実行します。
/// ユーザーインターフェースを通じてパスワード長と使用文字セットを取得し、
/// 安全なパスワードを生成して表示します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// パスワード生成フローが成功した場合は `Ok(())` を返します。
///
/// # Errors
/// パスワード長の取得、文字セットの組み立て、またはパスワード生成中にエラーが発生した場合、
/// [`GenerationError`] を含む [`Result`] を返します。
///
/// # Notes
/// パスワード生成処理は計算コストが高いため、ブロッキングスレッドプール
/// (`tokio::task::spawn_blocking`) で実行されます。
/// 生成されたパスワードは [`Zeroizing<String>`] でラップされ、スコープを離れる際に自動的にゼロクリアされます。
// パスワード生成フローのエントリポイント
pub async fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<()> {
    let gen_msg = fallback_translation(bundle, "generated_password", "Generated password:", None);
    let length = get_password_length(ui, bundle, args).await?;
    let (all_chars, req_sets) = assemble_character_set(ui, bundle, args).await?;

    let all_vec: Vec<char> = all_chars.chars().collect();
    let req_vec: Vec<Vec<char>> = req_sets.iter().map(|s| s.chars().collect()).collect();

    // heavy task => blocking thread-pool
    let pwd = task::spawn_blocking(move || produce_secure_password(&all_vec, length, &req_vec))
        .await
        .map_err(|_| GenerationError::GenerationFailed)??;

    // `Zeroizing<String>` → &str
    // 明示的にデリファレンスして表示
    ui.print(&format!("{gen_msg}\n{}\n", pwd.as_str())).await?;

    // スコープ離脱で自動zeroize
    drop(pwd);
    Ok(())
}
