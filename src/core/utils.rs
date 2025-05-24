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

use crate::cli::UserInterface;
use crate::core::app_errors::{GenerationError, Result};
use fluent::{FluentArgs, FluentBundle, FluentResource};
use futures::{FutureExt, future::LocalBoxFuture};

/// # Overview
/// 指定されたキーに対応する翻訳メッセージを [`FluentBundle`] から取得します。
/// 翻訳が見つからない場合は、指定されたフォールバック文字列を返します。
///
/// # Arguments
/// * `bundle`: 翻訳メッセージを取得する [`FluentBundle`] への参照。
/// * `key`: 取得する翻訳メッセージのキー。
/// * `fallback`: 翻訳が見つからなかった場合に返すフォールバック文字列。
/// * `args`: 翻訳メッセージに適用する引数を含む [`FluentArgs`] へのオプションの参照。
///
/// # Returns
/// 取得された翻訳メッセージまたはフォールバック文字列を含む [`String`] を返します。
#[doc(alias = "translate")]
#[doc(alias = "i18n")]
pub fn fallback_translation(
    bundle: &FluentBundle<FluentResource>,
    key: &str,
    fallback: &str,
    args: Option<&FluentArgs>,
) -> String {
    crate::core::i18n::get_translation(bundle, key, args).unwrap_or_else(|_| fallback.to_owned())
}

/// # Overview
/// ユーザーからの有効な入力を繰り返しプロンプト表示して取得するための非同期ループ。
/// 入力は指定されたパース関数によって検証され、無効な場合はエラーハンドラが実行されます。
/// 連続した入力エラーを制限し、システムの安定性を確保します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `prompt`: ユーザーに表示するプロンプトメッセージ。
/// * `parse_fn`: 入力文字列を目的の型 `T` にパースし、結果を [`std::result::Result<T, E>`] で返すクロージャ。
/// * `on_err`: パース関数がエラー `E` を返した場合に実行される非同期エラーハンドラクロージャ。
///
/// # Returns
/// パース関数によって返された有効な値 `T`。
///
/// # Type Parameters
/// * `T`: 期待される入力の型。
/// * `E`: パース関数が返すエラーの型。
/// * `F`: パース関数の型。
/// * `H`: エラーハンドラクロージャの型。
///
/// # Panics
/// 連続した入力読み取りエラーが最大再試行回数(10回)を超えた場合にパニックします。
#[doc(alias = "prompt")]
#[doc(alias = "input loop")]
pub async fn prompt_loop<T, E, F, H>(
    ui: &mut dyn UserInterface,
    prompt: &str,
    parse_fn: F,
    mut on_err: H,
) -> T
where
    F: Fn(&str) -> std::result::Result<T, E>,
    H: for<'a> FnMut(&'a mut dyn UserInterface, &'a E) -> LocalBoxFuture<'a, ()>,
{
    const MAX_INPUT_FAILURES: usize = 10;
    let mut consecutive_failures = 0;

    loop {
        let input = match ui.prompt(prompt).await {
            Ok(s) => {
                consecutive_failures = 0; // Reset counter on success
                s
            }
            Err(e) => {
                consecutive_failures += 1;
                let retry_msg = format!(
                    "Failed to read input (attempt {}/{}): {}",
                    consecutive_failures, MAX_INPUT_FAILURES, e
                );

                if let Err(_e) = ui.print(&retry_msg).await {}

                if consecutive_failures >= MAX_INPUT_FAILURES {
                    panic!(
                        "Consecutive input errors exceeded maximum attempts ({}). Terminating system.",
                        MAX_INPUT_FAILURES
                    );
                }
                continue;
            }
        };

        match parse_fn(&input) {
            Ok(v) => break v,
            Err(e) => on_err(ui, &e).await,
        }
    }
}

/// # Overview
/// ユーザーに yes/no の質問を投げかけ、その回答をブール値として取得します。
/// 無効な入力の場合は繰り返し質問します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `message`: ユーザーに表示する質問メッセージ。
///
/// # Returns
/// ユーザーの回答に対応するブール値 (`true` for yes, `false` for no) を含む [`Result<bool>`] を返します。
///
/// # Errors
/// 入出力エラーが発生した場合、[`Result`] を返します。
#[doc(alias = "ask")]
#[doc(alias = "yes no")]
pub async fn ask_user_yes_no(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    message: &str,
) -> Result<bool> {
    if message.is_empty() {
        return Ok(false);
    }

    let invalid_msg = fallback_translation(
        bundle,
        "error_invalid_input",
        "Invalid input. Please enter yes or no.",
        None,
    );

    let ans = prompt_loop(ui, message, parse_yes_no_input, {
        move |ui, _error| {
            let msg = invalid_msg.clone();
            async move {
                ui.print(&msg).await.ok();
            }
            .boxed_local()
        }
    })
    .await;

    Ok(ans)
}

/// # Overview
/// yes/no に関連する入力文字列をパースし、対応するブール値に変換します。
/// "y", "yes", "はい", "ja" は `true` に、"n", "no", "いいえ", "nein" は `false` にマッピングされます。
/// 大文字・小文字は区別されません。
///
/// # Arguments
/// * `s`: パースする入力文字列。
///
/// # Returns
/// パースに成功した場合、対応するブール値を含む [`std::result::Result<bool, ()>`] を返します。
/// 有効な yes/no 入力でない場合、エラー (`Err(())`) を返します。
#[doc(alias = "parse")]
#[doc(alias = "yes no")]
pub fn parse_yes_no_input(s: &str) -> std::result::Result<bool, GenerationError> {
    match s.trim().to_lowercase().as_str() {
        "y" | "yes" | "はい" | "ja" => Ok(true),
        "n" | "no" | "いいえ" | "nein" => Ok(false),
        _ => Err(GenerationError::InvalidInput),
    }
}
