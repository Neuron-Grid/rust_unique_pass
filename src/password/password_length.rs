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

use crate::cli::RupassArgs;
use crate::cli::UserInterface;
use crate::core::app_errors::{GenerationError, Result};
use fluent::FluentBundle;
use fluent::FluentResource;
use futures::FutureExt;
use std::sync::Arc;

/// # Overview
/// パスワード長を取得し、その値が有効であるかを検証します。
/// コマンドライン引数で指定されている場合はその値を、そうでない場合はユーザーに問い合わせて取得します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// 取得および検証されたパスワード長 (`usize`) を返します。
///
/// # Errors
/// コマンドライン引数またはユーザー入力から取得したパスワード長が不正な場合、
/// [`GenerationError::InvalidLength`] を含む [`Result`] を返します。
#[doc(alias = "length")]
#[doc(alias = "password length")]
pub async fn get_password_length(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<usize> {
    // 事前指定があれば即検証・返却
    if let Some(len) = args.password_length {
        validate_password_length(len)?;
        return Ok(len);
    }
    // 翻訳済みメッセージを先に生成
    let prompt = crate::core::utils::fallback_translation(
        bundle,
        "question_password_length",
        "Enter password length:",
        None,
    );
    let too_short_msg = Arc::new(crate::core::utils::fallback_translation(
        bundle,
        "error_password_too_short",
        "Password is too short.",
        None,
    ));

    // 入力ループ
    let len = crate::core::utils::prompt_loop(ui, &prompt, parse_length_input, {
        let msg = too_short_msg.clone();
        move |ui, _| {
            let msg = msg.clone();
            async move {
                ui.print(&msg).await.ok();
            }
            .boxed_local()
        }
    })
    .await;
    Ok(len)
}

/// # Overview
/// 指定されたパスワード長が有効であるかを検証します。
/// 現在は15文字未満の長さを無効としています。
///
/// # Arguments
/// * `len`: 検証するパスワード長。
///
/// # Returns
/// パスワード長が有効な場合、`Ok(())` を返します。
///
/// # Errors
/// パスワード長が15文字未満の場合、[`GenerationError::InvalidLength`] を含む [`Result`] を返します。
#[doc(alias = "validate")]
#[doc(alias = "length validation")]
pub fn validate_password_length(len: usize) -> Result<()> {
    if len < 15 {
        Err(GenerationError::InvalidLength)
    } else {
        Ok(())
    }
}

/// # Overview
/// 入力文字列をパスワード長 (`usize`) にパースし、その値が有効であるかを検証します。
///
/// # Arguments
/// * `s`: パースおよび検証する入力文字列。
///
/// # Returns
/// パースおよび検証されたパスワード長 (`usize`) を返します。
///
/// # Errors
/// 入力文字列が `usize` にパースできない場合、またはパースされた値が [`validate_password_length`] で無効と判断された場合、
/// [`GenerationError::InvalidLength`] を含む [`std::result::Result`] を返します。
fn parse_length_input(s: &str) -> std::result::Result<usize, GenerationError> {
    let v = s
        .trim()
        .parse::<usize>()
        .map_err(|_| GenerationError::InvalidLength)?;
    validate_password_length(v)?;
    Ok(v)
}
