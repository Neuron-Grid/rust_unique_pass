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
use fluent::{FluentArgs, FluentBundle, FluentResource};

const DEFAULT_SPECIAL_CHARS: &str = "~!@#$%^&*_-+=(){}[]:;<>,.?/";

/// # Overview
/// パスワード生成に使用する文字セットを組み立てます。
/// コマンドライン引数とユーザーの入力を基に、使用可能な文字と必須の文字セットを決定します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// 組み立てられた文字セット全体 (`String`) と、パスワードに最低1文字含める必要がある文字セットのリスト (`Vec<String>`) を含むタプルを返します。
///
/// # Errors
/// ユーザー入力の処理中にエラーが発生した場合、[`GenerationError`] を含む [`Result`] を返します。
/// 文字セットが何も選択されなかった場合、[`GenerationError::NoCharacterSet`] を返します。
#[doc(alias = "charset")]
#[doc(alias = "character set")]
pub async fn assemble_character_set(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<(String, Vec<String>)> {
    let (base, req) = assemble_flag_based_charset(args);
    let (mut charset, mut req_sets) = if args.no_prompt {
        (base, req)
    } else {
        ask_user_for_additional_sets(ui, bundle, args, base, req).await?
    };

    let special = if args.no_prompt {
        handle_special_characters_no_prompt(args)
    } else {
        handle_special_characters(ui, bundle, args).await
    }?;
    if !special.is_empty() {
        charset.push_str(&special);
        req_sets.push(special);
    }

    if charset.is_empty() {
        let msg = crate::core::utils::fallback_translation(
            bundle,
            "error_no_charset_selected",
            "No valid character set was selected.",
            None,
        );
        ui.print(&msg).await?;
        return Err(GenerationError::NoCharacterSet);
    }

    // 文字セットの重複除去と最適化
    let charset = remove_duplicate_chars(&charset);
    let req_sets = req_sets
        .into_iter()
        .map(|s| remove_duplicate_chars(&s))
        .filter(|s| !s.is_empty())
        .collect();

    Ok((charset, req_sets))
}

/// # Overview
/// コマンドラインフラグに基づいて初期の文字セットと必須文字セットを組み立てます。
///
/// # Arguments
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// フラグに基づいて組み立てられた文字セット (`String`) と、必須文字セットのリスト (`Vec<String>`) を含むタプルを返します。
fn assemble_flag_based_charset(args: &RupassArgs) -> (String, Vec<String>) {
    // --all が指定されている場合は全セットを有効化
    if args.all {
        return (
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".to_string(),
            vec![
                "0123456789".to_string(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
                "abcdefghijklmnopqrstuvwxyz".to_string(),
            ],
        );
    }

    let init = (String::new(), Vec::new());
    [
        (args.numbers, "0123456789"),
        (args.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (args.lowercase, "abcdefghijklmnopqrstuvwxyz"),
    ]
    .iter()
    .fold(init, |(mut acc, mut req), (flag, set)| {
        if *flag {
            acc.push_str(set);
            req.push((*set).to_owned());
        }
        (acc, req)
    })
}

/// # Overview
/// 文字列から重複文字を除去し、効率的な文字セットを生成します。
/// パスワード生成処理の最適化に寄与します。
///
/// # Arguments
/// * `input`: 重複除去対象の文字列
///
/// # Returns
/// 重複が除去された文字列
fn remove_duplicate_chars(input: &str) -> String {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    input.chars().filter(|&c| seen.insert(c)).collect()
}

/// # Overview
/// ユーザーに追加の文字セット（大文字、小文字、数字）を使用するかどうかを尋ねます。
/// コマンドラインフラグで既に含まれている場合はスキップします。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
/// * `charset`: 現在の文字セット。
/// * `required`: 現在の必須文字セットのリスト。
///
/// # Returns
/// ユーザーの選択に基づいて更新された文字セット (`String`) と必須文字セットのリスト (`Vec<String>`) を含むタプルを返します。
///
/// # Errors
/// ユーザー入力の処理中にエラーが発生した場合、[`GenerationError`] を含む [`Result`] を返します。
async fn ask_user_for_additional_sets(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
    charset: String,
    required: Vec<String>,
) -> Result<(String, Vec<String>)> {
    let q = [
        (
            args.no_uppercase,
            "question_uppercase",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        (
            args.no_lowercase,
            "question_lowercase",
            "abcdefghijklmnopqrstuvwxyz",
        ),
        (args.no_numbers, "question_numbers", "0123456789"),
    ];

    let (mut acc, mut req) = (charset, required);

    for (skip, key, chars) in q {
        if skip {
            continue;
        }

        if req.iter().any(|r| r == chars) {
            continue;
        }
        let question = crate::core::utils::fallback_translation(bundle, key, "", None);
        if crate::core::utils::ask_user_yes_no(ui, bundle, &question).await? {
            acc.push_str(chars);
            req.push(chars.to_owned());
        }
    }
    Ok((acc, req))
}

/// # Overview
/// 特殊文字を文字セットに含めるかどうかを処理します。
/// コマンドラインフラグで指定されている場合はデフォルトの特殊文字を使用し、
/// そうでない場合はユーザーに確認します。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体。
///
/// # Returns
/// 使用する特殊文字の文字列を返します。特殊文字を使用しない場合は空文字列を返します。
///
/// # Errors
/// ユーザー入力の処理中にエラーが発生した場合、[`GenerationError`] を含む [`Result`] を返します。
async fn handle_special_characters(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    if args.no_symbols {
        return Ok(String::new());
    }

    if args.all {
        return Ok(DEFAULT_SPECIAL_CHARS.to_owned());
    }

    if let Some(custom) = args.symbols_set.as_ref() {
        return Ok(custom.clone());
    }

    if args.symbols {
        return Ok(DEFAULT_SPECIAL_CHARS.to_owned());
    }

    let mut fargs = FluentArgs::new();
    fargs.set("specialChars", DEFAULT_SPECIAL_CHARS);

    let def_msg = crate::core::utils::fallback_translation(
        bundle,
        "default_special_chars_message",
        &format!("Default special chars: {DEFAULT_SPECIAL_CHARS}"),
        Some(&fargs),
    );
    ui.print(&def_msg).await?;

    let q = crate::core::utils::fallback_translation(
        bundle,
        "question_special_chars",
        "Use special characters?",
        None,
    );
    if crate::core::utils::ask_user_yes_no(ui, bundle, &q).await? {
        ask_special_chars(ui, bundle).await
    } else {
        Ok(String::new())
    }
}

// 非対話モード用: yes/no を尋ねずに決定する
fn handle_special_characters_no_prompt(args: &RupassArgs) -> Result<String> {
    if args.no_symbols {
        return Ok(String::new());
    }

    if args.all {
        return Ok(DEFAULT_SPECIAL_CHARS.to_owned());
    }

    if let Some(custom) = args.symbols_set.as_ref() {
        return Ok(custom.clone());
    }

    if args.symbols || args.all {
        return Ok(DEFAULT_SPECIAL_CHARS.to_owned());
    }

    Ok(String::new())
}

/// # Overview
/// ユーザーに特殊文字を変更するかどうか、および使用する特殊文字を入力するかどうかを尋ねます。
///
/// # Arguments
/// * `ui`: ユーザーとの対話に使用する [`UserInterface`] トレイトオブジェクト。
/// * `bundle`: 国際化対応に使用する [`FluentBundle`] オブジェクト。
///
/// # Returns
/// ユーザーが指定した特殊文字の文字列を返します。デフォルトを使用する場合はデフォルトの特殊文字を返します。
///
/// # Errors
/// ユーザー入力の処理中にエラーが発生した場合、[`GenerationError`] を含む [`Result`] を返します。
async fn ask_special_chars(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
) -> Result<String> {
    let change_q = crate::core::utils::fallback_translation(
        bundle,
        "question_change_special_chars",
        "Change the default special chars?",
        None,
    );

    if crate::core::utils::ask_user_yes_no(ui, bundle, &change_q).await? {
        let enter_msg = crate::core::utils::fallback_translation(
            bundle,
            "question_enter_special_chars",
            "Enter special chars:",
            None,
        );
        let inp = ui.prompt(&enter_msg).await?;
        // ユーザー入力の特殊文字もバリデーション
        if inp.is_empty() {
            let fallback_msg = crate::core::utils::fallback_translation(
                bundle,
                "warning_empty_special_chars",
                "Empty input received, using default special characters.",
                None,
            );
            ui.print(&fallback_msg).await?;
            Ok(DEFAULT_SPECIAL_CHARS.to_owned())
        } else {
            Ok(inp)
        }
    } else {
        Ok(DEFAULT_SPECIAL_CHARS.to_owned())
    }
}
