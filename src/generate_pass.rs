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
use crate::i18n::{RupassArgs, get_translation};
use crate::user_interface::UserInterface;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use futures::{FutureExt, future::LocalBoxFuture};
use rand::prelude::IndexedRandom;
use rand::prelude::SliceRandom;
use std::sync::Arc;
use tokio::task;
use zeroize::Zeroizing;
use zxcvbn::{Score, zxcvbn};

const DEFAULT_SPECIAL_CHARS: &str = "~!@#$%^&*_-+=(){}[]:;<>,.?/";
const MAX_GENERATION_ATTEMPTS: usize = 100_000;

// ヘルパー
fn fallback_translation(
    bundle: &FluentBundle<FluentResource>,
    key: &str,
    fallback: &str,
    args: Option<&FluentArgs>,
) -> String {
    get_translation(bundle, key, args).unwrap_or_else(|_| fallback.to_owned())
}

// 非同期プロンプトループ
async fn prompt_loop<T, E, F, H>(
    ui: &mut dyn UserInterface,
    prompt: &str,
    parse_fn: F,
    mut on_err: H,
) -> T
where
    F: Fn(&str) -> std::result::Result<T, E>,
    // LocalBoxFutureでSend制約を外す
    H: for<'a> FnMut(&'a mut dyn UserInterface, &'a E) -> LocalBoxFuture<'a, ()>,
{
    loop {
        let input = match ui.prompt(prompt).await {
            Ok(s) => s,
            Err(_) => {
                ui.print("Couldn't read input. Retrying...").await.ok();
                continue;
            }
        };
        match parse_fn(&input) {
            Ok(v) => break v,
            Err(e) => on_err(ui, &e).await,
        }
    }
}

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

/// パスワード⻑を取得して検証する
async fn get_password_length(
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
    let prompt = fallback_translation(
        bundle,
        "question_password_length",
        "Enter password length:",
        None,
    );
    let too_short_msg = Arc::new(fallback_translation(
        bundle,
        "error_password_too_short",
        "Password is too short.",
        None,
    ));

    // 入力ループ
    let len = prompt_loop(
        ui,
        &prompt,
        // 共通化
        |s| parse_length_input(s),
        {
            let msg = too_short_msg.clone();
            move |ui, _| {
                let msg = msg.clone();
                async move {
                    ui.print(&msg).await.ok();
                }
                .boxed_local()
            }
        },
    )
    .await;
    Ok(len)
}

fn validate_password_length(len: usize) -> Result<()> {
    if len < 15 {
        Err(GenerationError::InvalidLength)
    } else {
        Ok(())
    }
}

// 文字セット構築
async fn assemble_character_set(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<(String, Vec<String>)> {
    // unused_mut警告を解消
    let (base, req) = assemble_flag_based_charset(args);
    let (mut charset, mut req_sets) = ask_user_for_additional_sets(ui, bundle, base, req).await?;
    let special = handle_special_characters(ui, bundle, args).await?;
    if !special.is_empty() {
        charset.push_str(&special);
        req_sets.push(special);
    }

    if charset.is_empty() {
        let msg = fallback_translation(
            bundle,
            "error_no_charset_selected",
            "No valid character set was selected.",
            None,
        );
        ui.print(&msg).await?;
        return Err(GenerationError::NoCharacterSet);
    }

    Ok((charset, req_sets))
}

fn assemble_flag_based_charset(args: &RupassArgs) -> (String, Vec<String>) {
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

async fn ask_user_for_additional_sets(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    charset: String,
    required: Vec<String>,
) -> Result<(String, Vec<String>)> {
    let q = [
        ("question_uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("question_lowercase", "abcdefghijklmnopqrstuvwxyz"),
        ("question_numbers", "0123456789"),
    ];

    let (mut acc, mut req) = (charset, required);

    for (key, chars) in q {
        if req.iter().any(|r| r == chars) {
            continue;
        }
        let question = fallback_translation(bundle, key, "", None);
        if ask_user_yes_no(ui, bundle, &question).await? {
            acc.push_str(chars);
            req.push(chars.to_owned());
        }
    }
    Ok((acc, req))
}

// yes / noプロンプト
async fn ask_user_yes_no(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    message: &str,
) -> Result<bool> {
    if message.is_empty() {
        return Ok(false);
    }

    let invalid = Arc::new(fallback_translation(
        // Arcで共有
        bundle,
        "error_invalid_input",
        "Invalid input. Please enter yes or no.",
        None,
    ));

    let ans = prompt_loop(
        ui,
        message,
        // 共通化
        |s| parse_yes_no_input(s),
        {
            let msg = invalid.clone();
            move |ui, _| {
                let msg = msg.clone();
                async move {
                    ui.print(&msg).await.ok();
                }
                .boxed_local()
            }
        },
    )
    .await;

    Ok(ans)
}

// 特殊文字セット
async fn handle_special_characters(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    if args.symbols {
        return Ok(DEFAULT_SPECIAL_CHARS.to_owned());
    }

    let mut fargs = FluentArgs::new();
    fargs.set("specialChars", DEFAULT_SPECIAL_CHARS);

    let def_msg = fallback_translation(
        bundle,
        "default_special_chars_message",
        &format!("Default special chars: {DEFAULT_SPECIAL_CHARS}"),
        Some(&fargs),
    );
    ui.print(&def_msg).await?;

    let q = fallback_translation(
        bundle,
        "question_special_chars",
        "Use special characters?",
        None,
    );
    if ask_user_yes_no(ui, bundle, &q).await? {
        ask_special_chars(ui, bundle).await
    } else {
        Ok(String::new())
    }
}

async fn ask_special_chars(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
) -> Result<String> {
    let change_q = fallback_translation(
        bundle,
        "question_change_special_chars",
        "Change the default special chars?",
        None,
    );

    if ask_user_yes_no(ui, bundle, &change_q).await? {
        let enter_msg = fallback_translation(
            bundle,
            "question_enter_special_chars",
            "Enter special chars:",
            None,
        );
        let inp = ui.prompt(&enter_msg).await?;
        Ok(inp)
    } else {
        Ok(DEFAULT_SPECIAL_CHARS.to_owned())
    }
}

// 生成ロジック
// 同期処理
fn produce_secure_password(
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Zeroizing<String>> {
    validate_password_length(len)?;
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        if let Some(pwd) = assemble_random_password(all_vec, len, req) {
            if is_strong(&pwd) {
                return Ok(Zeroizing::new(pwd));
            }
        }
    }
    Err(GenerationError::GenerationFailed)
}

pub fn assemble_random_password(all_vec: &[char], len: usize, req: &[Vec<char>]) -> Option<String> {
    if all_vec.is_empty() {
        return None;
    }
    let mut rng = rand::rng();

    // 各必須セットから1文字ずつ
    let need: Vec<char> = req
        .iter()
        .filter_map(|set| set.choose(&mut rng).copied())
        .collect();

    if need.len() > len {
        return None;
    }

    let rest = len - need.len();
    let mut pwd: Vec<char> = need
        .into_iter()
        .chain((0..rest).filter_map(|_| all_vec.choose(&mut rng).copied()))
        .collect();

    pwd.shuffle(&mut rng);
    Some(pwd.iter().collect())
}

fn is_strong(pwd: &str) -> bool {
    zxcvbn(pwd, &[]).score() == Score::Four
}

/// yes/no系入力をブールへ変換
fn parse_yes_no_input(s: &str) -> std::result::Result<bool, ()> {
    match s.trim().to_lowercase().as_str() {
        "y" | "yes" | "はい" | "ja" => Ok(true),
        "n" | "no" | "いいえ" | "nein" => Ok(false),
        _ => Err(()),
    }
}

/// パスワード長を検証付きで数値化
fn parse_length_input(s: &str) -> std::result::Result<usize, GenerationError> {
    let v = s
        .trim()
        .parse::<usize>()
        .map_err(|_| GenerationError::InvalidLength)?;
    validate_password_length(v)?;
    Ok(v)
}
