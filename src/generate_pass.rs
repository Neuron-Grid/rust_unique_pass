/* Copyright 2023-2024 Neuron Grid

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
use crate::i18n::{get_translation, RupassArgs};
use crate::user_interface::UserInterface;
use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use rand::{prelude::SliceRandom, rngs::OsRng};
use std::collections::HashMap;
use zxcvbn::{zxcvbn, Score};

const DEFAULT_SPECIAL_CHARS: &str = "!?@#$%^&*()";
const MAX_GENERATION_ATTEMPTS: usize = 100000;

/// メインのパスワード生成フロー
pub fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    let generated_password_msg = get_translation(bundle, "generated_password", None)?;
    let length = get_password_length(ui, bundle, args)?;

    // assemble_character_setで全体の文字セット, 必須文字セットを取得
    let (all_chars, required_sets) = assemble_character_set(ui, bundle, args)?;

    // パスワードを生成する
    let password = produce_secure_password(&all_chars, length, &required_sets)?;

    ui.print(&format!("{}\n{}\n", generated_password_msg, &password));
    Ok(password)
}

/// パスワード長を取得する
pub fn get_password_length(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<usize> {
    // CLI引数で長さが指定されていればそれを優先
    if let Some(l) = args.password_length {
        validate_password_length(l)?;
        return Ok(l);
    }

    // 未指定の場合、ユーザーに尋ねる
    let prompt_message = get_translation(bundle, "question_password_length", None)
        .unwrap_or_else(|_| "Enter password length:".to_string());

    // ユーザーにパスワード長を繰り返し聞く
    ask_password_length(ui, bundle, &prompt_message)
}

/// パスワード長が 15 文字未満の場合はエラー
pub fn validate_password_length(length: usize) -> Result<()> {
    if length < 15 {
        return Err(GenerationError::InvalidLength);
    }
    Ok(())
}

/// 指定した文字集合で、強度が十分なパスワードを生成する
pub fn produce_secure_password(
    all_chars: &str,
    length: usize,
    required_sets: &[String],
) -> Result<String> {
    validate_password_length(length)?;

    match try_generate_strong_password(all_chars, length, required_sets, 0) {
        Some(password) => Ok(password),
        None => Err(GenerationError::GenerationFailed),
    }
}

/// ユーザー入力でパスワード長を再帰的に取得する
fn ask_password_length(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    prompt: &str,
) -> Result<usize> {
    let input = ui.prompt(prompt)?;
    match input.parse::<usize>() {
        Ok(n) => match validate_password_length(n) {
            Ok(_) => Ok(n),
            Err(e) => {
                print_length_error(ui, bundle, &e)?;
                ask_password_length(ui, bundle, prompt)
            }
        },
        Err(_) => {
            let msg = get_translation(bundle, "error_non_numeric_input", None)
                .unwrap_or_else(|_| "Input is not numeric.".to_string());
            ui.print(&msg);
            ask_password_length(ui, bundle, prompt)
        }
    }
}

/// パスワード長エラーを表示する
fn print_length_error(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    err: &GenerationError,
) -> Result<()> {
    let msg = match err {
        GenerationError::InvalidLength => get_translation(bundle, "error_password_too_short", None)
            .unwrap_or_else(|_| "Password is too short.".to_string()),
        _ => "Invalid length.".to_string(),
    };
    ui.print(&msg);
    Ok(())
}

/// 全体の文字セットと必須文字セットを返す
fn assemble_character_set(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<(String, Vec<String>)> {
    let (charset, required) = assemble_flag_based_charset(args);

    // 対話的に文字種を追加
    let (mut assembled_charset, mut required_sets) =
        ask_user_for_additional_sets(ui, bundle, charset, required)?;

    // 特殊文字の対話処理
    let special_characters_set = handle_special_characters(ui, bundle, args)?;
    if !special_characters_set.is_empty() {
        assembled_charset.push_str(&special_characters_set);
        required_sets.push(special_characters_set);
    }

    // 全体が空ならエラー
    if assembled_charset.is_empty() {
        return Err(GenerationError::NoCharacterSet);
    }

    Ok((assembled_charset, required_sets))
}

/// フラグ指定済みの文字種を組み立て、必須文字リストに加える
fn assemble_flag_based_charset(args: &RupassArgs) -> (String, Vec<String>) {
    let initial = (String::new(), Vec::new());
    [
        (args.numbers, "0123456789"),
        (args.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (args.lowercase, "abcdefghijklmnopqrstuvwxyz"),
    ]
    .iter()
    .fold(initial, |(mut ac, mut rs), (flag, chars)| {
        if *flag {
            ac.push_str(chars);
            rs.push(chars.to_string());
        }
        (ac, rs)
    })
}

/// フラグが false の文字種について、ユーザーに確認して追加する
fn ask_user_for_additional_sets(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    charset: String,
    required: Vec<String>,
) -> Result<(String, Vec<String>)> {
    let questions = [
        (
            "question_uppercase",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            // フラグが true だったか、すでに必須文字リストに含まれているか
            required.iter().any(|r| r == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ),
        (
            "question_lowercase",
            "abcdefghijklmnopqrstuvwxyz",
            required.iter().any(|r| r == "abcdefghijklmnopqrstuvwxyz"),
        ),
        (
            "question_numbers",
            "0123456789",
            required.iter().any(|r| r == "0123456789"),
        ),
    ];

    // foldを用いてイミュータブルに更新
    let (assembled_charset, required_sets) = questions.iter().fold(
        (charset, required),
        |(ac, rs), (key, chars, already_added)| {
            if *already_added {
                (ac, rs)
            } else {
                let question = match get_translation(bundle, key, None) {
                    Ok(q) => q,
                    Err(_) => "".to_string(),
                };
                let use_this = ask_user_yes_no(ui, bundle, &question).unwrap_or(false);
                if use_this {
                    let mut new_ac = ac.clone();
                    new_ac.push_str(chars);
                    let mut new_rs = rs.clone();
                    new_rs.push(chars.to_string());
                    (new_ac, new_rs)
                } else {
                    (ac, rs)
                }
            }
        },
    );

    Ok((assembled_charset, required_sets))
}

/// 特殊文字の対話処理
fn handle_special_characters(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    if args.symbols {
        // フラグが立っていればデフォルトの特殊文字を返す
        return Ok(DEFAULT_SPECIAL_CHARS.to_string());
    }

    // 対話的に特殊文字を使うか聞く
    let mut args_map: HashMap<&str, FluentValue> = HashMap::new();
    args_map.insert("specialChars", FluentValue::from(DEFAULT_SPECIAL_CHARS));
    let fargs: FluentArgs = args_map.iter().map(|(k, v)| (*k, v.clone())).collect();

    let default_message = get_translation(bundle, "default_special_chars_message", Some(&fargs))
        .unwrap_or_else(|_| "Default special chars: !?@#$%^&*()".to_string());
    ui.print(&default_message);

    let question = get_translation(bundle, "question_special_chars", None)
        .unwrap_or_else(|_| "Use special characters?".to_string());
    if ask_user_yes_no(ui, bundle, &question)? {
        // デフォルトかカスタマイズか再度聞く
        ask_special_chars(ui, bundle)
    } else {
        Ok("".to_string())
    }
}

/// デフォルトの特殊文字を使うかどうか再帰的に尋ねる
fn ask_special_chars(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
) -> Result<String> {
    let change_question = get_translation(bundle, "question_change_special_chars", None)
        .unwrap_or_else(|_| "Change the default special chars?".to_string());
    if ask_user_yes_no(ui, bundle, &change_question)? {
        let enter_message = get_translation(bundle, "question_enter_special_chars", None)
            .unwrap_or_else(|_| "Enter special chars:".to_string());
        let special_chars_input = ui.prompt(&enter_message)?;
        Ok(special_chars_input)
    } else {
        Ok(DEFAULT_SPECIAL_CHARS.to_string())
    }
}

/// yes/noをユーザーに聞く
fn ask_user_yes_no(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    message: &str,
) -> Result<bool> {
    let input = ui.prompt(message)?;
    match input.to_lowercase().as_str() {
        "y" | "yes" | "はい" | "ja" => Ok(true),
        "n" | "no" | "いいえ" | "nein" => Ok(false),
        _ => {
            let error_message = get_translation(bundle, "error_invalid_input", None)
                .unwrap_or_else(|_| "Invalid input. Please enter yes or no.".to_string());
            ui.print(&error_message);
            // 入力が不正なら再帰的にやり直し
            ask_user_yes_no(ui, bundle, message)
        }
    }
}

/// 強度十分なパスワードが得られるまで再帰的に試行する
fn try_generate_strong_password(
    all_chars: &str,
    length: usize,
    required_sets: &[String],
    attempts: usize,
) -> Option<String> {
    if attempts > MAX_GENERATION_ATTEMPTS {
        return None;
    }
    let password = assemble_random_password(all_chars, length, required_sets)?;
    if is_strong(&password) {
        Some(password)
    } else {
        try_generate_strong_password(all_chars, length, required_sets, attempts + 1)
    }
}

/// ランダムに文字を組み立て、必須文字を最低1文字ずつ含むパスワードを生成する
pub fn assemble_random_password(
    all_chars: &str,
    length: usize,
    required_sets: &[String],
) -> Option<String> {
    if all_chars.is_empty() {
        return None;
    }
    let mut rng = OsRng;

    //  必須文字を1文字ずつ確保
    let required_chars: Vec<char> = required_sets
        .iter()
        .filter_map(|set| {
            let set_chars: Vec<char> = set.chars().collect();
            set_chars.choose(&mut rng).copied()
        })
        .collect();

    // 必須文字数がlengthを超えたら組み立て不可能
    if required_chars.len() > length {
        return None;
    }

    // 残りをランダム埋め
    let all_chars_vec: Vec<char> = all_chars.chars().collect();
    let remaining_count = length - required_chars.len();
    let random_chars: Vec<char> = (0..remaining_count)
        .filter_map(|_| all_chars_vec.choose(&mut rng).copied())
        .collect();

    // 全部まとめてシャッフル
    let mut password_chars = [required_chars, random_chars].concat();
    password_chars.shuffle(&mut rng);

    Some(password_chars.iter().collect())
}

/// zxcvbn を利用して十分強いパスワードかどうか判定する
fn is_strong(password: &str) -> bool {
    let result = zxcvbn(password, &[]);
    matches!(result.score(), Score::Four)
}
