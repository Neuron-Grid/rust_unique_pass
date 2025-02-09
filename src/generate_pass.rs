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
use fluent::{FluentArgs, FluentBundle, FluentResource};
use rand::prelude::SliceRandom;
use rand::seq::IndexedRandom as _;
use zxcvbn::{zxcvbn, Score};

const DEFAULT_SPECIAL_CHARS: &str = "!?@#$%^&*()";
const MAX_GENERATION_ATTEMPTS: usize = 100000;

/// 小さなヘルパー関数:
/// 翻訳キーからメッセージを取得し、失敗時はフォールバックメッセージを返す
fn fallback_translation(
    bundle: &FluentBundle<FluentResource>,
    key: &str,
    fallback: &str,
    args: Option<&FluentArgs>,
) -> String {
    get_translation(bundle, key, args).unwrap_or_else(|_| fallback.to_string())
}

/// ユーザーの入力を繰り返し受け取り、パースに成功したら返すジェネリック関数
fn prompt_loop<T, E, F>(
    ui: &mut dyn UserInterface,
    prompt: &str,
    parse_fn: F,
    error_handler: impl Fn(&mut dyn UserInterface, &E),
) -> T
where
    F: Fn(&str) -> std::result::Result<T, E>,
{
    loop {
        let input = match ui.prompt(prompt) {
            Ok(s) => s,
            Err(_) => {
                // 入力を取得できなかった場合の処理を挟めるように状況に応じて終了やリトライを選択できる
                ui.print("Couldn't read input. Retrying...");
                continue;
            }
        };

        match parse_fn(&input) {
            Ok(value) => return value,
            Err(e) => {
                error_handler(ui, &e);
            }
        }
    }
}

/// メインのパスワード生成フロー
/// メインのパスワード生成フロー
pub fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    let generated_password_msg =
        fallback_translation(bundle, "generated_password", "Generated password:", None);
    // パスワード長を取得
    let length = get_password_length(ui, bundle, args)?;

    // assemble_character_setで全体の文字セット、必須文字セットを取得
    // もしNoCharacterSetエラーになったら翻訳メッセージを表示
    let (all_chars, required_sets) = match assemble_character_set(ui, bundle, args) {
        Ok((chars, sets)) => (chars, sets),
        Err(GenerationError::NoCharacterSet) => {
            let no_charset_msg = fallback_translation(
                bundle,
                "error_no_charset_selected",
                "No valid character set was selected.",
                None,
            );
            ui.print(&no_charset_msg);
            return Err(GenerationError::NoCharacterSet);
        }
        Err(e) => return Err(e),
    };

    // パスワードを生成する
    // 生成に失敗した場合は翻訳メッセージを表示
    let password = match produce_secure_password(&all_chars, length, &required_sets) {
        Ok(pwd) => pwd,
        Err(GenerationError::GenerationFailed) => {
            let gen_error_msg = fallback_translation(
                bundle,
                "error_generation",
                "Error generating password.",
                None,
            );
            ui.print(&gen_error_msg);
            return Err(GenerationError::GenerationFailed);
        }
        Err(e) => return Err(e),
    };
    ui.print(&format!("{}\n{}\n", generated_password_msg, &password));
    Ok(password)
}

/// パスワード長を取得する
/// CLI引数にあればそれを優先
/// なければ対話的に入力を受け付ける
pub fn get_password_length(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<usize> {
    if let Some(l) = args.password_length {
        validate_password_length(l)?;
        return Ok(l);
    }

    // ユーザーにパスワード長を聞くメッセージ
    let prompt_message = fallback_translation(
        bundle,
        "question_password_length",
        "Enter password length:",
        None,
    );

    // ループで数値入力を受け付ける
    let length = prompt_loop(
        ui,
        &prompt_message,
        |input: &str| -> std::result::Result<usize, GenerationError> {
            let parsed = input
                .parse::<usize>()
                .map_err(|_| GenerationError::InvalidLength)?;
            validate_password_length(parsed)?;
            Ok(parsed)
        },
        |ui, err| {
            // エラーの種類を見てユーザーにメッセージを出す
            print_length_error(ui, bundle, err).ok();
        },
    );

    Ok(length)
}

/// パスワード長が15文字未満の場合はエラー
pub fn validate_password_length(length: usize) -> Result<()> {
    if length < 15 {
        return Err(GenerationError::InvalidLength);
    }
    Ok(())
}

/// パスワード長エラーを表示する
fn print_length_error(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    err: &GenerationError,
) -> Result<()> {
    let msg = match err {
        GenerationError::InvalidLength => fallback_translation(
            bundle,
            "error_password_too_short",
            "Password is too short.",
            None,
        ),
        _ => "Invalid length.".to_string(),
    };
    ui.print(&msg);
    Ok(())
}

/// 指定した文字集合で、強度が十分なパスワードを生成する
pub fn produce_secure_password(
    all_chars: &str,
    length: usize,
    required_sets: &[String],
) -> Result<String> {
    validate_password_length(length)?;

    for _attempt in 0..MAX_GENERATION_ATTEMPTS {
        if let Some(password) = assemble_random_password(all_chars, length, required_sets) {
            if is_strong(&password) {
                return Ok(password);
            }
        }
    }

    Err(GenerationError::GenerationFailed)
}

/// 全体の文字セットと必須文字セットを返す
fn assemble_character_set(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<(String, Vec<String>)> {
    let (charset, required) = assemble_flag_based_charset(args);

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
        let msg = fallback_translation(
            bundle,
            "error_no_charset_selected",
            "No valid character set was selected.",
            None,
        );
        ui.print(&msg);
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

/// フラグがfalseの文字種についてのみ、ユーザーに確認して追加する
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

    let (mut assembled_charset, mut required_sets) = (charset, required);

    for (key, chars, already_added) in questions {
        if already_added {
            continue;
        }
        let question = fallback_translation(bundle, key, "", None);
        if ask_user_yes_no(ui, bundle, &question)? {
            assembled_charset.push_str(chars);
            required_sets.push(chars.to_string());
        }
    }

    Ok((assembled_charset, required_sets))
}

/// yes/noをユーザーに聞く
fn ask_user_yes_no(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    message: &str,
) -> Result<bool> {
    if message.is_empty() {
        // 空文字列のときはスキップしてfalse扱いにする
        return Ok(false);
    }

    let invalid_input_msg = fallback_translation(
        bundle,
        "error_invalid_input",
        "Invalid input. Please enter yes or no.",
        None,
    );

    // ループで入力を確認
    let result = prompt_loop(
        ui,
        message,
        |input: &str| -> std::result::Result<bool, ()> {
            match input.to_lowercase().as_str() {
                "y" | "yes" | "はい" | "ja" => Ok(true),
                "n" | "no" | "いいえ" | "nein" => Ok(false),
                _ => Err(()),
            }
        },
        |ui, _| {
            ui.print(&invalid_input_msg);
        },
    );

    Ok(result)
}

/// 特殊文字の対話処理
fn handle_special_characters(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    // フラグが立っていればデフォルトの特殊文字を返す
    if args.symbols {
        return Ok(DEFAULT_SPECIAL_CHARS.to_string());
    }

    let default_msg = fallback_translation(
        bundle,
        "default_special_chars_message",
        "Default special chars: !?@#$%^&*()",
        None,
    );
    ui.print(&default_msg);

    let question = fallback_translation(
        bundle,
        "question_special_chars",
        "Use special characters?",
        None,
    );

    if ask_user_yes_no(ui, bundle, &question)? {
        // デフォルトを使うかカスタマイズするか
        ask_special_chars(ui, bundle)
    } else {
        Ok("".to_string())
    }
}

/// デフォルトの特殊文字を使うかどうかループで尋ねる
fn ask_special_chars(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
) -> Result<String> {
    let change_question = fallback_translation(
        bundle,
        "question_change_special_chars",
        "Change the default special chars?",
        None,
    );

    if ask_user_yes_no(ui, bundle, &change_question)? {
        let enter_message = fallback_translation(
            bundle,
            "question_enter_special_chars",
            "Enter special chars:",
            None,
        );
        let input = ui.prompt(&enter_message)?;
        Ok(input)
    } else {
        Ok(DEFAULT_SPECIAL_CHARS.to_string())
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
    let mut rng = rand::rng();

    // 必須文字セットから1文字ずつピックアップ
    let required_chars: Vec<char> = required_sets
        .iter()
        .filter_map(|set| {
            let set_chars: Vec<char> = set.chars().collect();
            set_chars.choose(&mut rng).copied()
        })
        .collect();

    if required_chars.len() > length {
        return None;
    }

    let all_chars_vec: Vec<char> = all_chars.chars().collect();
    let remaining_count = length - required_chars.len();

    let random_chars: Vec<char> = (0..remaining_count)
        .filter_map(|_| all_chars_vec.choose(&mut rng).copied())
        .collect();

    let mut password_chars = [required_chars, random_chars].concat();
    password_chars.shuffle(&mut rng);

    Some(password_chars.iter().collect())
}

/// zxcvbn を利用して十分強いパスワードかどうか判定する
fn is_strong(password: &str) -> bool {
    let result = zxcvbn(password, &[]);
    matches!(result.score(), Score::Four)
}
