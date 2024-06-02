/* Copyright 2023 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use crate::i18n::{get_translation, RupassArgs};
use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use rand::{prelude::SliceRandom, rngs::OsRng};
use std::{
    collections::HashMap,
    io::{self, Write},
};
use zxcvbn::{zxcvbn, Score};

// ユーザーからの入力を取得し、トリムした結果を Result 型で返します。
fn get_input(prompt: &str) -> Result<String, io::Error> {
    println!("{}", prompt);
    // プロンプトを確実に表示するためにバッファをフラッシュします。
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// パスワードの長さに関するエラータイプを定義します。
#[derive(Debug)]
pub enum PasswordLengthError {
    NonNumericInput,
    NegativeNumber,
    TooShort,
}

pub enum TranslationError {
    GenerationError(String),
    Other(String),
}

impl From<String> for TranslationError {
    fn from(error: String) -> Self {
        TranslationError::Other(error)
    }
}

pub fn handle_password_generation(
    chars: &str,
    length: usize,
    generated_password_msg: &str,
    bundle: &FluentBundle<FluentResource>,
) -> Result<(), TranslationError> {
    match produce_secure_password(chars, length) {
        Ok(password) => {
            println!("{}\n{}\n", generated_password_msg, password);
            Ok(())
        }
        Err(_) => {
            let error_message = get_translation(bundle, "error_generation", None)
                .map_err(|e| TranslationError::GenerationError(e))?;
            println!("{}", error_message);
            Err(TranslationError::GenerationError(error_message))
        }
    }
}

// パスワードの長さを検証する
fn validate_password_length(input: &str) -> Result<usize, PasswordLengthError> {
    match input.parse::<isize>() {
        Ok(n) if n < 0 => Err(PasswordLengthError::NegativeNumber),
        Ok(n) if n as usize >= 8 => Ok(n as usize),
        Ok(_) => Err(PasswordLengthError::TooShort),
        Err(_) => Err(PasswordLengthError::NonNumericInput),
    }
}

// ユーザーにパスワードの長さを聞き、その長さを返す。
pub fn get_password_length(bundle: &FluentBundle<FluentResource>) -> usize {
    loop {
        // プロンプトとして表示するメッセージを取得
        let prompt_result = get_translation(bundle, "question_password_length", None);
        let prompt = match prompt_result {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error fetching translation: {}", e);
                continue;
            }
        };

        let input_result = get_input(&prompt);
        let input = match input_result {
            Ok(value) => value,
            Err(_) => {
                let error_msg = get_translation(bundle, "error_reading_input", None)
                    .unwrap_or_else(|_| "Failed to read input.".to_string());
                println!("{}", error_msg);
                continue;
            }
        };

        // 入力値を検証
        match validate_password_length(&input) {
            Ok(definitely) => return definitely,
            Err(PasswordLengthError::NonNumericInput) => {
                let error_msg = get_translation(bundle, "error_non_numeric_input", None)
                    .unwrap_or_else(|_| "Input is not numeric.".to_string());
                println!("{}", error_msg);
            }
            Err(PasswordLengthError::NegativeNumber) => {
                let error_msg = get_translation(bundle, "error_negative_number", None)
                    .unwrap_or_else(|_| "Number cannot be negative.".to_string());
                println!("{}", error_msg);
            }
            Err(PasswordLengthError::TooShort) => {
                let error_msg = get_translation(bundle, "error_password_too_short", None)
                    .unwrap_or_else(|_| "Password is too short.".to_string());
                println!("{}", error_msg);
            }
        }
    }
}

pub fn assemble_character_set(
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String, String> {
    let mut assembled_charset = String::new();

    if args.numbers {
        assembled_charset += "0123456789";
    }
    if args.uppercase {
        assembled_charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
    if args.lowercase {
        assembled_charset += "abcdefghijklmnopqrstuvwxyz";
    }

    let questions: [(Result<String, String>, &str, bool); 3] = [
        (
            get_translation(bundle, "question_uppercase", None),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            args.uppercase,
        ),
        (
            get_translation(bundle, "question_lowercase", None),
            "abcdefghijklmnopqrstuvwxyz",
            args.lowercase,
        ),
        (
            get_translation(bundle, "question_numbers", None),
            "0123456789",
            args.numbers,
        ),
    ];

    for (question_result, chars, flag) in questions.iter() {
        if *flag {
            continue;
        }
        let question = match question_result {
            Ok(q) => q,
            Err(e) => return Err(e.clone()),
        };
        if ask_user(question, bundle) {
            assembled_charset += chars;
        }
    }

    let special_characters_set = handle_special_characters(bundle, args)?;
    if !special_characters_set.is_empty() {
        assembled_charset += &special_characters_set;
    }

    if assembled_charset.is_empty() {
        let error_message = get_translation(bundle, "error_no_charset_selected", None)
            .unwrap_or_else(|_| "No character set selected.".to_string());
        return Err(error_message);
    }

    Ok(assembled_charset)
}

fn handle_special_characters(
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String, String> {
    let default_special_characters: &str = "!?@#$%^&*()";
    if args.symbols {
        return Ok(default_special_characters.to_string());
    }
    let mut args_map: HashMap<&str, FluentValue> = HashMap::new();
    args_map.insert(
        "specialChars",
        FluentValue::from(default_special_characters),
    );
    let args: FluentArgs = args_map.iter().map(|(k, v)| (*k, v.clone())).collect();
    let default_message = get_translation(bundle, "default_special_chars_message", Some(&args))?;
    println!("{}", default_message);
    let question = get_translation(bundle, "question_special_chars", None)?;
    if ask_user(&question, bundle) {
        loop {
            let change_question = get_translation(bundle, "question_change_special_chars", None)?;
            if ask_user(&change_question, bundle) {
                match get_input(&get_translation(
                    bundle,
                    "question_enter_special_chars",
                    None,
                )?) {
                    Ok(special_chars_input) => return Ok(special_chars_input),
                    Err(_) => {
                        let error_input_message =
                            get_translation(bundle, "error_reading_input", None)
                                .unwrap_or_else(|_| "Error reading input.".to_string());
                        println!("{}", error_input_message);
                        continue;
                    }
                }
            } else {
                return Ok(default_special_characters.to_string());
            }
        }
    }
    Ok("".to_string())
}

fn validate_input(input: &str) -> Option<bool> {
    match input.to_lowercase().as_str() {
        // english
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        // japanese
        "はい" => Some(true),
        "いいえ" => Some(false),
        // german
        "ja" => Some(true),
        "nein" => Some(false),
        _ => None,
    }
}

// ユーザーに質問する
fn ask_user(message: &str, bundle: &FluentBundle<FluentResource>) -> bool {
    loop {
        match get_input(message) {
            Ok(input) => {
                if let Some(result) = validate_input(&input) {
                    return result;
                } else {
                    let error_message = get_translation(bundle, "error_invalid_input", None)
                        .unwrap_or_else(|_| {
                            "Invalid input provided. Please try again.".to_string()
                        });
                    println!("{}", error_message);
                }
            }
            Err(_) => {
                let error_message = get_translation(bundle, "error_reading_input", None)
                    .unwrap_or_else(|_| "Error reading input. Please try again.".to_string());
                println!("{}", error_message);
            }
        }
    }
}

// 指定された文字セットと長さに基づいて、強力なパスワードを生成します
pub fn produce_secure_password(chars: &str, length: usize) -> Result<String, PasswordLengthError> {
    if length < 8 {
        return Err(PasswordLengthError::TooShort);
    }

    let mut password: String;
    loop {
        password = assemble_random_password(chars, length);
        if is_strong(&password) {
            break;
        }
    }
    Ok(password)
}

// 指定された文字セットと長さに基づいてランダムなパスワードを組み立てます。
fn assemble_random_password(chars: &str, length: usize) -> String {
    // セキュアな乱数生成のための乱数生成器を初期化します。
    let mut rng: OsRng = OsRng;
    // 文字列をcharのベクタに変換します。
    let chars_vec: Vec<char> = chars.chars().collect();
    (0..length)
        .map(|_| *chars_vec.choose(&mut rng).unwrap())
        .collect()
}

// zxcvbnライブラリを使用して、パスワードの強度を評価します。
fn is_strong(password: &str) -> bool {
    let result = zxcvbn(password, &[]);
    match result.score() {
        Score::Zero | Score::One | Score::Two | Score::Three => false,
        Score::Four => true,
        _ => todo!(),
    }
}
