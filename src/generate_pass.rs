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
const MAX_GENERATION_ATTEMPTS: usize = 10000;

pub fn generate_password_flow(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    let generated_password_msg = get_translation(bundle, "generated_password", None)?;
    let length = get_password_length(ui, bundle, args)?;
    let charset = assemble_character_set(ui, bundle, args)?;
    let password = produce_secure_password(&charset, length)?;
    ui.print(&format!("{}\n{}\n", generated_password_msg, &password));
    Ok(password)
}

fn get_password_length(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<usize> {
    // もし引数で長さが指定されていたら、そのまま使う
    if let Some(l) = args.password_length {
        validate_password_length(l)?;
        return Ok(l);
    }

    loop {
        let prompt = match get_translation(bundle, "question_password_length", None) {
            Ok(p) => p,
            Err(_) => "Enter password length:".to_string(),
        };
        let input = ui.prompt(&prompt)?;
        let parsed = input.parse::<usize>();
        match parsed {
            Ok(n) => {
                if let Err(e) = validate_password_length(n) {
                    print_length_error(ui, bundle, &e)?;
                    continue;
                }
                return Ok(n);
            }
            Err(_) => {
                let msg = get_translation(bundle, "error_non_numeric_input", None)
                    .unwrap_or_else(|_| "Input is not numeric.".to_string());
                ui.print(&msg);
            }
        }
    }
}

pub fn validate_password_length(length: usize) -> Result<()> {
    if length < 15 {
        return Err(GenerationError::InvalidLength);
    }
    Ok(())
}

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

fn assemble_character_set(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    let mut assembled_charset = String::new();

    // 引数でtrueな場合は先に追加
    if args.numbers {
        assembled_charset += "0123456789";
    }
    if args.uppercase {
        assembled_charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
    if args.lowercase {
        assembled_charset += "abcdefghijklmnopqrstuvwxyz";
    }

    let questions = [
        (
            "question_uppercase",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            args.uppercase,
        ),
        (
            "question_lowercase",
            "abcdefghijklmnopqrstuvwxyz",
            args.lowercase,
        ),
        ("question_numbers", "0123456789", args.numbers),
    ];

    for (key, chars, flag) in &questions {
        if *flag {
            continue;
        }
        let question = get_translation(bundle, key, None)?;
        if ask_user_yes_no(ui, bundle, &question)? {
            assembled_charset += chars;
        }
    }

    // 特殊文字
    let special_characters_set = handle_special_characters(ui, bundle, args)?;
    if !special_characters_set.is_empty() {
        assembled_charset += &special_characters_set;
    }

    if assembled_charset.is_empty() {
        return Err(GenerationError::InvalidInput);
    }

    Ok(assembled_charset)
}

fn handle_special_characters(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    args: &RupassArgs,
) -> Result<String> {
    if args.symbols {
        return Ok(DEFAULT_SPECIAL_CHARS.to_string());
    }

    let mut args_map: HashMap<&str, FluentValue> = HashMap::new();
    args_map.insert("specialChars", FluentValue::from(DEFAULT_SPECIAL_CHARS));
    let fargs: FluentArgs = args_map.iter().map(|(k, v)| (*k, v.clone())).collect();

    let default_message = get_translation(bundle, "default_special_chars_message", Some(&fargs))
        .unwrap_or_else(|_| "Default special chars: !?@#$%^&*()".to_string());
    ui.print(&default_message);

    let question = get_translation(bundle, "question_special_chars", None)
        .unwrap_or_else(|_| "Use special characters? (y/n)".to_string());
    if ask_user_yes_no(ui, bundle, &question)? {
        loop {
            let change_question = get_translation(bundle, "question_change_special_chars", None)
                .unwrap_or_else(|_| "Change the default special chars? (y/n)".to_string());
            if ask_user_yes_no(ui, bundle, &change_question)? {
                let enter_message = get_translation(bundle, "question_enter_special_chars", None)
                    .unwrap_or_else(|_| "Enter special chars:".to_string());
                let special_chars_input = ui.prompt(&enter_message)?;
                return Ok(special_chars_input);
            } else {
                return Ok(DEFAULT_SPECIAL_CHARS.to_string());
            }
        }
    }
    Ok("".to_string())
}

fn ask_user_yes_no(
    ui: &mut dyn UserInterface,
    bundle: &FluentBundle<FluentResource>,
    message: &str,
) -> Result<bool> {
    loop {
        let input = ui.prompt(message)?;
        let lower_input = input.to_lowercase();
        match lower_input.as_str() {
            "y" | "yes" | "はい" | "ja" => return Ok(true),
            "n" | "no" | "いいえ" | "nein" => return Ok(false),
            _ => {
                let error_message = get_translation(bundle, "error_invalid_input", None)
                    .unwrap_or_else(|_| "Invalid input. Please enter yes or no.".to_string());
                ui.print(&error_message);
            }
        }
    }
}

pub fn produce_secure_password(chars: &str, length: usize) -> Result<String> {
    validate_password_length(length)?;
    let mut attempts = 0;
    loop {
        if attempts > MAX_GENERATION_ATTEMPTS {
            return Err(GenerationError::GenerationFailed);
        }
        let password = assemble_random_password(chars, length)?;
        if is_strong(&password) {
            return Ok(password);
        }
        attempts += 1;
    }
}

pub fn assemble_random_password(chars: &str, length: usize) -> Result<String> {
    if chars.is_empty() {
        return Err(GenerationError::GenerationFailed);
    }
    let mut rng: OsRng = OsRng;
    let chars_vec: Vec<char> = chars.chars().collect();
    let mut password = String::with_capacity(length);
    for _ in 0..length {
        let c = chars_vec
            .choose(&mut rng)
            .ok_or(GenerationError::GenerationFailed)?;
        password.push(*c);
    }
    Ok(password)
}

fn is_strong(password: &str) -> bool {
    let result = zxcvbn(password, &[]);
    matches!(result.score(), Score::Four)
}
