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

mod i18n;
use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use i18n::{get_translation, initialize_bundle, parse_args, RupassArgs};
use rand::{rngs::OsRng, seq::SliceRandom};
use std::collections::HashMap;
use std::io;

// ユーザからの入力に基づいて強固なパスワードを生成し、表示します。
fn main() {
    // ユーザーの引数を解析して希望の言語を決定
    let matches: RupassArgs = parse_args();
    // ユーザーの言語の設定に基づいて翻訳バンドルを初期化
    let bundle = initialize_bundle(&matches);
    // ユーザーとの対話のための翻訳されたプロンプトとメッセージを取得
    let generated_password_msg: String = get_translation(&bundle, "generated_password", None);
    // ユーザーの入力から希望のパスワードの長さを決定
    let length: usize = get_password_length(&bundle);
    // ユーザーの選択に基づいて文字セットを組み立て
    let character_set: String = assemble_character_set(&bundle);
    // 決定された設定を使用してセキュアなパスワードを生成
    let password: String = produce_secure_password(&character_set, length);
    // ユーザーに生成されたパスワードを表示
    println!("{}\n{}", generated_password_msg.as_str(), password);
}

// ユーザーからの入力を取得し、トリムして返します。
fn get_input(prompt: &str, bundle: &FluentBundle<FluentResource>) -> String {
    println!("{}", prompt);
    let mut input: String = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect(&get_translation(bundle, "error_user_input", None));
    input.trim().to_string()
}

// パスワードの長さに関するエラータイプを定義します。
enum PasswordLengthError {
    InvalidNumber,
    TooShort,
}

// パスワードの長さを検証する
fn validate_password_length(input: &str) -> Result<usize, PasswordLengthError> {
    // 文字列をisize型に変換して解析します。isize型を使用して負の数も考慮します。
    match input.parse::<isize>() {
        Ok(n) if n <= 0 => Err(PasswordLengthError::InvalidNumber),
        Ok(n) if n as usize >= 8 => Ok(n as usize),
        Ok(_) => Err(PasswordLengthError::TooShort),
        Err(_) => Err(PasswordLengthError::InvalidNumber),
    }
}

// ユーザーにパスワードの長さを聞き、その長さを返す。
pub fn get_password_length(bundle: &FluentBundle<FluentResource>) -> usize {
    loop {
        // プロンプトとして表示するメッセージを取得
        let prompt: String = get_translation(bundle, "question_password_length", None);
        // get_inputに正しいプロンプトを渡します
        let input: String = get_input(&prompt, bundle);
        match validate_password_length(&input) {
            Ok(definitely) => return definitely,
            Err(PasswordLengthError::InvalidNumber) => {
                println!("{}", get_translation(bundle, "error_invalid_number", None));
                continue;
            }
            Err(PasswordLengthError::TooShort) => {
                println!(
                    "{}",
                    get_translation(bundle, "error_password_too_short", None)
                );
                continue;
            }
        }
    }
}

// ユーザーの選択に基づいて文字セットを組み立てて返します。
pub fn assemble_character_set(bundle: &FluentBundle<FluentResource>) -> String {
    // 各質問とそれに対応する文字セットをペアとして保持します。
    let questions: [(String, &str); 3] = [
        (
            get_translation(&bundle, "question_uppercase", None),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ),
        (
            get_translation(&bundle, "question_lowercase", None),
            "abcdefghijklmnopqrstuvwxyz",
        ),
        (
            get_translation(&bundle, "question_numbers", None),
            "0123456789",
        ),
    ];
    let mut assembled_charset: String = String::new();
    for (question, chars) in questions.iter() {
        if ask_user(question, bundle) {
            assembled_charset += chars;
        }
    }
    let special_characters_set: String = handle_special_characters(bundle);
    if !special_characters_set.is_empty() {
        assembled_charset += &special_characters_set;
    }
    if assembled_charset.is_empty() {
        println!(
            "{}",
            get_translation(bundle, "error_no_charset_selected", None)
        );
        std::process::exit(1);
    }
    assembled_charset
}

fn handle_special_characters(bundle: &FluentBundle<FluentResource>) -> String {
    // デフォルトで使用される特殊文字のセットの定義
    let default_special_characters: &str = "!?@#$%^&*()-_=+';:,.<>/";
    // 選択に基づいて組み立てられる文字セットを一時的に格納する。
    let mut args_map: HashMap<&str, FluentValue> = HashMap::new();
    args_map.insert(
        "specialChars",
        FluentValue::from(default_special_characters as &str),
    );
    // デバッグ用コードを一時的に追加
    // デバッグ出力: args_mapの内容を表示
    println!("Debug: args_map contents: {:?}", args_map);
    let args: FluentArgs = args_map.clone().into_iter().collect();
    // デバッグ出力: argsの内容を表示
    println!("Debug: args contents: {:?}", args);
    // デバッグ用コードを一時的に追加
    let args: FluentArgs = args_map.iter().map(|(k, v)| (*k, v.clone())).collect();
    println!(
        "{}",
        &get_translation(bundle, "default_special_chars_message", Some(&args)),
    );
    if ask_user(
        &get_translation(bundle, "question_special_chars", None),
        bundle,
    ) {
        loop {
            if ask_user(
                &get_translation(bundle, "question_change_special_chars", None),
                bundle,
            ) {
                let special_chars_input: String = get_input(
                    &get_translation(bundle, "question_enter_special_chars", None),
                    bundle,
                );
                return special_chars_input;
            } else {
                return default_special_characters.to_string();
            }
        }
    }
    "".to_string()
}

// ユーザーに質問する
fn ask_user(message: &str, bundle: &FluentBundle<FluentResource>) -> bool {
    loop {
        let input: String = get_input(message, bundle);
        match input.to_lowercase().as_str() {
            // english
            "y" => return true,
            "n" => return false,
            "yes" => return true,
            "no" => return false,
            // japanese
            "はい" => return true,
            "いいえ" => return false,
            // german
            "ja" => return true,
            "nein" => return false,
            _ => println!("{}", get_translation(bundle, "error_invalid_input", None)),
        }
    }
}

// 指定された文字セットと長さに基づいて、強力なパスワードを生成します
pub fn produce_secure_password(chars: &str, length: usize) -> String {
    let mut password: String;
    loop {
        password = assemble_random_password(chars, length);
        if is_strong(&password) {
            break;
        }
    }
    password
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
    let result: zxcvbn::Entropy = zxcvbn::zxcvbn(password, &[]).unwrap();
    result.score() > 3
}
