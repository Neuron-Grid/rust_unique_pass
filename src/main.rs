// Copyright 2023 Neuron Grid

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate rand;
extern crate zxcvbn;

use rand::{rngs::OsRng, seq::SliceRandom};
use std::io;

// ユーザからの入力に基づいて強固なパスワードを生成し、表示します。
fn main() {
    // ユーザーから指定されたパスワードの長さを格納します。
    let length = get_password_length();
    // ユーザーの選択に基づいて組み立てられた文字セットを格納します。
    let character_set = assemble_character_set();
    // 生成された強力なパスワードを格納します。
    let password = produce_secure_password(&character_set, length);
    println!("生成されたパスワード: {}", password);
}

// ユーザーからの入力を取得し、トリムして返します。
fn get_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);
    io::stdin().read_line(&mut input).expect("読み込みエラー");
    input.trim().to_string()
}

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

// パスワードの長さを取得します。
fn get_password_length() -> usize {
    println!("パスワードの長さを入力してください\n12文字以上を推奨します。");
    loop {
        let input = get_input("");
        match validate_password_length(&input) {
            Ok(n) => return n,
            Err(PasswordLengthError::InvalidNumber) => {
                println!("有効な数値を入力してください。");
                continue;
            }
            Err(PasswordLengthError::TooShort) => println!("推奨される長さは12文字以上です。"),
        }
    }
}

// ユーザーの選択に基づいて文字セットを組み立てて返します。
fn assemble_character_set() -> String {
    // 各質問とそれに対応する文字セットをペアとして保持します。
    let questions = [
        ("大文字を含めますか？ (y/n)", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("小文字を含めますか？ (y/n)", "abcdefghijklmnopqrstuvwxyz"),
        ("数字を含めますか？ (y/n)", "0123456789"),
    ];
    // デフォルトで使用される特殊文字のセットを定義します。
    let default_special_chars = "!@#$%^&*()-_=+';:,.<>/?";
    // 選択に基づいて組み立てられる文字セットを一時的に格納します。
    let mut assembled_charset: String = String::new();
    for (question, chars) in questions.iter() {
        if ask_user(question) {
            assembled_charset += chars;
        }
    }
    println!(
        "デフォルトで使用される特殊文字は{}です。",
        default_special_chars
    );
    if ask_user("特殊文字を含めますか？ (y/n)") {
        loop {
            if ask_user("使用する特殊文字を変更しますか？ (y/n)") {
                let special_chars_input =
                    get_input("使用する特殊文字を入力してください (例: !@#|¥");
                assembled_charset += &special_chars_input;
                break;
            } else {
                assembled_charset += default_special_chars;
                break;
            }
        }
    }
    if assembled_charset.is_empty() {
        println!("エラー: 有効な文字セットが選択されていません。\n少なくとも1つの質問に「y」と回答して、文字セットを選択してください。再度実行し、指示に従ってください。");
        std::process::exit(1);
    }
    assembled_charset
}

// ユーザーに質問する
fn ask_user(message: &str) -> bool {
    loop {
        let input = get_input(message);
        match input.to_lowercase().as_str() {
            "y" => return true,
            "n" => return false,
            _ => println!("無効な入力です。\nyまたはnを入力してください。"),
        }
    }
}

// 指定された文字セットと長さに基づいて、強力なパスワードを生成します
fn produce_secure_password(chars: &str, length: usize) -> String {
    let mut password;
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
    let mut rng = OsRng;
    // 文字列を char のベクタに変換します。
    let chars_vec: Vec<char> = chars.chars().collect();
    (0..length)
        .map(|_| *chars_vec.choose(&mut rng).unwrap())
        .collect()
}

// パスワードの強度をチェックする
fn is_strong(password: &str) -> bool {
    // zxcvbnライブラリを使用して、パスワードの強度を評価します。
    let result = zxcvbn::zxcvbn(password, &[]).unwrap();
    result.score() > 3
}
