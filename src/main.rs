// Copyright 2023 Neuron Grid

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate rand;
extern crate zxcvbn;

use clap::{App, Arg};
use fluent::{FluentBundle, FluentResource};
use rand::{rngs::OsRng, seq::SliceRandom};
use std::{fs, io, str::FromStr};
use unic_langid::LanguageIdentifier;

// デフォルトの言語英語に定義します。
const DEFAULT_LANGUAGE: &str = "en-US";

// ユーザからの入力に基づいて強固なパスワードを生成し、表示します。
fn main() {
    // ユーザーの引数を解析して希望の言語を決定
    let matches = parse_args();
    // ユーザーの言語の設定に基づいて翻訳バンドルを初期化
    let bundle = initialize_bundle(&matches);
    // ユーザーとの対話のための翻訳されたプロンプトとメッセージを取得
    let generated_password_msg = get_translation(&bundle, "generated_password", None);
    // ユーザーの入力から希望のパスワードの長さを決定
    let length = get_password_length(&bundle);
    // ユーザーの選択に基づいて文字セットを組み立て
    let character_set = assemble_character_set(&bundle);
    // 決定された設定を使用してセキュアなパスワードを生成
    let password = produce_secure_password(&character_set, length);
    // ユーザーに生成されたパスワードを表示
    println!("{}\n{}", generated_password_msg.as_str(), password);
}

// ユーザーからの入力を取得し、トリムして返します。
fn get_input(prompt: &str, bundle: &FluentBundle<FluentResource>) -> String {
    println!("{}", prompt);
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        // 翻訳キーを新しく作り指定する。
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
fn get_password_length(bundle: &FluentBundle<FluentResource>) -> usize {
    loop {
        // get_inputにbundleを渡します
        let input = get_input("", bundle);
        match validate_password_length(&input) {
            Ok(n) => return n,
            Err(PasswordLengthError::InvalidNumber) => {
                // 翻訳キーのerror_invalid_numberを表示させる。
                println!("{}", get_translation(bundle, "error_invalid_number", None));
                continue;
            }
            // Err(PasswordLengthError::TooShort) => println!("推奨される長さは12文字以上です。"),
            Err(PasswordLengthError::TooShort) => {
                // 翻訳キーのerror_password_too_shortを表示させる。
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
fn assemble_character_set(bundle: &FluentBundle<FluentResource>) -> String {
    // 各質問とそれに対応する文字セットをペアとして保持します。
    let questions = [
        ("question_uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        ("question_lowercase", "abcdefghijklmnopqrstuvwxyz"),
        ("question_numbers", "0123456789"),
    ];
    // デフォルトで使用される特殊文字のセットを定義します。
    let default_special_characters = "!@#$%^&*()-_=+';:,.<>/?";
    // 選択に基づいて組み立てられる文字セットを一時的に格納します。
    let mut assembled_charset: String = String::new();
    for (question, chars) in questions.iter() {
        if ask_user(question, bundle) {
            assembled_charset += chars;
        }
    }
    println!(
        "{}",
        get_translation(bundle, "default_special_chars_message", None)
            .replace("{}", &default_special_characters)
    );

    // if ask_user("特殊文字を含めますか？", bundle) {
    if ask_user(
        &get_translation(bundle, "question_special_chars", None),
        bundle,
    ) {
        loop {
            // if ask_user("使用する特殊文字を変更しますか？", bundle) {
            if ask_user(
                &get_translation(bundle, "question_change_special_chars", None),
                bundle,
            ) {
                let special_chars_input =
                    // get_input("使用する特殊文字を入力してください (例: !@#|¥", bundle);
                    // 翻訳キーとしてquestion_enter_special_charsを指定する。
                    get_input(&get_translation(bundle, "question_enter_special_chars", None), bundle);
                assembled_charset += &special_chars_input;
                break;
            } else {
                assembled_charset += default_special_characters;
                break;
            }
        }
    }
    if assembled_charset.is_empty() {
        // 翻訳キーのerror_no_charset_selectedを表示させる。
        println!(
            "{}",
            get_translation(bundle, "error_no_charset_selected", None)
        );

        std::process::exit(1);
    }
    assembled_charset
}

// ユーザーに質問する
fn ask_user(message: &str, bundle: &FluentBundle<FluentResource>) -> bool {
    loop {
        let input = get_input(message, bundle);
        match input.to_lowercase().as_str() {
            "y" => return true,
            "n" => return false,
            "yes" => return true,
            "no" => return false,
            "はい" => return true,
            "いいえ" => return false,
            // 翻訳キーのerror_invalid_inputを表示させる。
            _ => println!("{}", get_translation(bundle, "error_invalid_input", None)),
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

// ユーザーが指定した言語に基づいて、Fluentファイルの名前を返します。
fn parse_args() -> clap::ArgMatches {
    App::new("passgen")
        .version("0.2 beta")
        .author("Neuron Grid <neuron-grid@neurongrid.net>")
        .about("Generate strong passwords.")
        .arg(
            Arg::with_name("language")
                .short('l')
                .long("language")
                .value_name("LANGUAGE")
                .help("Sets a specific language for messages (e.g., jp, en)")
                .takes_value(true),
        )
        .get_matches()
}

fn map_to_fluent_code(code: &str) -> LanguageIdentifier {
    match LanguageIdentifier::from_str(code) {
        Ok(lang_id) => lang_id,
        Err(_) => {
            // Display a default error message
            eprintln!("Failed to parse the provided language identifier.");
            std::process::exit(1);
        }
    }
}

fn initialize_bundle(matches: &clap::ArgMatches) -> FluentBundle<FluentResource> {
    let language = matches.value_of("language").unwrap_or(DEFAULT_LANGUAGE);
    match load_fluent_bundle(language) {
        Some(bundle) => bundle,
        None => {
            eprintln!("翻訳バンドルのロードに失敗しました。");
            std::process::exit(1);
        }
    }
}

// 指定された言語のFTLファイルを読み込み、Fluentバンドルを返します。
fn load_fluent_bundle(language: &str) -> Option<FluentBundle<FluentResource>> {
    let fluent_code = map_to_fluent_code(language);
    let ftl_filepath = format!("./translation/{}.ftl", fluent_code);
    // 指定された言語のFTLファイルが存在するかどうかを確認
    if !std::path::Path::new(&ftl_filepath).exists() {
        eprintln!("エラー: {}\nファイルが存在しません。", ftl_filepath);
        return None;
    }
    let ftl_string = match fs::read_to_string(&ftl_filepath) {
        Ok(content) => content,
        Err(_) => {
            eprintln!("FTLファイルを読み取れません。\nFTL file reading not possible.");
            std::process::exit(1);
        }
    };
    let ftl_resource = match FluentResource::try_new(ftl_string) {
        Ok(resource) => resource,
        Err(_) => {
            eprintln!("FTL文字列をパースできませんでした。\nFTL string could not be parsed.");
            std::process::exit(1);
        } // これはテスト用のコードです。
          // This is a test code.
          // Err(e) => {
          //     eprintln!("FTL文字列をパースできませんでした。\n{:?}", e);
          //     std::process::exit(1);
          // }
    };
    let langid = fluent_code;
    let mut bundle = FluentBundle::new(vec![&langid]);
    bundle
        .add_resource(ftl_resource)
        .expect("FTLリソースの追加に失敗しました。\nFTL resource could not be added.");
    Some(bundle)
}

fn get_translation(
    bundle: &FluentBundle<FluentResource>,
    key: &str,
    args: Option<&fluent::FluentArgs>,
) -> String {
    if let Some(message) = bundle.get_message(key) {
        let value = match &message.value {
            Some(v) => v,
            None => return "翻訳が見つかりません。\nTranslation not found.".to_string(),
        };
        let result = bundle.format_pattern(value, args, &mut vec![]);
        result.to_string()
    } else {
        "翻訳が見つかりません。\nTranslation not found.".to_string()
    }
}
