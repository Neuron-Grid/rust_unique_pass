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

use clap::Parser;
use fluent::{FluentBundle, FluentResource};
use rust_embed::RustEmbed;
use std::str::FromStr;
use unic_langid::subtags::Language;
use unic_langid::LanguageIdentifier;

// デフォルト言語を定義
const DEFAULT_LANGUAGE: &str = "eng";

#[derive(RustEmbed)]
#[folder = "./translation"]
#[include = "*.ftl"]
struct Translations;

fn get_embedded_resource(filename: &str) -> Option<String> {
    Translations::get(filename)
        .and_then(|data: rust_embed::EmbeddedFile| String::from_utf8(data.data.to_vec()).ok())
}

fn map_to_fluent_code(code: &str) -> LanguageIdentifier {
    match LanguageIdentifier::from_str(code) {
        Ok(lang_id) => lang_id,
        Err(error) => {
            // デフォルトのエラーメッセージを表示する
            eprintln!(
                "指定された言語識別子の解析に失敗しました。\
                \nFailed to parse the provided language identifier.\
                \n{:?}",
                error
            );
            std::process::exit(1);
        }
    }
}

// 言語設定を取得。デフォルト言語を使う場合はそれを使う。
pub fn initialize_bundle(args: &RupassArgs) -> FluentBundle<FluentResource> {
    let language: &str = match &args.language {
        Some(lang) => lang.as_str(),
        None => DEFAULT_LANGUAGE,
    };
    // 言語バンドルをロード
    match load_fluent_bundle(language) {
        Some(bundle) => bundle,
        None => {
            // 翻訳バンドルのロードに失敗しました。
            // Failed to load translation bundle.
            eprintln!(
                "対応言語を確認した上で再度実行して下さい。\
                \nPlease check the supported languages and execute again."
            );
            std::process::exit(1);
        }
    }
}

// 指定された言語のFTLファイルを読み込み、Fluentバンドルを返します。
fn load_fluent_bundle(language: &str) -> Option<FluentBundle<FluentResource>> {
    let fluent_code: LanguageIdentifier = map_to_fluent_code(language);
    let ftl_filename: String = format!("{}.ftl", fluent_code);
    // 埋め込まれたリソースを取得
    let ftl_string: String = match get_embedded_resource(&ftl_filename) {
        Some(content) => content,
        None => {
            eprintln!(
                "エラー: 埋め込まれたリソースが存在しません。\
                \nerror: Embedded resource does not exist.\
                \n{}",
                ftl_filename
            );
            std::process::exit(1);
        }
    };
    let ftl_resource: FluentResource = match FluentResource::try_new(ftl_string) {
        Ok(resource) => resource,
        Err(error) => {
            eprintln!(
                "FTL文字列をパースできませんでした。\
                \nFTL string could not be parsed.\
                \n{:?}",
                error
            );
            std::process::exit(1);
        }
    };
    let langid: LanguageIdentifier = fluent_code;
    let mut bundle = FluentBundle::new(vec![langid]);
    match bundle.add_resource(ftl_resource) {
        Ok(_) => (),
        Err(error) => {
            eprintln!(
                "FTLリソースの追加に失敗しました。\
                \nFailed to add FTL resource.\
                \n{:?}",
                error
            );
            std::process::exit(1);
        }
    };
    Some(bundle)
}

pub fn get_translation(
    bundle: &FluentBundle<FluentResource>,
    key: &str,
    args: Option<&fluent::FluentArgs>,
) -> String {
    if let Some(message) = bundle.get_message(key) {
        // 一時的な値を長寿命の変数に格納
        let temp_value = message.value();
        let value = match &temp_value {
            // ここで長寿命の変数を使用
            Some(v) => v,
            None => {
                return "翻訳が見つかりません。\
                    \nTranslation not found."
                    .to_string()
            }
        };
        let result = bundle.format_pattern(value, args, &mut vec![]);
        result.trim_matches('"').to_string();
        // デバック用コードを一時的に追加
        let mut errors: Vec<fluent::FluentError> = vec![];
        let result: std::borrow::Cow<'_, str> = bundle.format_pattern(value, args, &mut errors);
        if !errors.is_empty() {
            println!(
                "Fluent errors\
                \n{:?}",
                errors
            );
        }
        result.trim_matches('"').to_string()
        // デバック用コードを一時的に追加
    } else {
        "翻訳が見つかりません。\
        \nTranslation not found."
            .to_string()
    }
}

#[derive(Parser, Debug)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = "Neuron Grid",
    about = "Rust Unique Pass: Generate strong password.",
    name = "Rust Unique Pass",
    bin_name = "rupass",
)]
pub struct RupassArgs {
    // 設定言語を指定する
    #[clap(
        short = 'l',
        long = "language",
        value_name = "LANGUAGE",
        help = "Specifies the language for user prompts and messages.\
            \nSpecify the language code as defined by Iso639-3.\
            \nSupported languages: Japanese, English, and German.\
            \nDefault language: English"
    )]
    language: Option<Language>,
    // 大文字を含めるかどうかを尋ねる
    /*#[clap(
        short = 'u',
        long = "uppercase",
        help = "Include uppercase letters in the password."
    )]
    uppercase: bool,
    // 小文字を含めるかどうかを尋ねる
    #[clap(
        short = 'c',
        long = "lowercase",
        help = "Include lowercase letters in the password."
    )]
    lowercase: bool,
    // 数字を含めるかどうかを尋ねる
    #[clap(
        short = 'n',
        long = "numbers",
        help = "Include numbers in the password."
    )]
    numbers: bool,
    // 記号(特殊記号)を含めるかどうかを尋ねる
    #[clap(
        short = 's',
        long = "symbols",
        help = "Include symbols in the password."
    )]
    symbols: bool,
    */
}

pub fn parse_args() -> RupassArgs {
    let matches = RupassArgs::parse();
    matches
}
