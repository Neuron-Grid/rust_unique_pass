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
use fluent::{FluentArgs, FluentBundle, FluentResource};
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

pub fn get_embedded_resource(filename: &str) -> Option<String> {
    Translations::get(filename)
        .and_then(|data: rust_embed::EmbeddedFile| String::from_utf8(data.data.to_vec()).ok())
}

fn map_to_fluent_code(code: &str) -> LanguageIdentifier {
    match LanguageIdentifier::from_str(code) {
        Ok(lang_id) => lang_id,
        Err(_) => {
            eprintln!("Failed to parse the provided language identifier");
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
    match load_fluent_bundle(language) {
        Some(bundle) => bundle,
        None => {
            eprintln!("Failed to parse the provided language identifier");
            std::process::exit(1);
        }
    }
}

// 指定された言語のFTLファイルを読み込み、Fluentバンドルを返します。
fn load_fluent_bundle(language: &str) -> Option<FluentBundle<FluentResource>> {
    let fluent_code = map_to_fluent_code(language);
    let ftl_filename = format!("{}.ftl", fluent_code);
    let ftl_string = match get_embedded_resource(&ftl_filename) {
        Some(content) => content,
        None => {
            eprintln!("The selected language is not supported.");
            std::process::exit(1);
        }
    };

    let ftl_resource = match FluentResource::try_new(ftl_string) {
        Ok(resource) => resource,
        Err(_) => {
            eprintln!("FTL string could not be parsed.");
            std::process::exit(1);
        }
    };

    let langid = fluent_code;
    let mut bundle = FluentBundle::new(vec![langid]);
    match bundle.add_resource(ftl_resource) {
        Ok(_) => (),
        Err(_) => {
            eprintln!("Failed to add FTL resource.");
            std::process::exit(1);
        }
    };
    Some(bundle)
}

pub fn get_translation<'bundle>(
    bundle: &'bundle FluentBundle<FluentResource>,
    key: &str,
    args: Option<&FluentArgs<'bundle>>,
) -> Result<String, String> {
    match bundle.get_message(key) {
        Some(message) => {
            let value = match message.value() {
                Some(v) => v,
                None => return Err("The embedded resource does not exist.".to_string()),
            };
            let result = bundle.format_pattern(value, args, &mut Vec::with_capacity(1));
            Ok(result.trim_matches('"').to_owned())
        }
        None => Err("The embedded resource does not exist.".to_string()),
    }
}

#[derive(Parser, Debug, PartialEq)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = "A CLI tool for generating strong password.",
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
            \nSpecify the language code as defined by ISO639-3.\
            \nSupported languages: Japanese, English, and German.\
            \nDefault language: English"
    )]
    pub language: Option<Language>,

    // 特殊記号を含むかどうかのフラグ
    #[clap(
        short = 's',
        long = "symbols",
        help = "Include symbols in the password."
    )]
    pub symbols: bool,

    // 数字を含むかどうかのフラグ
    #[clap(
        short = 'n',
        long = "numbers",
        help = "Include numbers in the password.\
        \nAs a default setting, !@#$%^&*() is used."
    )]
    pub numbers: bool,

    // 大文字を含むかどうかのフラグ
    #[clap(
        short = 'u',
        long = "uppercase",
        help = "Include uppercase letters in the password."
    )]
    pub uppercase: bool,

    // 小文字を含むかどうかのフラグ
    #[clap(
        short = 'w',
        long = "lowercase",
        help = "Include lowercase letters in the password."
    )]
    pub lowercase: bool,

    // パスワードの長さを指定する
    #[clap(
        short = 'c',
        long = "count",
        value_name = "PASSWORD_LENGTH",
        help = "Specifies the length of the password.\
        \nThis option allows you to set the number of characters in the generated password."
    )]
    pub password_length: Option<usize>,
}

pub fn parse_args() -> RupassArgs {
    let matches = RupassArgs::parse();
    matches
}
