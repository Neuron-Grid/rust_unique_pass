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
use clap::Parser;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use rust_embed::RustEmbed;
use std::str::FromStr;
use unic_langid::LanguageIdentifier;

const DEFAULT_LANGUAGE: &str = "eng";

#[derive(RustEmbed)]
#[folder = "./translation"]
#[include = "*.ftl"]
struct Translations;

/// 埋め込みリソースを取得し、UTF-8文字列として返す。
fn get_embedded_resource(filename: &str) -> Option<String> {
    Translations::get(filename)
        .and_then(|data: rust_embed::EmbeddedFile| String::from_utf8(data.data.to_vec()).ok())
}

/// 言語コード文字列を `LanguageIdentifier` に変換する。
fn map_to_fluent_code(code: &str) -> Result<LanguageIdentifier> {
    LanguageIdentifier::from_str(code).map_err(|_| GenerationError::UnsupportedLanguage)
}

/// コマンドライン引数から言語を解決し、文字列で返す。
/// 引数で指定されていなければデフォルト言語 (eng) を返す。
fn resolve_language(args: &RupassArgs) -> String {
    args.language
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| DEFAULT_LANGUAGE.to_string())
}

/// 指定された言語文字列をもとに FluentBundle を生成して返す。
fn load_fluent_bundle(language: &str) -> Result<FluentBundle<FluentResource>> {
    let langid = map_to_fluent_code(language)?;
    let resource_filename = format!("{}.ftl", langid);

    let ftl_string =
        get_embedded_resource(&resource_filename).ok_or(GenerationError::UnsupportedLanguage)?;
    let ftl_resource =
        FluentResource::try_new(ftl_string).map_err(|_| GenerationError::ResourceParseError)?;

    let mut bundle = FluentBundle::new(vec![langid]);
    bundle
        .add_resource(ftl_resource)
        .map_err(|_| GenerationError::ResourceParseError)?;

    Ok(bundle)
}

/// コマンドライン引数から言語設定を取得し、それに対応する FluentBundle を初期化する。
pub fn initialize_bundle(args: &RupassArgs) -> Result<FluentBundle<FluentResource>> {
    let language = resolve_language(args);
    load_fluent_bundle(&language)
}

/// FluentBundle から指定キーのメッセージを取得し、引数があれば適用して返す。
pub fn get_translation<'bundle>(
    bundle: &'bundle FluentBundle<FluentResource>,
    key: &str,
    args: Option<&FluentArgs<'bundle>>,
) -> Result<String> {
    let message = bundle
        .get_message(key)
        .ok_or_else(|| GenerationError::TranslationMissing(key.to_string()))?;

    let value = message
        .value()
        .ok_or_else(|| GenerationError::TranslationMissing(key.to_string()))?;

    let formatted_value = bundle.format_pattern(value, args, &mut Vec::new());
    Ok(formatted_value.trim_matches('"').to_owned())
}

#[derive(Parser, Debug, PartialEq)]
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
    pub language: Option<String>,

    // パスワード長を指定する
    #[clap(
        short = 'p',
        long = "password-length",
        value_name = "PASSWORD_LENGTH",
        help = "Specify the length of the password. \
            \nIf omitted, a default length is used."
    )]
    pub password_length: Option<usize>,

    // 数字を含むかどうかのフラグ
    #[clap(
        short = 'n',
        long = "numbers",
        help = "Include numbers in the password."
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

    // 特殊記号を含むかどうかのフラグ
    #[clap(
        short = 's',
        long = "symbols",
        help = "Include symbols in passwords.\
        \nBy default, the symbols ~!@#$%^&*_-+=(){}[]:;<>,.?/ are used.\
        \nYou can change which special symbols are used."
    )]
    pub symbols: bool,
}

/// コマンドライン引数をパースしてRupassArgsを生成する。
pub fn parse_args() -> RupassArgs {
    RupassArgs::parse()
}
