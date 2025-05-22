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

use crate::cli::RupassArgs;
use crate::core::app_errors::{GenerationError, Result};
use fluent::{FluentArgs, FluentBundle, FluentResource};
use rust_embed::RustEmbed;
use std::str::FromStr;
use unic_langid::LanguageIdentifier;

const DEFAULT_LANGUAGE: &str = "eng";

/// # Overview
/// `RustEmbed` を使用して、`./translation` ディレクトリにある `.ftl` ファイルをバイナリに埋め込みます。
#[derive(RustEmbed)]
#[folder = "./translation"]
#[include = "*.ftl"]
struct Translations;

/// # Overview
/// 埋め込まれた翻訳リソースファイルの内容を UTF-8 文字列として取得します。
///
/// # Arguments
/// * `filename`: 取得するリソースのファイル名 (例: "eng.ftl")。
///
/// # Returns
/// リソースが見つかり、UTF-8 としてデコードできた場合、その内容を含む [`Option<String>`] を返します。
/// 見つからないかデコードに失敗した場合、`None` を返します。
fn get_embedded_resource(filename: &str) -> Option<String> {
    Translations::get(filename)
        .and_then(|data: rust_embed::EmbeddedFile| String::from_utf8(data.data.to_vec()).ok())
}

/// # Overview
/// 言語コード文字列を `fluent` クレートで使用される [`LanguageIdentifier`] に変換します。
///
/// # Arguments
/// * `code`: 変換する言語コード文字列 (例: "eng", "jpn")。
///
/// # Returns
/// 変換に成功した場合、対応する [`LanguageIdentifier`] を含む [`Result`] を返します。
///
/// # Errors
/// 指定された言語コードが [`LanguageIdentifier`] として無効な場合、[`GenerationError::UnsupportedLanguage`] を含む [`Result`] を返します。
fn map_to_fluent_code(code: &str) -> Result<LanguageIdentifier> {
    LanguageIdentifier::from_str(code).map_err(|_| GenerationError::UnsupportedLanguage)
}

/// # Overview
/// コマンドライン引数から指定された言語コードを解決します。
/// 引数で言語が指定されていない場合は、デフォルト言語コード ("eng") を返します。
///
/// # Arguments
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体への参照。
///
/// # Returns
/// 解決された言語コードを含む [`String`] を返します。
fn resolve_language(args: &RupassArgs) -> String {
    args.language
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| DEFAULT_LANGUAGE.to_string())
}

/// # Overview
/// 指定された言語コードに対応する FluentBundle をロードします。
/// 埋め込まれた `.ftl` リソースを読み込み、パースしてバンドルに追加します。
///
/// # Arguments
/// * `language`: ロードするバンドルの言語コード文字列。
///
/// # Returns
/// ロードされた [`FluentBundle<FluentResource>`] を含む [`Result`] を返します。
///
/// # Errors
/// 指定された言語のリソースが見つからない場合、[`GenerationError::UnsupportedLanguage`] を含む [`Result`] を返します。
/// リソースのパースに失敗した場合、[`GenerationError::ResourceParseError`] を含む [`Result`] を返します。
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

/// # Overview
/// コマンドライン引数に基づいて、アプリケーションで使用する [`FluentBundle`] を初期化します。
///
/// # Arguments
/// * `args`: コマンドライン引数を格納した [`RupassArgs`] 構造体への参照。
///
/// # Returns
/// 初期化された [`FluentBundle<FluentResource>`] を含む [`Result`] を返します。
///
/// # Errors
/// 言語の解決またはバンドルのロードに失敗した場合、関連する [`GenerationError`] を含む [`Result`] を返します。
#[doc(alias = "i18n")]
#[doc(alias = "internationalization")]
#[doc(alias = "localization")]
pub fn initialize_bundle(args: &RupassArgs) -> Result<FluentBundle<FluentResource>> {
    let language = resolve_language(args);
    load_fluent_bundle(&language)
}

/// # Overview
/// 指定されたキーに対応する翻訳メッセージを [`FluentBundle`] から取得し、必要に応じて引数を適用してフォーマットします。
///
/// # Arguments
/// * `bundle`: 翻訳メッセージを取得する [`FluentBundle`] への参照。
/// * `key`: 取得する翻訳メッセージのキー。
/// * `args`: 翻訳メッセージに適用する引数を含む [`FluentArgs`] へのオプションの参照。
///
/// # Returns
/// フォーマットされた翻訳メッセージ文字列を含む [`Result<String>`] を返します。
///
/// # Errors
/// 指定されたキーに対応するメッセージまたは値がバンドルに見つからない場合、[`GenerationError::TranslationMissing`] を含む [`Result`] を返します。
#[doc(alias = "translate")]
#[doc(alias = "get message")]
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
