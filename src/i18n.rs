/*
Copyright 2023 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use fluent::{FluentBundle, FluentResource};
use std::{fs, str::FromStr};
use unic_langid::LanguageIdentifier;

// デフォルトの言語英語に定義します。
const DEFAULT_LANGUAGE: &str = "en-US";

pub fn map_to_fluent_code(code: &str) -> LanguageIdentifier {
    match LanguageIdentifier::from_str(code) {
        Ok(lang_id) => lang_id,
        Err(_) => {
            // デフォルトのエラーメッセージを表示する
            eprintln!("Failed to parse the provided language identifier.");
            std::process::exit(1);
        }
    }
}

// ユーザーの入力からパスワードの長さを決定します。
pub fn initialize_bundle(matches: &clap::ArgMatches) -> FluentBundle<FluentResource> {
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
pub fn load_fluent_bundle(language: &str) -> Option<FluentBundle<FluentResource>> {
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
        /*Err(_) => {
            eprintln!("FTL文字列をパースできませんでした。\nFTL string could not be parsed.");
            std::process::exit(1);
        } */
        // これはテスト用のコードです。
        // This is a test code.
        Err(error) => {
            eprintln!("FTL文字列をパースできませんでした。\n{:?}", error);
            std::process::exit(1);
        }
    };
    let langid = fluent_code;
    let mut bundle = FluentBundle::new(vec![&langid]);
    bundle
        .add_resource(ftl_resource)
        .expect("FTLリソースの追加に失敗しました。\nFTL resource could not be added.");
    Some(bundle)
}

pub fn get_translation(
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
