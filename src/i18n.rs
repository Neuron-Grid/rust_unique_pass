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
use clap::Parser;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use rust_embed::RustEmbed;
use std::str::FromStr;
use unic_langid::{subtags::Language, LanguageIdentifier};

const DEFAULT_LANGUAGE: &str = "eng";

#[derive(RustEmbed)]
#[folder = "./translation"]
#[include = "*.ftl"]
struct Translations;

fn get_embedded_resource(filename: &str) -> Option<String> {
    Translations::get(filename)
        .and_then(|data: rust_embed::EmbeddedFile| String::from_utf8(data.data.to_vec()).ok())
}

fn map_to_fluent_code(code: &str) -> Result<LanguageIdentifier> {
    LanguageIdentifier::from_str(code).map_err(|_| GenerationError::UnsupportedLanguage)
}

pub fn initialize_bundle(args: &RupassArgs) -> Result<FluentBundle<FluentResource>> {
    let language = args
        .language
        .as_ref()
        .map(|l| l.to_string())
        .unwrap_or_else(|| DEFAULT_LANGUAGE.to_string());
    load_fluent_bundle(&language)
}

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
    #[arg(short = 'l', long = "language", value_name = "LANGUAGE")]
    pub language: Option<Language>,

    #[arg(short = 's', long = "symbols")]
    pub symbols: bool,

    #[arg(short = 'c', long = "count", value_name = "PASSWORD_LENGTH")]
    pub password_length: Option<usize>,

    #[arg(short = 'n', long = "numbers")]
    pub numbers: bool,

    #[arg(short = 'u', long = "uppercase")]
    pub uppercase: bool,

    #[arg(short = 'w', long = "lowercase")]
    pub lowercase: bool,
}

pub fn parse_args() -> RupassArgs {
    RupassArgs::parse()
}
