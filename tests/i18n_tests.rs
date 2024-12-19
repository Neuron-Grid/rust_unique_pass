/* Copyright 2024 Neuron Grid

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
use fluent::FluentArgs;
use rust_unique_pass::i18n::{get_translation, RupassArgs};
use rust_unique_pass::initialize_bundle;
use rust_unique_pass::GenerationError;
use std::str::FromStr;
use unic_langid::subtags::Language;

#[test]
fn test_parse_args_default() {
    let args = RupassArgs::parse_from(&["test_app"]);
    assert_eq!(args.language, None);
    assert_eq!(args.symbols, false);
    assert_eq!(args.password_length, None);
    assert_eq!(args.numbers, false);
    assert_eq!(args.uppercase, false);
    assert_eq!(args.lowercase, false);
}

#[test]
fn test_parse_args_custom() {
    let args =
        RupassArgs::parse_from(&["test_app", "-l", "eng", "-s", "-c", "20", "-n", "-u", "-w"]);
    let parsed_language = Language::from_str("eng").expect("Failed to parse language code 'eng'");
    assert_eq!(args.language, Some(parsed_language));
    assert_eq!(args.symbols, true);
    assert_eq!(args.password_length, Some(20));
    assert_eq!(args.numbers, true);
    assert_eq!(args.uppercase, true);
    assert_eq!(args.lowercase, true);
}

#[test]
fn test_initialize_bundle_default() {
    let args = RupassArgs {
        language: None,
        symbols: false,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
    };
    let bundle = initialize_bundle(&args).expect("Failed to initialize bundle");

    let msg = get_translation(&bundle, "generated_password", None);
    assert!(
        msg.is_ok(),
        "Failed to get translation for generated_password"
    );
}

#[test]
fn test_initialize_bundle_unsupported_language() {
    let parsed_language = Language::from_str("zzz").expect("Failed to parse language code 'zzz'");
    let args = RupassArgs {
        language: Some(parsed_language),
        symbols: false,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
    };
    let result = initialize_bundle(&args);
    match result {
        Err(GenerationError::UnsupportedLanguage) => {}
        Err(e) => panic!("Expected UnsupportedLanguage error, got {:?}", e),
        Ok(_) => panic!("Expected UnsupportedLanguage error, but got Ok(_) instead"),
    }
}

#[test]
fn test_get_translation() {
    let parsed_language = Language::from_str("eng").expect("Failed to parse language code 'eng'");
    let args = RupassArgs {
        language: Some(parsed_language),
        symbols: false,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
    };

    let bundle = initialize_bundle(&args).expect("Failed to initialize bundle");
    let msg = get_translation(&bundle, "question_password_length", None)
        .expect("Failed to get translation for question_password_length");
    assert!(!msg.is_empty(), "Translation should not be empty");
}

#[test]
fn test_get_translation_with_args() {
    let parsed_language = Language::from_str("eng").expect("Failed to parse language code 'eng'");
    let args = RupassArgs {
        language: Some(parsed_language),
        symbols: false,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
    };
    let bundle = initialize_bundle(&args).expect("Failed to initialize bundle");

    let mut fargs = FluentArgs::new();
    fargs.set("specialChars", "!?@#$%^&*()");
    let msg = get_translation(&bundle, "default_special_chars_message", Some(&fargs))
        .expect("Failed to get translation for default_special_chars_message");
    assert!(
        msg.contains("!?@#$%^&*()"),
        "Message should contain the provided specialChars"
    );
}
