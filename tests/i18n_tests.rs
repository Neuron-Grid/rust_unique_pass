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

use rust_unique_pass::i18n::*;
use fluent::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

#[test]
fn get_embedded_resource_exists() {
    let resource = get_embedded_resource("eng.ftl");
    assert!(resource.is_some());
}

#[test]
fn get_embedded_resource_not_exists() {
    let resource = get_embedded_resource("nonexistent.ftl");
    assert!(resource.is_none());
}

#[test]
fn get_translation_success() {
    let ftl_string = String::from("hello = Hello, world!");
    let resource = FluentResource::try_new(ftl_string).expect("Failed to parse FTL string.");
    let langid: LanguageIdentifier = "en-US".parse().expect("Parsing language failed.");
    let mut bundle = FluentBundle::new(vec![langid]);
    bundle.add_resource(resource).expect("Failed to add resource.");
    let translation_result = get_translation(&bundle, "hello", None);
    match translation_result {
        Ok(translation) => assert_eq!(translation, "Hello, world!"),
        Err(e) => panic!("Failed to get translation: {:?}", e),
    }
}

#[test]
fn get_translation_missing_key() {
    let ftl_string = String::from("hello = Hello, world!");
    let resource = FluentResource::try_new(ftl_string).expect("Failed to parse FTL string.");
    let langid: LanguageIdentifier = "en-US".parse().expect("Parsing language failed.");
    let mut bundle = FluentBundle::new(vec![langid]);
    bundle.add_resource(resource).expect("Failed to add resource.");
    let translation = get_translation(&bundle, "goodbye", None);
    assert!(translation.is_err());
}