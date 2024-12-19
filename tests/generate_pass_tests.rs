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

use fluent::{FluentBundle, FluentResource};
use rust_unique_pass::generate_pass::{
    assemble_random_password, produce_secure_password, validate_password_length,
};
use rust_unique_pass::i18n::RupassArgs;
use rust_unique_pass::{generate_password_flow, GenerationError, Result, StdioInterface};
use std::collections::VecDeque;
use unic_langid::LanguageIdentifier;

struct MockUi {
    inputs: VecDeque<String>,
    outputs: Vec<String>,
}

impl MockUi {
    fn new(inputs: Vec<&str>) -> Self {
        Self {
            inputs: inputs.into_iter().map(String::from).collect(),
            outputs: vec![],
        }
    }
}

impl rust_unique_pass::user_interface::UserInterface for MockUi {
    fn prompt(&mut self, message: &str) -> Result<String> {
        self.outputs.push(message.to_string());
        self.inputs
            .pop_front()
            .ok_or_else(|| GenerationError::InvalidInput)
    }

    fn print(&mut self, message: &str) {
        self.outputs.push(message.to_string());
    }
}

fn get_test_bundle() -> FluentBundle<FluentResource> {
    let langid: LanguageIdentifier = "eng".parse().expect("Failed to parse language identifier");
    let ftl_string = include_str!("../translation/eng.ftl");
    let resource = FluentResource::try_new(ftl_string.to_string())
        .expect("Failed to create FluentResource from given FTL string.");

    let mut bundle = FluentBundle::new(vec![langid]);
    bundle
        .add_resource(resource)
        .expect("Failed to add resource to FluentBundle.");
    bundle
}

#[test]
fn test_validate_password_length() -> std::result::Result<(), GenerationError> {
    let err = validate_password_length(10).expect_err("Expected an error for length 10");
    assert!(matches!(err, GenerationError::InvalidLength));
    validate_password_length(15)?;
    validate_password_length(20)?;
    Ok(())
}

#[test]
fn test_assemble_random_password() -> std::result::Result<(), GenerationError> {
    let chars = "ABC123";
    let pwd = assemble_random_password(chars, 10)?;
    assert_eq!(pwd.len(), 10);
    assert!(pwd.chars().all(|c| chars.contains(c)));

    let err =
        assemble_random_password("", 10).expect_err("Expected GenerationError for empty chars");
    assert!(matches!(err, GenerationError::GenerationFailed));
    Ok(())
}

#[test]
fn test_produce_secure_password() -> std::result::Result<(), GenerationError> {
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?@#$%^&*()";
    let pwd = produce_secure_password(chars, 15)?;
    assert!(pwd.len() >= 15);
    Ok(())
}

#[test]
fn test_generate_password_flow_mock_ui() -> std::result::Result<(), GenerationError> {
    let mut ui = MockUi::new(vec!["15", "y", "y", "y", "y", "n"]);

    let args = RupassArgs {
        language: None,
        symbols: false,
        password_length: None,
        numbers: false,
        uppercase: false,
        lowercase: false,
    };

    let bundle = get_test_bundle();
    generate_password_flow(&mut ui, &bundle, &args)?;
    let output_str = ui.outputs.join("\n");
    assert!(output_str.contains("Password Generation Result"));
    Ok(())
}

#[test]
fn test_generate_password_flow_integration() -> std::result::Result<(), GenerationError> {
    let args = RupassArgs {
        language: None,
        symbols: true,
        password_length: Some(15),
        numbers: true,
        uppercase: true,
        lowercase: true,
    };

    let bundle = get_test_bundle();
    let mut ui = StdioInterface;
    let res = generate_password_flow(&mut ui, &bundle, &args)?;
    assert!(res.len() >= 15);
    Ok(())
}
