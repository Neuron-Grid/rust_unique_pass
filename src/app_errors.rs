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

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GenerationError {
    #[error("Invalid password length")]
    InvalidLength,
    #[error("Password generation failed")]
    GenerationFailed,
    #[error("No character set selected")]
    NoCharacterSet,
    #[error("Translation missing: {0}")]
    TranslationMissing(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Unsupported language")]
    UnsupportedLanguage,
    #[error("Resource parse error")]
    ResourceParseError,
    #[error("Interaction cancelled or invalid input.")]
    #[allow(dead_code)]
    InvalidInput,
}

pub type Result<T> = std::result::Result<T, GenerationError>;
