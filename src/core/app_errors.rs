/* Copyright 2024-2025 Neuron Grid

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

/// # Overview
/// パスワード生成プロセス中に発生しうるエラーを定義します。
#[derive(Error, Debug)]
pub enum GenerationError {
    /// パスワード長が不正な場合に発生します。
    #[error("Invalid password length")]
    InvalidLength,
    /// タイムアウト値が不正な場合に発生します。
    #[error("Invalid timeout value")]
    InvalidTimeout,
    /// パスワード生成が指定された試行回数内に完了しなかった場合に発生します。
    #[error("Password generation failed")]
    GenerationFailed,
    /// パスワード生成に使用する文字セットが何も選択されなかった場合に発生します。
    #[error("No character set selected")]
    NoCharacterSet,
    /// 指定された翻訳キーに対応する翻訳が見つからなかった場合に発生します。
    #[error("Translation missing: {0}")]
    TranslationMissing(String),
    /// 標準入出力操作中にエラーが発生した場合に発生します。
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    /// 指定された言語がサポートされていない場合に発生します。
    #[error("Unsupported language")]
    UnsupportedLanguage,
    /// 翻訳リソースのパースに失敗した場合に発生します。
    #[error("Resource parse error")]
    ResourceParseError,
    /// ユーザーとの対話がキャンセルされたか、無効な入力があった場合に発生します。
    #[error("Interaction cancelled or invalid input.")]
    InvalidInput,
    /// 厳格モードで時間内に目標スコアに到達しなかった場合に発生します。
    #[error("Strict target unmet within time budget")]
    StrictTargetUnmet,
    /// 連続した入力エラーが発生した場合に発生します。
    #[error("Input failure: {0}")]
    InputFailure(String),
    /// OSからのエントロピー取得に失敗した場合に発生します。
    #[error("Failed to gather entropy from the operating system.")]
    EntropyError(#[from] getrandom::Error),
}

/// # Overview
/// CLI の終了コードをエラー種別から決定します。
pub fn exit_code_for_error(err: &GenerationError) -> i32 {
    match err {
        GenerationError::StrictTargetUnmet => 3,
        _ => 1,
    }
}

/// # Overview
/// アプリケーション全体で使用される [`Result`] 型のエイリアス。
/// エラー型として [`GenerationError`] を使用します。
pub type Result<T> = std::result::Result<T, GenerationError>;
