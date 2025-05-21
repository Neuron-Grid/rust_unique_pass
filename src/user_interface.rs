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

use crate::app_errors::Result;
use async_trait::async_trait;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

/// # Overview
/// ユーザーとの入出力を抽象化するためのトレイト。
/// これにより、CLI、GUI、Webなど、様々なユーザーインターフェースの実装を
/// アプリケーションのコアロジックから分離できます。
#[async_trait(?Send)]
pub trait UserInterface {
    /// # Overview
    /// ユーザーにメッセージを表示し、一行の入力を受け付けます。
    ///
    /// # Arguments
    /// * `message`: ユーザーに表示するプロンプトメッセージ。
    ///
    /// # Returns
    /// ユーザーが入力した文字列を返します。
    ///
    /// # Errors
    /// 入出力エラーが発生した場合、[`Result`] を返します。
    async fn prompt(&mut self, message: &str) -> Result<String>;

    /// # Overview
    /// ユーザーにメッセージを表示します。
    ///
    /// # Arguments
    /// * `message`: ユーザーに表示するメッセージ。
    ///
    /// # Returns
    /// 処理が成功した場合、`Ok(())` を返します。
    ///
    /// # Errors
    /// 入出力エラーが発生した場合、[`Result`] を返します。
    async fn print(&mut self, message: &str) -> Result<()>;
}

/// # Overview
/// 標準入出力 (stdin/stdout) を使用した [`UserInterface`] の実装。
///
/// # Notes
/// 入力読み取りのために [`BufReader`] を内部で使用し、効率的な読み取りを行います。
#[doc(alias = "stdio")]
pub struct StdioInterface {
    reader: BufReader<io::Stdin>,
}

impl Default for StdioInterface {
    /// # Overview
    /// [`StdioInterface`] のデフォルトインスタンスを作成します。
    /// 標準入力に対する [`BufReader`] を初期化します。
    fn default() -> Self {
        Self {
            reader: BufReader::new(io::stdin()),
        }
    }
}

impl StdioInterface {
    /// # Overview
    /// [`StdioInterface`] の新しいインスタンスを作成します。
    /// [`Default::default()`] と同じです。
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl UserInterface for StdioInterface {
    /// # Overview
    /// 標準出力にプロンプトメッセージを表示し、標準入力から一行読み取ります。
    ///
    /// # Arguments
    /// * `message`: ユーザーに表示するプロンプトメッセージ。
    ///
    /// # Returns
    /// ユーザーが入力した文字列を返します。末尾の改行はトリムされます。
    ///
    /// # Errors
    /// 標準入出力エラーが発生した場合、[`Result`] を返します。
    async fn prompt(&mut self, message: &str) -> Result<String> {
        let mut stdout = io::stdout();
        stdout.write_all(format!("{message}\n").as_bytes()).await?;
        stdout.flush().await?;

        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line.trim().to_owned())
    }

    /// # Overview
    /// 標準出力にメッセージを表示します。
    ///
    /// # Arguments
    /// * `message`: ユーザーに表示するメッセージ。
    ///
    /// # Returns
    /// 処理が成功した場合、`Ok(())` を返します。
    ///
    /// # Errors
    /// 標準出力エラーが発生した場合、[`Result`] を返します。
    async fn print(&mut self, message: &str) -> Result<()> {
        let mut stdout = io::stdout();
        stdout.write_all(format!("{message}\n").as_bytes()).await?;
        stdout.flush().await?;
        Ok(())
    }
}
