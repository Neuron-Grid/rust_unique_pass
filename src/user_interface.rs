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

/// ユーザーとのI/Oを抽象化
#[async_trait(?Send)]
pub trait UserInterface {
    async fn prompt(&mut self, message: &str) -> Result<String>;
    async fn print(&mut self, message: &str) -> Result<()>;
}

/// 標準入出力実装
/// BufReaderを再利用
pub struct StdioInterface {
    reader: BufReader<io::Stdin>,
}

impl Default for StdioInterface {
    fn default() -> Self {
        Self {
            reader: BufReader::new(io::stdin()),
        }
    }
}

impl StdioInterface {
    /// 明示的なコンストラクタ
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait(?Send)]
impl UserInterface for StdioInterface {
    /// プロンプトを表示して1行読み取る
    async fn prompt(&mut self, message: &str) -> Result<String> {
        let mut stdout = io::stdout();
        stdout.write_all(format!("{message}\n").as_bytes()).await?;
        stdout.flush().await?;

        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line.trim().to_owned())
    }

    /// メッセージを出力
    async fn print(&mut self, message: &str) -> Result<()> {
        let mut stdout = io::stdout();
        stdout.write_all(format!("{message}\n").as_bytes()).await?;
        stdout.flush().await?;
        Ok(())
    }
}
