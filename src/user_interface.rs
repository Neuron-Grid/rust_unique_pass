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

use crate::app_errors::Result;
use std::io::{self, Write};

// ユーザーとの入出力を抽象化するトレイト
pub trait UserInterface {
    fn prompt(&mut self, message: &str) -> Result<String>;
    fn print(&mut self, message: &str);
}

// 標準入出力の実装
pub struct StdioInterface;

impl UserInterface for StdioInterface {
    fn prompt(&mut self, message: &str) -> Result<String> {
        println!("{}", message);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    fn print(&mut self, message: &str) {
        println!("{}", message);
    }
}
