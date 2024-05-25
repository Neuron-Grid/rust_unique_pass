/* Copyright 2023 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

mod generate_pass;
mod i18n;
use generate_pass::{assemble_character_set, get_password_length, handle_password_generation};
use i18n::{get_translation, initialize_bundle, parse_args, RupassArgs};

fn main() {
    // ユーザーの引数を解析して希望の言語を決定
    let matches = parse_args();
    // ユーザーの言語の設定に基づいて翻訳バンドルを初期化
    let bundle = initialize_bundle(&matches);
    // ユーザーとの対話のための翻訳されたプロンプトとメッセージを取得
    let generated_password_msg = match handle_error(
        get_translation(&bundle, "generated_password", None),
        "Error retrieving translation",
    ) {
        Some(msg) => msg,
        None => return,
    };
    // ユーザーの入力から希望のパスワードの長さを決定
    let length = get_password_length(&bundle);
    // ユーザーの選択に基づいて文字セットを組み立て
    let character_set = match handle_error(
        assemble_character_set(&bundle, &matches),
        "Error assembling character set",
    ) {
        Some(set) => set,
        None => return,
    };
    // パスワードを生成し、メッセージを表示
    let _ = handle_password_generation(&character_set, length, &generated_password_msg, &bundle);
}

fn handle_error<T>(result: Result<T, String>, error_message: &str) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(e) => {
            eprintln!("{}: {}", error_message, e);
            None
        }
    }
}
