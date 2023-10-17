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
use generate_pass::{assemble_character_set, get_password_length, produce_secure_password};
use i18n::{get_translation, initialize_bundle, parse_args, RupassArgs};

// ユーザからの入力に基づいて強固なパスワードを生成し、表示します。
fn main() {
    // ユーザーの引数を解析して希望の言語を決定
    let matches: RupassArgs = parse_args();
    // ユーザーの言語の設定に基づいて翻訳バンドルを初期化
    let bundle = initialize_bundle(&matches);
    // ユーザーとの対話のための翻訳されたプロンプトとメッセージを取得
    let generated_password_msg: String =
        get_translation(&bundle, "generated_password", None).unwrap();
    // ユーザーの入力から希望のパスワードの長さを決定
    let length: usize = get_password_length(&bundle);
    // ユーザーの選択に基づいて文字セットを組み立て
    let character_set: String = assemble_character_set(&bundle);
    // 決定された設定を使用してセキュアなパスワードを生成
    let password: String = produce_secure_password(&character_set, length);
    // ユーザーに生成されたパスワードを表示
    println!("{}\n{}", generated_password_msg.as_str(), password);
}
