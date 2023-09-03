## パスワードジェネレーター
このパスワードジェネレーターは、ランダムな強力なパスワードを生成するためのものです。<br>
ユーザーはパスワードの長さや使用する特殊文字などをカスタマイズすることができます。

- **対応言語**
  - 日本語
  - 英語
  - ドイツ語

## 使い方
これは`Rust`製のパスワードジェネレーターです。<br>
CLIアプリなのでコマンドラインから実行してください。<br>
コマンド名は`rupass`です。

### 強制終了する方法について

- **macOSの場合** : `control` + `c`を押してください。
- **Windowsの場合** : `Ctrl` + `c`を押してください。

## 注意事項
- デフォルトの言語設定は英語です。
- 言語は`-l`オプションで変更できます。
- 一部で`{specialChars}`と表示される不具合があります。
- 今回のコミットでは、1箇所のエラーが含まれています。<br>
`unresolved import clap::App no App in the root`

## 実行方法
`Rust`がインストールされていることを確認してください。<br>
インストールされていない場合は、[Rustの公式サイト](https://www.rust-lang.org/)を参照してください。

``` zsh
git clone https://github.com/Neuron-Grid/rust_unique_pass && \
cd rust_unique_pass && \
cargo build --release && \
cd /target/release/ && \
./rupass
```

## 今後の予定
- **パスワードの強度推定機能**
  - `zxcvbn`を利用して実装
  - 今後気が向いたら実装します。

## このソフトウェアは以下のクレートを利用しています
-  `rand` licensed under the MIT/Apache License 2.0.
-  `zxcvbn` licensed under the MIT License.

GitHub repository
> [rand](https://github.com/rust-random/rand)<br>
> [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs)

## ライセンス
このソフトウェアは`Apache License 2.0`の下で公開されています。<br>
詳細は[LICENSE](./LICENSE)をご覧ください。

Copyright © 2023 Neuron Grid. <br>
Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).