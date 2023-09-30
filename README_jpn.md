## Rust unique pass
このソフトウェアは、ランダムな強力なパスワードを生成するためのものです。<br>
利用者はパスワードの長さや使用する特殊文字などをカスタマイズすることができます。<br>
翻訳用のFTLファイル以外は全てRust言語で書かれています。

## 使い方
下記の**実行方法**を参照してください。<br>
CLIツールなのでコマンドラインから実行してください。<br>
コマンド名は`rupass`です。

### 強制終了する方法について
- **macOSの場合** : `control` + `c`を押してください。
- **Windowsの場合** : `Ctrl` + `c`を押してください。

### 注意事項
- デフォルトの言語は英語です。
- 言語は`-l`オプションで指定できます。

## 実行方法
事前に`Rust`がインストールされていることを確認してください。<br>
インストールされていない場合は、[Rustの公式サイト](https://www.rust-lang.org/)を参照してください。

``` zsh
git clone https://github.com/Neuron-Grid/rust_unique_pass && \
cd rust_unique_pass && \
cargo build --release && \
cd /target/release/ && \
./rupass
```

## 言語について
- **対応言語**
  - 日本語
  - 英語
  - ドイツ語

ISO 639-3で定義されている言語コードを指定してください。<br>
コマンドを下記のようにすることで日本語で利用できます。
```
./rupass -l jpn
```

## このソフトウェアは以下のクレートを利用しています
GitHub repository
- [clap](ttps://github.com/clap-rs/clap)<br>
- [fluent-rs](https://github.com/projectfluent/fluent-rs)<br>
- [rand](https://github.com/rust-random/rand)<br>
- [rust-embed](https://github.com/pyrossh/rust-embed)<br>
- [unic-locale](https://github.com/zbraniecki/unic-locale)<br>
- [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs)<br>

## License
このソフトウェアは`Apache License 2.0`の下で公開されています。<br>
詳細は[LICENSE](./LICENSE)をご覧ください。

Copyright © 2023 Neuron Grid. <br>
Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).