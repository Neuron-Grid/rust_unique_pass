## パスワードジェネレーター
このパスワードジェネレーターは、ランダムな強力なパスワードを生成するためのものです。<br>
ユーザーはパスワードの長さや使用する特殊文字などをカスタマイズすることができます。

## 使い方
これは`Rust`製のパスワードジェネレーターです。<br>
CLIアプリなのでコマンドラインから実行してください。<br>

### 強制終了する方法について

- **macOSの場合** : `control` + `c`を押してください。
- **Windowsの場合** : `Ctrl` + `c`を押してください。


## コマンドのコピペ用
Cargo.tomlの`dependencies`が古い可能性があります。<br>
事前に確認してください。

``` zsh
git clone https://github.com/Neuron-Grid/Password_Generator && \
cd Password_Generator && \
cargo run
```

## このソフトウェアは以下のクレートを利用しています
-  `rand` licensed under the MIT/Apache License 2.0.<br>
-  `zxcvbn` licensed under the MIT License.<br>

GitHub repository
> [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs)<br>
> [rand](https://github.com/rust-random/rand)

## ライセンス
このソフトウェアは`Apache License 2.0`の下で公開されています。<br>
詳細は[LICENSE](./LICENSE)をご覧ください。

Copyright © 2023 Neuron Grid. <br>
Licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).