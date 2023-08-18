## パスワードジェネレーター
このパスワードジェネレーターは、ランダムな強力なパスワードを生成するためのものです。<br>
ユーザーはパスワードの長さや使用する特殊文字などをカスタマイズすることができます。

## 使い方
これは`Rust`製のパスワードジェネレーターです。<br>
CLIアプリなのでコマンドラインから実行してください。

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
