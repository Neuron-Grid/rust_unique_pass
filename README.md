## Rust 製パスワードジェネレーター

このパスワードジェネレーターは、ランダムな強力なパスワードを生成するためのものです。<br>
ユーザーはパスワードの長さや使用する特殊文字などをカスタマイズすることができます。

## 使い方

このパスワードジェネレーターは、コマンドラインから実行することができます。<br>
以下のコマンドを実行すると、パスワードを生成することができます。

```zsh
cargo run
```

## コマンドのコピペ用

Cargo.toml の dependencies が古い可能性があります。<br>
必ず最新のものを使用してください。

```zsh
git clone https://github.com/Neuron-Grid/Password_Generator && \
cd Password_Generator && \
cargo run
```

## このソフトウェアは以下のクレートを利用しています

-   `rand` licensed under the MIT/Apache License 2.0.<br>
-   `zxcvbn` licensed under the MIT License.

-   GitHub repository<br>
    [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs)<br>
    [rand](https://github.com/rust-random/rand)
