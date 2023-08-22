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
`Rust`がインストールされていることを確認してください。<br>
`Rust`がインストールされていない場合は、[Rustの公式サイト](https://www.rust-lang.org/)を参照してください。

クレートが古い可能性があります。<br>
事前に確認してください。

``` zsh
git clone https://github.com/Neuron-Grid/Password_Generator && \
cd Password_Generator && \
cargo run
```

## 名前の募集
このパスワードジェネレーターはまだ名前がありません。<br>
現時点では`password_generator`となっていますが、将来的に変更する予定です。<br>
名前を募集しています。<br>
名前を考えてくださった方は、[こちら](https://manager.neuron-grid.net/)からご連絡ください。

名前を考える場合は、以下のことを考慮してください。<br>
- CLIアプリなので、正式名称とコマンド名の2つを考えてください。
- その他、自由に考えてください。

下記は具体例です。<br>
| 募集中 | 正式名 | コマンド名 | 考案者 |
| :---: | :---: | :---: | :---: |
| 1. | rust unique pass | rupass | Neuron Grid |

## 今後の予定
- 多言語対応
- パスワードの強度を推定する機能の追加

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