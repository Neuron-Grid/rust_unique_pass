## Rust Unique Pass
This software is designed to generate random strong passwords.<br>
Users can customize the length of their passwords and the special characters they use.<br>
Except for the FTL files for translation, everything is written in the Rust language.

## usage
See `execution method` in the next section.<br>
It is a CLI tool and should be run from the command line.<br>
The command name is `rupass`.<br>

### How to force termination
- **For macOS**: `control` + `c`
- **For Windows**: `Ctrl` + `c`

### precautions
- Default language setting is English.
- The language can be specified with the `-l` option.

## execution method
Please make sure that the `Rust language` is installed beforehand.<br>
If not, please install it from the [official website](https://www.rust-lang.org/).<br>
If it has already been installed, move it to any folder and then execute the following command.

``` zsh
git clone https://github.com/Neuron-Grid/rust_unique_pass && \
cd rust_unique_pass && \
cargo build --release && \
cd /target/release/ && \
./rupass
```

## About Language Settings
- **Languages supported**
  - Japanese language
  - English language
  - German language

For use in languages other than English, specify the language code defined in ISO 639-3.
The command can be used in Japanese by making the following changes.
```
./rupass -l jpn
```

## This software utilizes the following crates
GitHub repository
- [clap](https://github.com/clap-rs/clap)
- [fluent-rs](https://github.com/projectfluent/fluent-rs)
- [rand](https://github.com/rust-random/rand)
- [rust-embed](https://github.com/pyrossh/rust-embed)
- [unic-locale](https://github.com/zbraniecki/unic-locale)
- [zxcvbn-rs](https://github.com/shssoichiro/zxcvbn-rs)


## License
This software is released under the `Apache License 2.0`.<br>
See [LICENSE](../LICENSE) for details.

Copyright © 2023 Neuron Grid. <br>
Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).