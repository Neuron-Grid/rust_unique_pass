Language: [English](./README_eng.md) | [日本語](./README_jpn.md)

## Rust Unique Pass
This software is designed to generate random strong passwords.<br>
Users can customize the length of their passwords and the special characters they use.<br>
Except for the FTL files for translation, everything is written in the Rust language.

## Install
Please make sure that the `Rust language` is installed beforehand.<br>
If not, please install it from the [official website](https://www.rust-lang.org/).<br>
If it is already installed, run the following command.<br>
``` zsh
cargo install rust_unique_pass
```

## usage
See `execution method` in the next section.<br>
It is a CLI tool and should be run from the command line.<br>
The command name is `rupass`.

## About Language Settings
- **Languages supported**
  - Japanese language
  - English language
  - German language

For use in languages other than English, specify the language code defined in `ISO 639-3`.<br>
The command can be used in Japanese by making the following changes.
```
rupass -l jpn
```

### precautions
- Default language setting is English.
- The language can be specified with the `-l` option.
  - The `-l` option is not required when using the English language.
  - english use example
  ``` zsh
  rupass
  ```

## Request for collaboration.
This project is intended to be multilingual.
If you would like to help with translation, please see [CONTRIBUTING](../CONTRIBUTING/English.md).

## License
This software is released under the `Apache License 2.0`.<br>
See [LICENSE](../LICENSE) for details.

Copyright © 2023 Neuron Grid. <br>
Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).