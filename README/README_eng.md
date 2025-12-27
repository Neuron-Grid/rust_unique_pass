Language: [English](./README_eng.md) | [日本語](./README_jpn.md)

## Rust Unique Pass

This software is designed to generate random strong passwords.<br> Users can
customize the length of their passwords and the special characters they use.<br>
Except for the FTL files for translation, everything is written in the Rust
language.

## Install

Please make sure that the `Rust language` is installed beforehand.<br> If not,
please install it from the [official website](https://www.rust-lang.org/).<br>
If it is already installed, run the following command.<br>

```zsh
cargo install rust_unique_pass
```

## Usage

It is a CLI tool and should be run from the command line.<br> The command name
is `rupass`.

### Command-Line Options

`rupass` provides several command-line options to control password generation.

| Option (Short) | Option (Long) | Description |
| :-- | :-- | :-- |
| `-l` | `--language` | Language for prompts/messages (`eng` default, also `jpn`, `deu`). |
| `-p` | `--password-length` | Password length. Required when `--no-prompt` is used. |
| `-a` | `--all` | Enable all character classes (numbers, uppercase, lowercase, symbols). |
|  | `--no-prompt` | Non-interactive: skip all questions; unspecified classes stay OFF (errors if none chosen). |
| `-n` | `--numbers` / `--no-numbers` | Include / exclude numbers (default OFF). |
| `-u` | `--uppercase` / `--no-uppercase` | Include / exclude uppercase (default OFF). |
| `-w` | `--lowercase` / `--no-lowercase` | Include / exclude lowercase (default OFF). |
| `-s` | `--symbols` / `--no-symbols` | Include / exclude symbols (default OFF; default set `~!@#$%^&*_-+=(){}[]:;<>,.?/`). |
|  | `--symbols-set` | Custom symbols set to use with `--symbols`. |
|  | `--timeout-ms` (`--budget-ms`) | Time budget for strength search (>=10). Default: `150`. *Advanced* |
|  | `--min-score` | Early-stop target score (0..=4). Default: `4`. *Advanced* |
|  | `--strict` | Fail (exit 3) if target not reached within budget. *Advanced* |
|  | `--show-strength` | Print strength (score/entropy) on success. |
|  | `--quiet` (`--porcelain`) | Output password only; suppress headings/warnings. *Advanced* |

**Command Examples:**

- If you specify nothing, all character classes start OFF and the CLI will ask interactively. With `--no-prompt`, you must provide `--password-length` and at least one class flag (e.g., `--numbers` or `--all`), otherwise it errors.

- Generate a 32-character password including numbers, uppercase, lowercase, and
  symbols:
  ```zsh
  rupass -p 32 -n -u -w -s
  ```
- Generate a password with prompts in Japanese:
  ```zsh
  rupass -l jpn
  ```

### Time-budgeted strength search

- By default, the generator searches up to 150 ms for a candidate that reaches zxcvbn score 4.
- It stops early as soon as the target score is reached. If not reached within the budget, it uses the best candidate and prints a warning to stderr (unless `--strict` or `--quiet`).
- Use `--show-strength` to print a strength line like `Strength: 4/4 (entropy: 82.3 bits)`.
- In `--strict` mode, the program exits with code 3 if the target score is not met within the budget and does not print the password.

## About Language Settings

- **Languages supported**
  - Japanese language
  - English language
  - German language

For use in languages other than English, specify the language code defined in
`ISO 639-3`.<br> The command can be used in Japanese by making the following
changes.

```
rupass -l jpn
```

### precautions

- Default language setting is English.
- The language can be specified with the `-l` option.
- Password length is constrained by both character count and UTF-8 byte length.
- 32-bit targets are not supported.
  - The `-l` option is not required when using the English language.
  - english use example
  ```zsh
  rupass
  ```

## Request for collaboration.

This project is intended to be multilingual. If you would like to help with
translation, please see [CONTRIBUTING](../CONTRIBUTING/English.md).

## License

This software is released under the `Apache License 2.0`.<br> See
[LICENSE](../LICENSE) for details.

Copyright © 2023 Neuron Grid. <br> Licensed under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
