use clap::Parser;

/// # Overview
/// コマンドライン引数を定義する構造体。
/// `clap` クレートを使用して引数をパースします。
#[derive(Parser, Debug, PartialEq)]
pub struct RupassArgs {
    // 設定言語を指定する
    #[clap(
        short = 'l',
        long = "language",
        value_name = "LANGUAGE",
        help = "Specifies the language for user prompts and messages.\
            \nSpecify the language code as defined by ISO639-3.\
            \nSupported languages: Japanese, English, and German.\
            \nDefault language: English"
    )]
    pub language: Option<String>,

    // パスワード長を指定する
    #[clap(
        short = 'p',
        long = "password-length",
        value_name = "PASSWORD_LENGTH",
        help = "Specify the length of the password. \
            \nIf omitted, a default length is used."
    )]
    pub password_length: Option<usize>,

    // 数字を含むかどうかのフラグ
    #[clap(
        short = 'n',
        long = "numbers",
        help = "Include numbers in the password."
    )]
    pub numbers: bool,

    // 大文字を含むかどうかのフラグ
    #[clap(
        short = 'u',
        long = "uppercase",
        help = "Include uppercase letters in the password."
    )]
    pub uppercase: bool,

    // 小文字を含むかどうかのフラグ
    #[clap(
        short = 'w',
        long = "lowercase",
        help = "Include lowercase letters in the password."
    )]
    pub lowercase: bool,

    // 特殊記号を含むかどうかのフラグ
    #[clap(
        short = 's',
        long = "symbols",
        help = "Include symbols in passwords.\
        \nBy default, the symbols ~!@#$%^&*_-+=(){}[]:;<>,.?/ are used.\
        \nYou can change which special symbols are used."
    )]
    pub symbols: bool,
}

/// # Overview
/// コマンドライン引数をパースして [`RupassArgs`] 構造体を生成します。
/// `clap::Parser::parse()` を使用します。
#[doc(alias = "parse")]
#[doc(alias = "args")]
pub fn parse_args() -> RupassArgs {
    RupassArgs::parse()
}
