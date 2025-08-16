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

    // 強度探索の時間予算（ミリ秒）
    #[clap(
        long = "timeout-ms",
        alias = "budget-ms",
        value_name = "TIMEOUT_MS",
        default_value_t = 150u64,
        value_parser = clap::value_parser!(u64).range(10..),
        help = "Time budget in milliseconds for strength search.\
            \nAlias: --budget-ms.\
            \nMust be >= 10. Default: 150"
    )]
    pub timeout_ms: u64,

    // 早期終了の目標スコア
    #[clap(
        long = "min-score",
        value_name = "MIN_SCORE",
        default_value_t = 4u8,
        value_parser = clap::value_parser!(u8).range(0..=4),
        help = "Target zxcvbn score for early stop (0..=4). Default: 4"
    )]
    pub min_score: u8,

    // 厳格モード：期限内未達で失敗
    #[clap(
        long = "strict",
        help = "Strict mode: fail if target score not reached within time budget"
    )]
    pub strict: bool,

    // 強度行の表示
    #[clap(
        long = "show-strength",
        help = "Show strength line (score/entropy) on success"
    )]
    pub show_strength: bool,

    // 静かな出力（別名: porcelain）
    #[clap(
        long = "quiet",
        alias = "porcelain",
        help = "Quiet (porcelain) output: print only the password on success"
    )]
    pub quiet: bool,

    // 最大試行回数の安全装置
    #[clap(
        long = "max-attempts",
        value_name = "MAX_ATTEMPTS",
        default_value_t = 1_000_000u64,
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Safety guard: maximum attempts before giving up. Default: 1,000,000"
    )]
    pub max_attempts: u64,
}

/// # Overview
/// コマンドライン引数をパースして [`RupassArgs`] 構造体を生成します。
/// `clap::Parser::parse()` を使用します。
#[doc(alias = "parse")]
#[doc(alias = "args")]
pub fn parse_args() -> RupassArgs {
    RupassArgs::parse()
}
