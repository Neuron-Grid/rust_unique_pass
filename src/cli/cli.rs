use {crate::password::password_generation::MAX_TIMEOUT_MS, clap::Parser};

/// # Overview
/// コマンドライン引数を定義する構造体。
/// `clap` クレートを使用して引数をパースします。
#[derive(Parser, Debug, PartialEq)]
pub struct RupassArgs {
    // 設定言語を指定する
    #[clap(
        short = 'l',
        long = "language",
        short_alias = 'L',
        value_name = "LANGUAGE",
        help = "Specifies the language for user prompts and messages.\
            \nDefault: English (eng). ISO639-3 codes: eng (en), jpn (ja), deu (de)."
    )]
    pub language: Option<String>,

    // パスワード長を指定する
    #[clap(
        short = 'p',
        long = "password-length",
        value_name = "PASSWORD_LENGTH",
        help = "Specify the length of the password. \
            \nDefault: prompt (interactive).\
            \nWith --no-prompt you must specify this."
    )]
    pub password_length: Option<usize>,

    // 文字種を全て有効化するショートカット
    #[clap(
        short = 'a',
        long = "all",
        conflicts_with_all = [
            "no_numbers",
            "no_uppercase",
            "no_lowercase",
            "no_symbols",
        ],
        help = "Enable all character classes: numbers, uppercase, lowercase, symbols.\
            \nConflicts: --no-numbers, --no-uppercase, --no-lowercase, --no-symbols"
    )]
    pub all: bool,

    // 対話を行わずデフォルト（OFF）のまま進める
    #[clap(
        long = "no-prompt",
        help = "Disable all interactive questions.\
            \nUnspecified character classes stay OFF.\
            \nRequires specifying --password-length."
    )]
    pub no_prompt: bool,

    // 数字を含むかどうかのフラグ
    #[clap(
        short = 'n',
        long = "numbers",
        help = "Include numbers in the password.\
            \nDefault: OFF.\
            \nNegative form available: --no-numbers (-N)."
    )]
    pub numbers: bool,

    // 数字を使用しないフラグ
    #[clap(
        short = 'N',
        long = "no-numbers",
        help = "Exclude numbers from the password (alias of not setting --numbers).",
        conflicts_with = "numbers"
    )]
    pub no_numbers: bool,

    // 大文字を含むかどうかのフラグ
    #[clap(
        short = 'u',
        long = "uppercase",
        help = "Include uppercase letters in the password.\
            \nDefault: OFF.\
            \nNegative form available: --no-uppercase (-U)."
    )]
    pub uppercase: bool,

    // 大文字を使用しないフラグ
    #[clap(
        short = 'U',
        long = "no-uppercase",
        help = "Exclude uppercase letters from the password (alias of not setting --uppercase).",
        conflicts_with = "uppercase"
    )]
    pub no_uppercase: bool,

    // 小文字を含むかどうかのフラグ
    #[clap(
        short = 'w',
        long = "lowercase",
        help = "Include lowercase letters in the password.\
            \nDefault: OFF.\
            \nNegative form available: --no-lowercase (-W)."
    )]
    pub lowercase: bool,

    // 小文字を使用しないフラグ
    #[clap(
        short = 'W',
        long = "no-lowercase",
        help = "Exclude lowercase letters from the password (alias of not setting --lowercase).",
        conflicts_with = "lowercase"
    )]
    pub no_lowercase: bool,

    // 特殊記号を含むかどうかのフラグ
    #[clap(
        short = 's',
        long = "symbols",
        help = "Include symbols in passwords.\
        \nDefault: OFF.\
        \nBy default uses ~!@#$%^&*_-+=(){}[]:;<>,.?/.\
        \nNegative form available: --no-symbols (-S)."
    )]
    pub symbols: bool,

    // 特殊記号を使用しないフラグ
    #[clap(
        short = 'S',
        long = "no-symbols",
        help = "Exclude symbols from the password (alias of not setting --symbols).",
        conflicts_with = "symbols"
    )]
    pub no_symbols: bool,

    // カスタム特殊記号セット
    #[clap(
        long = "symbols-set",
        value_name = "SYMBOLS_SET",
        help = "Custom set of symbols to use with --symbols (non-empty string).",
        requires = "symbols",
        conflicts_with = "no_symbols",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    pub symbols_set: Option<String>,

    // 強度探索の時間予算（ミリ秒）
    #[clap(
        long = "timeout-ms",
        alias = "budget-ms",
        value_name = "TIMEOUT_MS",
        default_value_t = 150u64,
        value_parser = clap::value_parser!(u64).range(10..=MAX_TIMEOUT_MS),
        help = "Time budget in milliseconds for strength search.\
            \nAlias: --budget-ms.\
            \nMust be between 10 and 3600000. Default: 150"
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
}

/// # Overview
/// コマンドライン引数をパースして [`RupassArgs`] 構造体を生成します。
/// `clap::Parser::parse()` を使用します。
#[doc(alias = "parse")]
#[doc(alias = "args")]
pub fn parse_args() -> RupassArgs {
    RupassArgs::parse()
}
