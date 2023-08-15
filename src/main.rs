extern crate rand;
extern crate zxcvbn;

use rand::{rngs::OsRng, seq::SliceRandom};
use std::io;

fn main() {
    // パスワードの長さの取得
    let length = get_password_length();

    // 文字のセットを取得
    let character_set = get_character_set();

    // 強力なパスワードを生成する
    let mut password = generate_password(&character_set, length);
    while !is_strong(&password) {
        password = generate_password(&character_set, length);
    }

    println!("生成されたパスワード: {}", password);
}

fn get_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);
    io::stdin().read_line(&mut input).expect("読み込みエラー");
    input.trim().to_string()
}

enum PasswordLengthError {
    InvalidNumber,
    TooShort,
}

fn validate_password_length(input: &str) -> Result<usize, PasswordLengthError> {
    match input.parse::<isize>() {
        // isize型に変更して、負の数も解析できるようにします。
        Ok(n) if n <= 0 => Err(PasswordLengthError::InvalidNumber), // 0以下の場合もエラーハンドリング
        Ok(n) if n as usize >= 8 => Ok(n as usize),
        Ok(_) => Err(PasswordLengthError::TooShort),
        Err(_) => Err(PasswordLengthError::InvalidNumber),
    }
}

fn get_password_length() -> usize {
    println!("パスワードの長さを入力してください\n12以上を推奨します。");
    loop {
        let input = get_input("");
        match validate_password_length(&input) {
            Ok(n) => return n,
            Err(PasswordLengthError::InvalidNumber) => {
                println!("有効な数値を入力してください。");
                continue;
            }
            Err(PasswordLengthError::TooShort) => println!("推奨される長さは12以上です。"),
        }
    }
}

fn get_character_set() -> String {
    let default_special_chars = "!@#$%^&*()-_=+';:,.<>/?";
    let mut character_set: String = String::new();

    if ask_user("大文字を含めますか？ (y/n)") {
        character_set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }

    if ask_user("小文字を含めますか？ (y/n)") {
        character_set += "abcdefghijklmnopqrstuvwxyz";
    }

    if ask_user("数字を含めますか？ (y/n)") {
        character_set += "0123456789";
    }

    println!(
        "デフォルトで使用される特殊文字は{}です。",
        default_special_chars
    );
    if ask_user("特殊文字を含めますか？ (y/n)") {
        loop {
            if ask_user("使用する特殊文字を変更しますか？ (y/n)") {
                let special_chars_input =
                    get_input("使用する特殊文字を入力してください (例: !@#):");
                if special_chars_input
                    .chars()
                    .all(|c| default_special_chars.contains(c))
                {
                    character_set += &special_chars_input;
                    break;
                } else {
                    println!("無効な特殊文字が入力されました。再度入力してください。");
                }
            } else {
                character_set += default_special_chars;
                break;
            }
        }
    }
    character_set
}

fn ask_user(message: &str) -> bool {
    let input = get_input(message);
    input.eq_ignore_ascii_case("y")
}

fn generate_password(chars: &str, length: usize) -> String {
    let mut rng = OsRng;
    (0..length)
        .map(|_| chars.as_bytes().choose(&mut rng).unwrap().clone() as char)
        .collect()
}

fn is_strong(password: &str) -> bool {
    let result = zxcvbn::zxcvbn(password, &[]).unwrap();
    result.score() > 2
}
