use zxcvbn::zxcvbn;

/// zxcvbnによるパスワード強度推定のテスト関数
pub fn test_zxcvbn(password: &str) -> (f64, u8) {
    match zxcvbn(password, &[]) {
        Ok(result) => {
            let guesses = result.guesses();
            let bits_of_entropy = guesses.log10() * 3.321928094887362;
            (bits_of_entropy, result.score())
        }
        Err(_) => (0.0, 0),
    }
}
