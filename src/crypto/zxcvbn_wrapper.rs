use zxcvbn::zxcvbn;

pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// zxcvbnによるパスワード強度推定（推奨）
/// # 引数
/// - `password`: 評価対象のパスワード文字列
/// # 戻り値
/// - Ok((エントロピー[bit], スコア[0-4])): 成功時
/// - Err(String): エラー詳細
/// # セキュリティ考慮事項
/// - この関数はzxcvbnアルゴリズムを用いてパスワード強度を推定します。
/// - エラー時は詳細なエラー内容を返します。
pub fn zxcvbn_entropy_score(password: &str) -> Result<(f64, u8), String> {
    if password.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(format!(
            "password length {} exceeds maximum allowed {}",
            password.len(),
            MAX_PASSWORD_LENGTH
        ));
    }

    let analysis = zxcvbn(password, &[]);
    let guesses_f = analysis.guesses() as f64;
    let bits_of_entropy = guesses_f.log10() * std::f64::consts::LOG2_10;
    let score_u8: u8 = analysis.score().into();
    Ok((bits_of_entropy, score_u8))
}
