use zxcvbn::zxcvbn;

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
    match zxcvbn(password, &[]) {
        Ok(result) => {
            let guesses = result.guesses();
            // log2(10) ≈ 3.321928
            let bits_of_entropy = guesses.log10() * 3.321928094887362;
            Ok((bits_of_entropy, result.score()))
        }
        Err(e) => Err(format!("zxcvbn failed: {}", e)),
    }
}

/// 非推奨: 旧API（後方互換用）
/// エラー時は(0.0, 0)を返す
#[deprecated(
    since = "1.1.0",
    note = "zxcvbn_entropy_score()のResult型バージョンを使用してください"
)]
pub fn zxcvbn_entropy_score_legacy(password: &str) -> (f64, u8) {
    match zxcvbn_entropy_score(password) {
        Ok((entropy, score)) => (entropy, score),
        Err(_) => (0.0, 0),
    }
}
