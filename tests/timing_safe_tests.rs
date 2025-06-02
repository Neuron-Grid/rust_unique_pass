use rust_unique_pass::crypto::timing_safe::*;

#[test]
fn test_constant_time_select() {
    let chars = vec!['a', 'b', 'c', 'd', 'e'];

    // 各インデックスでテスト
    for i in 0..chars.len() {
        let result = TimingSafeOps::constant_time_select(&chars, i);
        assert_eq!(result, Some(chars[i]));
    }

    // 範囲外のインデックス
    let result = TimingSafeOps::constant_time_select(&chars, 10);
    // モジュロで折り返す
    assert!(result.is_some());
}

#[test]
fn test_constant_time_compare() {
    assert!(TimingSafeOps::constant_time_compare("hello", "hello"));
    assert!(!TimingSafeOps::constant_time_compare("hello", "world"));
    assert!(!TimingSafeOps::constant_time_compare("hello", "hello!"));
}

#[test]
fn test_secure_random_index() {
    // rand::rng()がプロジェクト内で定義されている場合は適切にuseする必要あり
    use rust_unique_pass::crypto::rng::SecureRng;
    let rng = SecureRng::new().expect("Failed to create SecureRng");
    let mut rng = rng;

    // 複数回実行して範囲内であることを確認
    for _ in 0..100 {
        let index = TimingSafeOps::secure_random_index(&mut rng, 10);
        assert!(index < 10);
    }

    // バイアス検証
    // 簡易統計
    let mut counts = [0usize; 10];
    for _ in 0..10_000 {
        let idx = TimingSafeOps::secure_random_index(&mut rng, 10);
        counts[idx] += 1;
    }
    // 全てのインデックスが0でないこと
    // 極端なバイアスがないこと
    assert!(counts.iter().all(|&c| c > 0));
}

#[test]
fn test_secure_shuffle() {
    let mut items = vec![1, 2, 3, 4, 5];
    let original = items.clone();
    use rust_unique_pass::crypto::rng::SecureRng;
    let rng = SecureRng::new().expect("Failed to create SecureRng");
    let mut rng = rng;

    TimingSafeOps::secure_shuffle(&mut items, &mut rng);

    // 要素が保持されていることを確認
    items.sort();
    assert_eq!(items, original);
}
