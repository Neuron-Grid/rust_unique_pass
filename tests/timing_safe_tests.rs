// src/crypto/timing_safe.rs のテストを分離

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
    assert!(result.is_some()); // モジュロで折り返す
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
    let mut rng = rand::rng();

    // 複数回実行して範囲内であることを確認
    for _ in 0..100 {
        let index = TimingSafeOps::secure_random_index(&mut rng, 10);
        assert!(index < 10);
    }
}

#[test]
fn test_secure_shuffle() {
    let mut items = vec![1, 2, 3, 4, 5];
    let original = items.clone();
    let mut rng = rand::rng();

    SecureStringOps::secure_shuffle(&mut items, &mut rng);

    // 要素が保持されていることを確認
    items.sort();
    assert_eq!(items, original);
}
