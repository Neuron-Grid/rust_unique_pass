use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rust_unique_pass::TimingSafeOps;

type TestResult<T> = std::result::Result<T, String>;

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
fn test_secure_random_index() -> TestResult<()> {
    // rand::rng()がプロジェクト内で定義されている場合は適切にuseする必要あり
    let mut rng = ChaCha8Rng::from_seed([0x44; 32]);

    // 複数回実行して範囲内であることを確認
    for _ in 0..100 {
        let index = TimingSafeOps::secure_random_index(&mut rng, 10)
            .map_err(|e| format!("secure_random_index failed: {e}"))?;
        assert!(index < 10);
    }

    // バイアス検証
    // 簡易統計
    let mut counts = [0usize; 10];
    for _ in 0..10_000 {
        let idx = TimingSafeOps::secure_random_index(&mut rng, 10)
            .map_err(|e| format!("secure_random_index failed: {e}"))?;
        counts[idx] += 1;
    }
    // 全てのインデックスが0でないこと
    // 極端なバイアスがないこと
    assert!(counts.iter().all(|&c| c > 0));
    Ok(())
}

#[test]
fn test_secure_random_index_boundary_values() -> TestResult<()> {
    let mut rng = ChaCha8Rng::from_seed([0x46; 32]);
    let bounds = [
        1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
    ];

    for max in bounds {
        for _ in 0..512 {
            let index = TimingSafeOps::secure_random_index(&mut rng, max)
                .map_err(|e| format!("secure_random_index failed: {e}"))?;
            assert!(index < max);
        }
    }
    Ok(())
}

#[test]
fn test_secure_random_index_zero_max_returns_zero() -> TestResult<()> {
    let mut rng = ChaCha8Rng::from_seed([0x47; 32]);
    let index = TimingSafeOps::secure_random_index(&mut rng, 0)
        .map_err(|e| format!("secure_random_index failed: {e}"))?;
    assert_eq!(index, 0);
    Ok(())
}

#[test]
fn test_secure_shuffle() -> TestResult<()> {
    let mut items = vec![1, 2, 3, 4, 5];
    let original = items.clone();
    let mut rng = ChaCha8Rng::from_seed([0x45; 32]);

    TimingSafeOps::secure_shuffle(&mut items, &mut rng)
        .map_err(|e| format!("secure_shuffle failed: {e}"))?;

    // 要素が保持されていることを確認
    items.sort();
    assert_eq!(items, original);
    Ok(())
}
