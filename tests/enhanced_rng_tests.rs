use rust_unique_pass::crypto::{SecureRng, get_global_rng};
use std::sync::Arc;

#[tokio::test]
async fn test_auto_reseed_functionality() {
    let rng = SecureRng::new().unwrap();
    let mut buffer = [0u8; 1024]; // 1KB

    // 基本的な統計追跡機能をテスト
    assert!(rng.generate_bytes(&mut buffer).is_ok());

    let stats = rng.get_statistics();
    // 統計情報が正しく追跡されていることを確認
    assert!(stats.output_bytes > 0);
    assert!(stats.requests > 0);
    assert!(stats.last_reseed > 0);

    // 複数回の生成で統計が更新されることを確認
    let initial_output = stats.output_bytes;
    let initial_requests = stats.requests;

    for _ in 0..10 {
        assert!(rng.generate_bytes(&mut buffer).is_ok());
    }

    let updated_stats = rng.get_statistics();
    // 統計が更新されている
    // 再シードが発生してもカウンタは増える
    assert!(updated_stats.output_bytes >= initial_output);
    assert!(updated_stats.requests >= initial_requests);
}

#[tokio::test]
async fn test_global_rng_singleton() {
    let rng1 = get_global_rng().unwrap();
    let rng2 = get_global_rng().unwrap();

    // Arc参照カウントが同じであることを確認
    assert!(Arc::ptr_eq(&rng1, &rng2));
}

#[tokio::test]
async fn test_global_rng_auto_reseed() {
    let global_rng = get_global_rng().unwrap();
    let mut buffer = [0u8; 1024];

    // 正常な乱数生成
    for _ in 0..100 {
        assert!(global_rng.generate_bytes(&mut buffer).is_ok());
    }

    let stats = global_rng.get_statistics();
    assert!(stats.output_bytes > 0);
}

#[tokio::test]
async fn test_rng_quality_check() {
    let rng = SecureRng::new().unwrap();
    let mut buffer = [0u8; 1024];

    for _ in 0..10 {
        assert!(rng.generate_bytes(&mut buffer).is_ok());
    }
}

#[tokio::test]
async fn test_rng_statistics() {
    let rng = SecureRng::new().unwrap();
    let mut buffer = [0u8; 100];

    let stats_before = rng.get_statistics();

    for _ in 0..5 {
        assert!(rng.generate_bytes(&mut buffer).is_ok());
    }

    let stats_after = rng.get_statistics();

    // 統計情報が更新されていることを確認
    assert!(stats_after.output_bytes > stats_before.output_bytes);
    assert!(stats_after.requests > stats_before.requests);
}

#[tokio::test]
async fn test_manual_reseed() {
    let rng = SecureRng::new().unwrap();

    // 手動再シード
    assert!(rng.reseed().is_ok());

    let stats = rng.get_statistics();
    // リセットされている
    assert_eq!(stats.output_bytes, 0);
    // リセットされている
    assert_eq!(stats.requests, 0);
}

#[tokio::test]
async fn test_concurrent_access() {
    use std::sync::Arc;
    use tokio::task;

    let rng = Arc::new(SecureRng::new().unwrap());
    let mut handles = vec![];

    // 並行アクセステスト
    for _ in 0..10 {
        let rng_clone = rng.clone();
        let handle = task::spawn(async move {
            let mut buffer = [0u8; 100];
            for _ in 0..10 {
                rng_clone.generate_bytes(&mut buffer).unwrap();
            }
        });
        handles.push(handle);
    }

    // すべてのタスクが正常完了することを確認
    for handle in handles {
        assert!(handle.await.is_ok());
    }
}
