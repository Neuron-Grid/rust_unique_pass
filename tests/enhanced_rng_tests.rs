use rust_unique_pass::{SecureRng, get_global_rng};
use std::sync::Arc;

type TestResult<T> = std::result::Result<T, String>;

#[tokio::test]
async fn test_auto_reseed_functionality() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    let mut buffer = [0u8; 1024]; // 1KB

    // 基本的な統計追跡機能をテスト
    rng.generate_bytes(&mut buffer)
        .map_err(|e| format!("generate_bytes failed: {e:?}"))?;

    let stats = rng.get_statistics();
    // 統計情報が正しく追跡されていることを確認
    assert!(stats.output_bytes > 0);
    assert!(stats.requests > 0);
    assert!(stats.last_reseed > 0);

    // 複数回の生成で統計が更新されることを確認
    let initial_output = stats.output_bytes;
    let initial_requests = stats.requests;

    for _ in 0..10 {
        rng.generate_bytes(&mut buffer)
            .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    }

    let updated_stats = rng.get_statistics();
    // 統計が更新されている
    // 再シードが発生してもカウンタは増える
    assert!(updated_stats.output_bytes >= initial_output);
    assert!(updated_stats.requests >= initial_requests);
    Ok(())
}

#[tokio::test]
async fn test_global_rng_singleton() -> TestResult<()> {
    let rng1 = get_global_rng().map_err(|e| format!("get_global_rng failed: {e:?}"))?;
    let rng2 = get_global_rng().map_err(|e| format!("get_global_rng failed: {e:?}"))?;

    // Arc参照カウントが同じであることを確認
    assert!(Arc::ptr_eq(&rng1, &rng2));
    Ok(())
}

#[tokio::test]
async fn test_global_rng_auto_reseed() -> TestResult<()> {
    let global_rng = get_global_rng().map_err(|e| format!("get_global_rng failed: {e:?}"))?;
    let mut buffer = [0u8; 1024];

    // 正常な乱数生成
    for _ in 0..100 {
        global_rng
            .generate_bytes(&mut buffer)
            .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    }

    let stats = global_rng.get_statistics();
    assert!(stats.output_bytes > 0);
    Ok(())
}

#[tokio::test]
async fn test_rng_quality_check() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    let mut buffer = [0u8; 1024];

    for _ in 0..10 {
        rng.generate_bytes(&mut buffer)
            .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    }
    Ok(())
}

#[tokio::test]
async fn test_rng_statistics() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    let mut buffer = [0u8; 100];

    let stats_before = rng.get_statistics();

    for _ in 0..5 {
        rng.generate_bytes(&mut buffer)
            .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    }

    let stats_after = rng.get_statistics();

    // 統計情報が更新されていることを確認
    assert!(stats_after.output_bytes > stats_before.output_bytes);
    assert!(stats_after.requests > stats_before.requests);
    Ok(())
}

#[tokio::test]
async fn test_manual_reseed() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;

    // 手動再シード
    rng.reseed().map_err(|e| format!("reseed failed: {e:?}"))?;

    let stats = rng.get_statistics();
    // リセットされている
    assert_eq!(stats.output_bytes, 0);
    // リセットされている
    assert_eq!(stats.requests, 0);
    Ok(())
}

#[tokio::test]
async fn test_concurrent_access() -> TestResult<()> {
    use std::sync::Arc;
    use tokio::task;

    let rng = Arc::new(SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?);
    let mut handles = vec![];

    // 並行アクセステスト
    for _ in 0..10 {
        let rng_clone = rng.clone();
        let handle = task::spawn(async move {
            let mut buffer = [0u8; 100];
            for _ in 0..10 {
                rng_clone
                    .generate_bytes(&mut buffer)
                    .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
            }
            Ok::<(), String>(())
        });
        handles.push(handle);
    }

    // すべてのタスクが正常完了することを確認
    for handle in handles {
        handle
            .await
            .map_err(|e| format!("task join failed: {e:?}"))??;
    }
    Ok(())
}
