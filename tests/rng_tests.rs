use rust_unique_pass::{SecureRng, get_global_rng};

type TestResult<T> = std::result::Result<T, String>;

#[tokio::test]
async fn test_secure_rng_initialization() -> TestResult<()> {
    let _rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    Ok(())
}

#[tokio::test]
async fn test_generate_bytes() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    let mut buffer = [0u8; 32];

    rng.generate_bytes(&mut buffer)
        .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    Ok(())
}

#[tokio::test]
async fn test_reseed() -> TestResult<()> {
    let rng = SecureRng::new().map_err(|e| format!("SecureRng::new failed: {e:?}"))?;
    rng.reseed().map_err(|e| format!("reseed failed: {e:?}"))?;
    Ok(())
}

#[tokio::test]
async fn test_global_rng_basic() -> TestResult<()> {
    let global_rng = get_global_rng().map_err(|e| format!("get_global_rng failed: {e:?}"))?;

    let mut buffer = [0u8; 32];
    global_rng
        .generate_bytes(&mut buffer)
        .map_err(|e| format!("generate_bytes failed: {e:?}"))?;
    Ok(())
}
