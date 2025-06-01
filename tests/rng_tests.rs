// src/crypto/rng.rs のテストを分離

use rust_unique_pass::crypto::rng::*;
use tokio;

#[tokio::test]
async fn test_secure_rng_initialization() {
    let rng = SecureRng::new();
    assert!(rng.is_ok());
}

#[tokio::test]
async fn test_generate_bytes() {
    let rng = SecureRng::new().unwrap();
    let mut buffer = [0u8; 32];

    let result = rng.generate_bytes(&mut buffer);
    assert!(result.is_ok());

    // 全てゼロでないことを確認
    assert!(buffer.iter().any(|&b| b != 0));
}

#[tokio::test]
async fn test_reseed() {
    let rng = SecureRng::new().unwrap();
    let result = rng.reseed().await;
    assert!(result.is_ok());
}
