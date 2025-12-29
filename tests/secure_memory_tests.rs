// src/crypto/secure_memory.rs のテストを分離

use rust_unique_pass::{CryptoError, MemoryProtection, SecureMemory, SecureString};

type TestResult<T> = std::result::Result<T, String>;

#[test]
fn test_secure_string_creation() -> TestResult<()> {
    let secure =
        SecureString::new("test password").map_err(|e| format!("secure string failed: {e:?}"))?;
    assert_eq!(secure.len(), 13);
    assert_eq!(secure.as_str(), Some("test password"));
    Ok(())
}

#[test]
fn test_memory_protection() {
    let mut data = vec![1u8, 2, 3, 4, 5];
    MemoryProtection::secure_clear(&mut data);
    assert!(data.iter().all(|&b| b == 0));

    let a = b"hello";
    let b = b"hello";
    let c = b"world";

    assert!(MemoryProtection::secure_compare(a, b));
    assert!(!MemoryProtection::secure_compare(a, c));
}

#[test]
fn test_secure_memory_large_allocation_error() -> TestResult<()> {
    let result = SecureMemory::new(usize::MAX);

    match result {
        Err(CryptoError::MemoryError(message)) => {
            assert_eq!(message, "Layout error");
            Ok(())
        }
        Err(other) => Err(format!("unexpected CryptoError variant: {other:?}")),
        Ok(_) => Err("expected Err(CryptoError::MemoryError), got Ok".to_string()),
    }
}
