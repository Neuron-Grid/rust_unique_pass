// src/crypto/secure_memory.rs のテストを分離

use rust_unique_pass::crypto::secure_memory::*;

#[test]
fn test_secure_string_creation() {
    let secure = SecureString::new("test password").unwrap();
    assert_eq!(secure.len(), 13);
    assert_eq!(secure.as_str(), "test password");
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
