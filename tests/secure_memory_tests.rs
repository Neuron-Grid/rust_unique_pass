// src/crypto/secure_memory.rs のテストを分離

use rust_unique_pass::crypto::secure_memory::*;

#[test]
fn test_secure_string_creation() {
    let secure = SecureString::new("test password").unwrap();
    assert_eq!(secure.len(), 13);
    assert_eq!(secure.as_str(), "test password");
}

#[test]
fn test_secure_buffer() {
    let mut buffer = SecureBuffer::new(32);
    let data = b"sensitive data";

    buffer.copy_from_slice(data).unwrap();
    assert_eq!(&buffer.as_slice()[..data.len()], data);

    buffer.clear();
    assert!(buffer.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn test_secure_temp() {
    let mut temp = SecureTemp::new(vec![1u8, 2, 3, 4, 5]);

    assert_eq!(temp.get(), Some(&vec![1u8, 2, 3, 4, 5]));

    let taken = temp.take();
    assert_eq!(taken, Some(vec![1u8, 2, 3, 4, 5]));
    assert!(temp.get().is_none());
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
