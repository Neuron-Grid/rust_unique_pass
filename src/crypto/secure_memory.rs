/* Copyright 2023-2025 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

/// # Secure Memory モジュール
/// 本モジュールはパスワードや秘密鍵などの機密データを安全にメモリ上で管理するための各種型・関数を提供します。
/// - メモリロック（mlock/VirtualLock）によるスワップ防止
/// - コアダンプ除外（Linux madvise）
/// - 自動ゼロ化（drop時）
/// - セキュアなバッファ・文字列型
/// ## セキュリティ設計方針
/// - 機密データは常にロック・ゼロ化・除外処理を徹底
/// - OSごとの最適な保護APIを利用
/// - エラー時は詳細な情報を返却
///
use super::{CryptoError, CryptoResult};
use std::alloc::Layout;
use std::io;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// プラットフォーム固有のメモリ保護機能を提供
struct MemoryProtector;

impl MemoryProtector {
    /// メモリをロックしてスワップを防ぐ
    #[inline]
    fn lock_memory(buffer: &mut [u8]) -> Result<(), String> {
        if buffer.is_empty() {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len();
            // SAFETY:
            // - `ptr` は `buffer` の有効な先頭ポインタ
            // - `len` は `buffer` の実長で、呼び出し中は生存している
            // - C API は読み書きせず、ページロックを設定するだけ
            let result = unsafe { libc::mlock(ptr, len) };
            if result != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualLock;
            let ptr = buffer.as_mut_ptr() as *mut core::ffi::c_void;
            let len = buffer.len();
            // SAFETY:
            // - `ptr` は `buffer` の有効な先頭ポインタ
            // - `len` は `buffer` の実長で、呼び出し中は生存している
            // - Win32 API の契約に従い、メモリロック設定のみを行う
            let ok = unsafe { VirtualLock(ptr, len) };
            if ok == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            // メモリロック非対応OSではベストエフォートで処理継続
            return Ok(());
        }

        Ok(())
    }

    /// メモリロックを解除
    #[inline]
    fn unlock_memory(buffer: &mut [u8]) -> Result<(), String> {
        if buffer.is_empty() {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len();
            // SAFETY:
            // - `ptr` は `buffer` の有効な先頭ポインタ
            // - `len` は `buffer` の実長で、呼び出し中は生存している
            // - C API はロック解除のメタデータ更新のみを行う
            let result = unsafe { libc::munlock(ptr, len) };
            if result != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            let ptr = buffer.as_mut_ptr() as *mut core::ffi::c_void;
            let len = buffer.len();
            // SAFETY:
            // - `ptr` は `buffer` の有効な先頭ポインタ
            // - `len` は `buffer` の実長で、呼び出し中は生存している
            // - Win32 API の契約に従い、メモリロック解除のみを行う
            let ok = unsafe { VirtualUnlock(ptr, len) };
            if ok == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            return Ok(());
        }

        Ok(())
    }

    /// 追加のメモリ保護
    /// コアダンプ除外など
    #[inline]
    fn additional_protection(buffer: &mut [u8]) -> Result<(), String> {
        if buffer.is_empty() {
            return Ok(());
        }

        #[cfg(all(unix, target_os = "linux"))]
        {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len();
            // SAFETY:
            // - `ptr` は `buffer` の有効な先頭ポインタ
            // - `len` は `buffer` の実長で、呼び出し中は生存している
            // - `madvise` には DONTDUMP ヒントのみを渡す
            let result = unsafe { libc::madvise(ptr, len, libc::MADV_DONTDUMP) };
            if result != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }

        Ok(())
    }
}

/// メモリ保護の状態を呼び出し元に通知するためのレポート。
#[derive(Debug, Clone)]
pub struct MemoryProtectionStatus {
    additional_protection_error: Option<String>,
}

impl MemoryProtectionStatus {
    pub fn additional_protection_error(&self) -> Option<&str> {
        self.additional_protection_error.as_deref()
    }
}

/// セキュアメモリアロケータ
/// ゼロ化とプラットフォーム保護を自動的に行うセキュアなメモリ管理を提供します。
pub struct SecureMemory {
    data: Vec<u8>,
    protection: MemoryProtectionStatus,
}

impl SecureMemory {
    /// 新しいセキュアメモリを割り当てる
    /// - メモリロック（mlock/VirtualLock）でスワップ防止
    /// - Linuxではmadviseでコアダンプ除外
    /// - 割り当て直後にゼロクリア
    /// - エラー時は詳細な情報を返却
    pub fn new(len: usize) -> CryptoResult<Self> {
        if len == 0 {
            return Err(CryptoError::MemoryError(
                "Zero-length memory allocation".to_string(),
            ));
        }

        Layout::array::<u8>(len)
            .map_err(|_| CryptoError::MemoryError("Layout error".to_string()))?;

        let mut data = Vec::new();
        if data.try_reserve_exact(len).is_err() {
            return Err(CryptoError::MemoryError(
                "Memory allocation failed".to_string(),
            ));
        }
        data.resize(len, 0u8);

        if let Err(e) = MemoryProtector::lock_memory(&mut data) {
            return Err(CryptoError::MemoryError(format!(
                "Memory protection failed: {e}"
            )));
        }

        let additional_protection_error = MemoryProtector::additional_protection(&mut data).err();

        Ok(Self {
            data,
            protection: MemoryProtectionStatus {
                additional_protection_error,
            },
        })
    }

    /// スライスとしてアクセス
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// 可変スライスとしてアクセス
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// 確保済みのバッファ長を返却
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 空かどうかを返却
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 容量を取得
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// 追加保護の状態を取得
    pub fn protection_status(&self) -> &MemoryProtectionStatus {
        &self.protection
    }

    /// 明示的にメモリロック解除を試みる
    pub fn try_unlock(&mut self) -> CryptoResult<()> {
        MemoryProtector::unlock_memory(&mut self.data)
            .map_err(|e| CryptoError::MemoryError(format!("Memory unlock failed: {e}")))
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        self.data.zeroize();

        let _ = MemoryProtector::unlock_memory(&mut self.data);
    }
}

/// パスワード用のセキュアな文字列型
/// 自動的にゼロ化され、メモリロックされた文字列を提供します。
pub struct SecureString {
    data: SecureMemory,
    len: usize,
}

impl SecureString {
    /// 通常の文字列からセキュア文字列を作成
    pub fn new(s: &str) -> CryptoResult<Self> {
        let bytes = s.as_bytes();
        let mut memory = SecureMemory::new(bytes.len())?;
        memory.as_mut_slice().copy_from_slice(bytes);

        Ok(Self {
            data: memory,
            len: bytes.len(),
        })
    }

    /// 空のセキュア文字列を作成
    pub fn with_capacity(capacity: usize) -> CryptoResult<Self> {
        let memory = SecureMemory::new(capacity)?;

        Ok(Self {
            data: memory,
            len: 0,
        })
    }

    /// 文字列として参照
    /// # Returns
    /// 内部データが有効なUTF-8の場合、文字列スライスを返します。
    /// 無効なUTF-8の場合、`None`を返します。
    ///
    /// # Notes
    /// より厳密なエラーハンドリングが必要な場合は`try_as_str()`を使用してください。
    pub fn as_str(&self) -> Option<&str> {
        let slice = &self.data.as_slice()[..self.len];
        std::str::from_utf8(slice).ok()
    }

    /// 文字列として安全に参照
    pub fn try_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        let slice = &self.data.as_slice()[..self.len];
        std::str::from_utf8(slice)
    }

    /// 内部の長さを取得
    pub fn len(&self) -> usize {
        self.len
    }

    /// 空かどうかをチェック
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 容量を取得
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        if self.len > 0 {
            let slice = &mut self.data.as_mut_slice()[..self.len];
            slice.zeroize();
        }
    }
}

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // セキュリティのため、内容を表示しない
        write!(f, "SECURE STRING: {} bytes", self.len)
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // セキュリティのため、内容を表示しない
        f.debug_struct("SecureString")
            .field("len", &self.len)
            .field("capacity", &self.capacity())
            .finish()
    }
}

/// メモリ保護ユーティリティ
pub struct MemoryProtection;

impl MemoryProtection {
    /// スタック上の変数を安全にクリア
    #[inline(always)]
    pub fn secure_clear<T: Zeroize>(data: &mut T) {
        data.zeroize();

        // コンパイラの最適化を防ぐ
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// セキュアなメモリ比較
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        let len = a.len().max(b.len());
        let mut result = Choice::from(1u8);

        result &= a.len().ct_eq(&b.len());

        for i in 0..len {
            let a_byte = if i < a.len() { a[i] } else { 0 };
            let b_byte = if i < b.len() { b[i] } else { 0 };
            result &= a_byte.ct_eq(&b_byte);
        }

        result.unwrap_u8() == 1
    }
}
