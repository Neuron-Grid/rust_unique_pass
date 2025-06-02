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
use std::alloc::{Layout, alloc, dealloc};
use std::pin::Pin;
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

/// プラットフォーム固有のメモリ保護機能を提供
struct MemoryProtector;

impl MemoryProtector {
    /// メモリをロックしてスワップを防ぐ
    #[inline]
    fn lock_memory(ptr: *mut u8, size: usize) -> Result<(), String> {
        #[cfg(unix)]
        {
            use libc::mlock;
            unsafe {
                if mlock(ptr as *mut _, size) != 0 {
                    return Err("mlock failed".to_string());
                }
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualLock;
            unsafe {
                if VirtualLock(ptr as *mut _, size) == 0 {
                    return Err("VirtualLock failed".to_string());
                }
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            // メモリロックはサポートされていないが、エラーにはしない
            Ok(())
        }
    }

    /// メモリロックを解除
    #[inline]
    fn unlock_memory(ptr: *mut u8, size: usize) -> Result<(), String> {
        #[cfg(unix)]
        {
            use libc::munlock;
            unsafe {
                if munlock(ptr as *mut _, size) != 0 {
                    return Err("munlock failed".to_string());
                }
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            unsafe {
                if VirtualUnlock(ptr as *mut _, size) == 0 {
                    return Err("VirtualUnlock failed".to_string());
                }
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }
    }

    /// 追加のメモリ保護（コアダンプ除外など）
    #[inline]
    fn additional_protection(_ptr: *mut u8, _size: usize) -> Result<(), String> {
        #[cfg(all(unix, target_os = "linux"))]
        {
            use libc::madvise;
            const MADV_DONTDUMP: i32 = 16;
            unsafe {
                if madvise(_ptr as *mut _, _size, MADV_DONTDUMP) != 0 {
                    // 警告だけで続行
                    return Err("madvise failed (non-critical)".to_string());
                }
            }
        }
        Ok(())
    }
}

/// セキュアメモリアロケータ
/// メモリロックとゼロ化を自動的に行うセキュアなメモリ管理を提供します。
pub struct SecureMemory<T> {
    ptr: *mut T,
    len: usize,
    layout: Layout,
}

impl<T> SecureMemory<T> {
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

        let layout = Layout::array::<T>(len)
            .map_err(|_| CryptoError::MemoryError("Layout error".to_string()))?;

        let ptr = unsafe {
            let ptr = alloc(layout) as *mut T;
            if ptr.is_null() {
                return Err(CryptoError::MemoryError(
                    "Memory allocation failed".to_string(),
                ));
            }

            // メモリをゼロクリア
            ptr::write_bytes(ptr, 0, len);

            // メモリロック（スワップ防止）
            if let Err(e) = MemoryProtector::lock_memory(ptr as *mut u8, layout.size()) {
                dealloc(ptr as *mut u8, layout);
                return Err(CryptoError::MemoryError(format!(
                    "Memory protection failed: {}",
                    e
                )));
            }

            // 追加の保護（コアダンプ除外など）
            if let Err(e) = MemoryProtector::additional_protection(ptr as *mut u8, layout.size()) {
                // 追加保護の失敗は警告レベル、続行可能
                eprintln!("Warning: Additional memory protection failed: {}", e);
            }

            ptr
        };

        Ok(Self { ptr, len, layout })
    }

    /// スライスとしてアクセス
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// 可変スライスとしてアクセス
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        unsafe {
            // メモリ内容の安全な消去
            ptr::write_bytes(self.ptr, 0, self.len);

            // メモリロック解除
            if let Err(e) = MemoryProtector::unlock_memory(self.ptr as *mut u8, self.layout.size())
            {
                // ロック解除の失敗は警告レベル
                eprintln!("Warning: Memory unlock failed: {}", e);
            }

            // メモリ解放
            dealloc(self.ptr as *mut u8, self.layout);
        }
    }
}

// Sendを安全に実装
// Tに依存
unsafe impl<T: Send> Send for SecureMemory<T> {}

/// パスワード用のセキュアな文字列型
/// 自動的にゼロ化され、メモリロックされた文字列を提供します。
pub struct SecureString {
    data: Pin<Box<SecureMemory<u8>>>,
    len: usize,
}

impl SecureString {
    /// 通常の文字列からセキュア文字列を作成
    pub fn new(s: &str) -> CryptoResult<Self> {
        let bytes = s.as_bytes();
        let mut memory = Box::pin(SecureMemory::<u8>::new(bytes.len())?);

        // 安全なコピー
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), memory.as_mut().get_mut().ptr, bytes.len());
        }

        Ok(Self {
            data: memory,
            len: bytes.len(),
        })
    }

    /// 空のセキュア文字列を作成
    pub fn with_capacity(capacity: usize) -> CryptoResult<Self> {
        let memory = Box::pin(SecureMemory::<u8>::new(capacity)?);

        Ok(Self {
            data: memory,
            len: 0,
        })
    }

    /// 文字列として参照
    pub fn as_str(&self) -> &str {
        let slice = &self.data.as_slice()[..self.len];
        std::str::from_utf8(slice).expect("Valid UTF-8")
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
        self.data.len
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // 明示的なゼロ化
        // SecureMemoryのDropでも行われるが、二重に保護
        if self.len > 0 {
            let slice = unsafe { std::slice::from_raw_parts_mut(self.data.ptr, self.len) };
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

/// セキュアなバッファ
/// 一時的なデータ保存用のセキュアバッファを提供します。
pub struct SecureBuffer {
    memory: Zeroizing<Vec<u8>>,
}

impl SecureBuffer {
    /// 新しいセキュアバッファを作成
    pub fn new(size: usize) -> Self {
        Self {
            memory: Zeroizing::new(vec![0u8; size]),
        }
    }

    /// バッファの内容をコピー
    pub fn copy_from_slice(&mut self, data: &[u8]) -> CryptoResult<()> {
        if data.len() > self.memory.len() {
            return Err(CryptoError::MemoryError("Buffer size exceeded".to_string()));
        }

        self.memory[..data.len()].copy_from_slice(data);
        Ok(())
    }

    /// バッファのスライスを取得
    pub fn as_slice(&self) -> &[u8] {
        &self.memory
    }

    /// バッファの可変スライスを取得
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.memory
    }

    /// バッファをクリア
    pub fn clear(&mut self) {
        self.memory.zeroize();
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

    /// メモリバリアを設定
    #[inline(always)]
    pub fn memory_barrier() {
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// セキュアなメモリ比較
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if a.len() != b.len() {
            return false;
        }

        a.ct_eq(b).unwrap_u8() == 1
    }
}

/// セキュアな一時変数
/// スコープを抜ける際に自動的にゼロ化される変数を提供します。
pub struct SecureTemp<T: Zeroize> {
    value: Option<T>,
}

impl<T: Zeroize> SecureTemp<T> {
    pub fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }

    pub fn take(&mut self) -> Option<T> {
        self.value.take()
    }
}

impl<T: Zeroize> Drop for SecureTemp<T> {
    fn drop(&mut self) {
        if let Some(mut val) = self.value.take() {
            val.zeroize();
        }
    }
}
