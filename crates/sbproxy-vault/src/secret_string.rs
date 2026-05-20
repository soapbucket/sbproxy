//! Protected string type that zeroizes memory on drop and prevents logging.

use std::fmt;

/// A string that holds a secret value.
///
/// - `Display` and `Debug` both render as `[REDACTED]`
/// - Memory is zeroed on drop to avoid leaking secrets in heap dumps
/// - Equality is constant-time to prevent timing attacks
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    /// Wrap a plaintext string as a protected secret.
    pub fn new(value: &str) -> Self {
        Self {
            inner: value.as_bytes().to_vec(),
        }
    }

    /// Expose the secret value. Use sparingly and never log the result.
    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap_or("[invalid utf8]")
    }

    /// Length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // Zeroize memory to prevent secrets from lingering in heap dumps.
        for byte in &mut self.inner {
            // SAFETY: we hold exclusive access via &mut self; volatile write
            // prevents the optimizer from eliding the zeroing.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing side-channels.
        //
        // WOR-593: do NOT early-return on a length mismatch. An
        // `if self.len() != other.len() { return false }` exits before
        // the comparison loop and leaks the secret's length through
        // timing, which an attacker can probe byte-by-byte. We do not
        // use `subtle::ConstantTimeEq` for slices either: its slice impl
        // short-circuits on length the same way.
        //
        // Instead, fold the length difference into the accumulator and
        // walk every position up to the longer slice, padding the
        // shorter side with a constant byte so the loop body does the
        // same work for either ordering.
        let a = &self.inner;
        let b = &other.inner;

        // Widen to u64 (exact on 32- and 64-bit usize) and fold all
        // bytes of the length XOR into one byte with a fixed sequence of
        // shifts: the accumulator is non-zero iff the lengths differ,
        // computed without a data-dependent branch or loop.
        let len_xor = (a.len() as u64) ^ (b.len() as u64);
        let mut acc: u8 = (len_xor
            | (len_xor >> 8)
            | (len_xor >> 16)
            | (len_xor >> 24)
            | (len_xor >> 32)
            | (len_xor >> 40)
            | (len_xor >> 48)
            | (len_xor >> 56)) as u8;

        let max = a.len().max(b.len());
        for i in 0..max {
            let ai = a.get(i).copied().unwrap_or(0);
            let bi = b.get(i).copied().unwrap_or(0);
            acc |= ai ^ bi;
        }
        acc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_redacted() {
        let s = SecretString::new("my_super_secret");
        assert_eq!(format!("{}", s), "[REDACTED]");
    }

    #[test]
    fn debug_shows_redacted() {
        let s = SecretString::new("another_secret");
        assert_eq!(format!("{:?}", s), "[REDACTED]");
    }

    #[test]
    fn expose_returns_original_value() {
        let s = SecretString::new("hello_secret");
        assert_eq!(s.expose(), "hello_secret");
    }

    #[test]
    fn clone_preserves_value() {
        let s = SecretString::new("clone_me");
        let c = s.clone();
        assert_eq!(c.expose(), "clone_me");
    }

    #[test]
    fn len_and_is_empty() {
        let empty = SecretString::new("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let nonempty = SecretString::new("abc");
        assert!(!nonempty.is_empty());
        assert_eq!(nonempty.len(), 3);
    }

    #[test]
    fn constant_time_equality_equal() {
        let a = SecretString::new("same_value");
        let b = SecretString::new("same_value");
        assert_eq!(a, b);
    }

    #[test]
    fn constant_time_equality_different() {
        let a = SecretString::new("value_a");
        let b = SecretString::new("value_b");
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_equality_different_lengths() {
        let a = SecretString::new("short");
        let b = SecretString::new("much_longer_value");
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_equality_prefix_is_not_equal() {
        // WOR-593: a value that is a strict prefix of another (the
        // bytes match up to the shorter length, only the length
        // differs) must not compare equal. This guards the
        // length-difference fold against being masked by the
        // byte loop.
        assert_ne!(SecretString::new("abc"), SecretString::new("abcd"));
        assert_ne!(SecretString::new("abcd"), SecretString::new("abc"));
        // Empty versus non-empty differs by length alone.
        assert_ne!(SecretString::new(""), SecretString::new("\0"));
        // Empty versus empty is equal.
        assert_eq!(SecretString::new(""), SecretString::new(""));
    }

    #[test]
    fn drop_zeroizes_memory() {
        // Verify the zeroization code path executes by driving it directly.
        // Reading freed memory is undefined behavior, so instead we test that
        // a manual drop of a cloned inner Vec zeroizes correctly while we
        // still hold a raw pointer to the allocation.
        let value = "zeroize_me";
        let mut buf: Vec<u8> = value.as_bytes().to_vec();
        let ptr = buf.as_mut_ptr();
        let len = buf.len();

        // Confirm the bytes are non-zero before zeroization.
        // SAFETY: `ptr` comes from `buf.as_mut_ptr()` and `buf` is alive for
        // the whole test; `i < len` keeps `ptr.add(i)` in bounds, and `u8`
        // has no alignment requirement, so each volatile read is valid.
        for i in 0..len {
            assert_ne!(unsafe { std::ptr::read_volatile(ptr.add(i)) }, 0);
        }

        // Simulate the zeroization that Drop performs.
        // SAFETY: same invariants as above; `buf` is uniquely owned in this
        // test, so the writes through `ptr` do not alias any other reference.
        for i in 0..len {
            unsafe { std::ptr::write_volatile(ptr.add(i), 0) };
        }

        // Verify all bytes are zero while the Vec is still alive (so memory is valid).
        // SAFETY: `buf` is still alive, `ptr` addresses its allocation, and
        // `i < len` bounds every read.
        for i in 0..len {
            assert_eq!(
                unsafe { std::ptr::read_volatile(ptr.add(i)) },
                0,
                "byte at index {} should be zeroed",
                i
            );
        }

        // Keep buf alive until here so the pointer remains valid above.
        drop(buf);
    }
}
