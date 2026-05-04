//! Thread-safe pool of reusable `BytesMut` buffers.
//!
//! Avoids repeated heap allocation for response body buffering by
//! recycling buffers through a bounded pool. When the pool is full,
//! returned buffers are simply dropped.

use bytes::BytesMut;
use std::sync::Mutex;

/// Thread-safe pool of reusable BytesMut buffers.
/// Avoids repeated heap allocation for response body buffering.
pub struct BufferPool {
    pool: Mutex<Vec<BytesMut>>,
    default_capacity: usize,
    max_pool_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool.
    ///
    /// `default_capacity` is the initial capacity of newly created buffers.
    /// `max_pool_size` is the maximum number of buffers kept in the pool.
    pub fn new(default_capacity: usize, max_pool_size: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(max_pool_size)),
            default_capacity,
            max_pool_size,
        }
    }

    /// Get a buffer from the pool or create a new one.
    ///
    /// Returned buffers are always empty (len == 0) but retain their
    /// allocated capacity for reuse.
    pub fn get(&self) -> BytesMut {
        self.pool
            .lock()
            .unwrap()
            .pop()
            .map(|mut buf| {
                buf.clear();
                buf
            })
            .unwrap_or_else(|| BytesMut::with_capacity(self.default_capacity))
    }

    /// Return a buffer to the pool for reuse.
    ///
    /// If the pool is already at capacity the buffer is silently dropped.
    pub fn put(&self, buf: BytesMut) {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_pool_size {
            pool.push(buf);
        }
        // else: drop the buffer (pool is full)
    }

    /// Number of buffers currently available in the pool.
    pub fn available(&self) -> usize {
        self.pool.lock().unwrap().len()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_buffer_with_correct_capacity() {
        let pool = BufferPool::new(4096, 8);
        let buf = pool.get();
        assert!(buf.capacity() >= 4096);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn put_then_get_reuses_buffer() {
        let pool = BufferPool::new(4096, 8);
        let mut buf = pool.get();
        buf.extend_from_slice(b"hello");
        let ptr = buf.as_ptr();
        pool.put(buf);

        let reused = pool.get();
        // Buffer should be cleared but reuse the same allocation.
        assert_eq!(reused.len(), 0);
        assert_eq!(reused.as_ptr(), ptr);
    }

    #[test]
    fn pool_does_not_exceed_max_pool_size() {
        let pool = BufferPool::new(64, 2);
        pool.put(BytesMut::with_capacity(64));
        pool.put(BytesMut::with_capacity(64));
        pool.put(BytesMut::with_capacity(64)); // Should be dropped.
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn cleared_buffer_has_len_zero() {
        let pool = BufferPool::new(128, 4);
        let mut buf = pool.get();
        buf.extend_from_slice(b"some data that should be cleared");
        pool.put(buf);

        let reused = pool.get();
        assert_eq!(reused.len(), 0);
    }
}
