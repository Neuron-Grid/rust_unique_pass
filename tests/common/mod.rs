use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rust_unique_pass::{ByteStream, Result};
use zeroize::{Zeroize, Zeroizing};

const TEST_STREAM_BLOCK_SIZE: usize = 256;

pub struct DeterministicByteStream {
    rng: ChaCha8Rng,
    cache: Zeroizing<[u8; TEST_STREAM_BLOCK_SIZE]>,
    cursor: usize,
    available: usize,
}

impl DeterministicByteStream {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha8Rng::from_seed(seed),
            cache: Zeroizing::new([0u8; TEST_STREAM_BLOCK_SIZE]),
            cursor: 0,
            available: 0,
        }
    }
}

impl ByteStream for DeterministicByteStream {
    fn fill_next_block(&mut self) -> Result<()> {
        self.rng.fill_bytes(self.cache.as_mut());
        self.cursor = 0;
        self.available = self.cache.len();
        Ok(())
    }

    fn remaining_bytes(&self) -> &[u8] {
        let end = self
            .cursor
            .saturating_add(self.available)
            .min(self.cache.len());
        &self.cache[self.cursor..end]
    }

    fn consume(&mut self, n: usize) {
        let take = n.min(self.available);
        self.cursor = (self.cursor + take).min(self.cache.len());
        self.available = self.available.saturating_sub(take);
        if self.available == 0 {
            self.cursor = 0;
        }
    }
}

impl Drop for DeterministicByteStream {
    fn drop(&mut self) {
        self.cache.as_mut().zeroize();
        self.cursor = 0;
        self.available = 0;
    }
}
