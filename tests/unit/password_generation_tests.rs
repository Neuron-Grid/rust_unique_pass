use super::*;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

const TEST_STREAM_BLOCK_SIZE: usize = 256;

struct DeterministicOutcome {
    password: String,
    swap_count: usize,
    bytes_consumed: usize,
}

struct DeterministicByteStream<'a, R: RngCore> {
    rng: &'a mut R,
    cache: Zeroizing<[u8; TEST_STREAM_BLOCK_SIZE]>,
    cursor: usize,
    available: usize,
    bytes_consumed: usize,
}

impl<'a, R: RngCore> DeterministicByteStream<'a, R> {
    fn new(rng: &'a mut R) -> Self {
        Self {
            rng,
            cache: Zeroizing::new([0u8; TEST_STREAM_BLOCK_SIZE]),
            cursor: 0,
            available: 0,
            bytes_consumed: 0,
        }
    }

    fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }
}

impl<R: RngCore> ByteStream for DeterministicByteStream<'_, R> {
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
        self.bytes_consumed += take;
        if self.available == 0 {
            self.cursor = 0;
        }
    }
}

impl<R: RngCore> Drop for DeterministicByteStream<'_, R> {
    fn drop(&mut self) {
        self.cache.as_mut().zeroize();
        self.cursor = 0;
        self.available = 0;
    }
}

fn assemble_random_password_with_rng(
    rng: &mut impl RngCore,
    all_vec: &[char],
    len: usize,
    req: &[Vec<char>],
) -> Result<Option<DeterministicOutcome>> {
    if all_vec.is_empty() {
        return Ok(None);
    }

    let stream = DeterministicByteStream::new(rng);
    let mut sampler = StreamingIndexSampler::new(stream);
    let mut swaps = 0usize;
    let password =
        assemble_random_password_internal(&mut sampler, all_vec, len, req, Some(&mut swaps))?;
    let StreamingIndexSampler { stream } = sampler;

    Ok(password.map(|password| DeterministicOutcome {
        password,
        swap_count: swaps,
        bytes_consumed: stream.bytes_consumed(),
    }))
}

#[test]
fn fisher_yates_executes_all_swaps() -> std::result::Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let all_vec: Vec<char> = (33u8..=126).map(char::from).collect();
    let req = vec![
        ('0'..='9').collect::<Vec<char>>(),
        ('A'..='Z').collect::<Vec<char>>(),
        ('a'..='z').collect::<Vec<char>>(),
        vec!['!', '@', '#', '$', '%', '^'],
    ];

    let mut rng = ChaCha8Rng::from_seed([0x42; 32]);
    let len = 32;

    let outcome = assemble_random_password_with_rng(&mut rng, &all_vec, len, &req)
        .map_err(|e| format!("password generation failed: {e:?}"))?
        .ok_or_else(|| "password generation returned None".to_string())?;

    assert_eq!(outcome.password.chars().count(), len);
    assert_eq!(outcome.swap_count, len.saturating_sub(1));
    assert!(outcome.bytes_consumed >= outcome.swap_count * std::mem::size_of::<u64>());
    Ok(())
}
