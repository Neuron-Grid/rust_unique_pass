use super::*;
use rand::RngCore;
use std::cell::Cell;
use std::time::Duration;
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

struct SequenceClock {
    timeline: Vec<Duration>,
    cursor: Cell<usize>,
}

impl SequenceClock {
    fn new(timeline: Vec<Duration>) -> Self {
        Self {
            timeline,
            cursor: Cell::new(0),
        }
    }
}

impl Clock for SequenceClock {
    fn now(&self) -> Duration {
        let index = self.cursor.get();
        self.cursor.set(index.saturating_add(1));
        match self.timeline.get(index).copied() {
            Some(t) => t,
            None => self.timeline.last().copied().unwrap_or(Duration::ZERO),
        }
    }
}

struct SequenceEvaluator {
    sequence: Vec<(u8, f64)>,
    calls: Cell<usize>,
}

impl SequenceEvaluator {
    fn new(sequence: Vec<(u8, f64)>) -> Self {
        Self {
            sequence,
            calls: Cell::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.get()
    }
}

impl PasswordStrengthEvaluator for SequenceEvaluator {
    fn score_entropy(&self, _pwd: &str) -> Result<(u8, f64)> {
        let index = self.calls.get();
        self.calls.set(index.saturating_add(1));
        let pos = index.min(self.sequence.len().saturating_sub(1));
        Ok(self.sequence.get(pos).copied().unwrap_or((0, 0.0)))
    }
}

fn run_strength_search_with_clock(
    rng: &mut impl RngCore,
    clock: &impl Clock,
    evaluator: &dyn PasswordStrengthEvaluator,
    timeout_ms: u64,
    min_score: u8,
    strict: bool,
) -> Result<GenerationOutcome> {
    let stream = DeterministicByteStream::new(rng);
    let mut sampler = StreamingIndexSampler::new(stream);
    let all_vec: Vec<char> = "AbCdef0123456789!@#$".chars().collect();
    let req = vec![vec!['A'], vec!['b']];
    let config = StrengthSearchConfig {
        all_vec: &all_vec,
        req: &req,
        len: 15,
        timeout_ms,
        min_score,
        strict,
    };

    produce_password_within_time_sync_with_sampler_and_clock(
        &mut sampler,
        &config,
        evaluator,
        clock,
    )
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

#[test]
fn timeout_budget_limits_evaluator_invocations() -> std::result::Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::from_seed([0x43; 32]);
    let evaluator = SequenceEvaluator::new(vec![(0, 12.0)]);
    let clock = SequenceClock::new(vec![Duration::from_millis(0), Duration::from_millis(1)]);

    let outcome = run_strength_search_with_clock(&mut rng, &clock, &evaluator, 0, 4, false)
        .map_err(|e| format!("search failed: {e}"))?;

    assert_eq!(evaluator.call_count(), 1);
    assert_eq!(outcome.score, 0);
    assert!(!outcome.reached_target);
    Ok(())
}

#[test]
fn strict_mode_keeps_contract_when_budget_expires() -> std::result::Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::from_seed([0x44; 32]);
    let evaluator = SequenceEvaluator::new(vec![(0, 8.0)]);
    let clock = SequenceClock::new(vec![Duration::from_millis(0), Duration::from_millis(1)]);

    let result = run_strength_search_with_clock(&mut rng, &clock, &evaluator, 0, 4, true);
    assert_eq!(evaluator.call_count(), 1);
    match result {
        Err(GenerationError::StrictTargetUnmet) => Ok(()),
        Err(other) => Err(format!("unexpected error: {other}")),
        Ok(_) => Err("strict mode should fail when target is unmet".to_string()),
    }
}

#[test]
fn best_candidate_prefers_higher_entropy_on_same_score() -> std::result::Result<(), String> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::from_seed([0x45; 32]);
    let evaluator = SequenceEvaluator::new(vec![(2, 10.0), (2, 40.0)]);
    let clock = SequenceClock::new(vec![
        Duration::from_millis(0),
        Duration::from_millis(0),
        Duration::from_millis(0),
        Duration::from_millis(1),
    ]);

    let outcome = run_strength_search_with_clock(&mut rng, &clock, &evaluator, 1, 4, false)
        .map_err(|e| format!("search failed: {e}"))?;

    assert_eq!(evaluator.call_count(), 2);
    assert_eq!(outcome.score, 2);
    assert!((outcome.entropy_bits - 40.0).abs() < 0.0001);
    assert!(!outcome.reached_target);
    Ok(())
}
