use async_trait::async_trait;
use fluent::{FluentBundle, FluentResource};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rust_unique_pass::{
    GenerationError, PasswordStrengthEvaluator, Result, RupassArgs, UserInterface,
    generate_password_flow, generate_password_flow_with_evaluator,
};
use std::collections::VecDeque;

mod common;
use common::DeterministicByteStream;

// Mock evaluator for deterministic scenarios
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T> = std::result::Result<T, String>;

// Sequence of scores to return; last value repeats
struct MockEvaluator {
    seq: Vec<(u8, f64)>,
    idx: AtomicUsize,
}

impl MockEvaluator {
    fn new(seq: Vec<(u8, f64)>) -> Self {
        Self {
            seq,
            idx: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.idx.load(Ordering::Relaxed)
    }
}

impl PasswordStrengthEvaluator for MockEvaluator {
    fn score_entropy(&self, _pwd: &str) -> Result<(u8, f64)> {
        let i = self.idx.fetch_add(1, Ordering::Relaxed);
        let pos = i.min(self.seq.len().saturating_sub(1));
        Ok(self.seq[pos])
    }
}

// Lightweight UI mock to capture stdout lines
#[derive(Default)]
struct MockUI {
    inputs: VecDeque<String>,
}

impl MockUI {
    fn new(src: Vec<&str>) -> Self {
        Self {
            inputs: src.into_iter().map(String::from).collect(),
        }
    }
}

#[async_trait(?Send)]
impl UserInterface for MockUI {
    async fn prompt(&mut self, _msg: &str) -> Result<String> {
        self.inputs.pop_front().ok_or(GenerationError::InvalidInput)
    }
    async fn print(&mut self, msg: &str) -> Result<()> {
        let _ = msg;
        Ok(())
    }
}

// Use embedded English FTL for bundle
fn mock_bundle() -> TestResult<FluentBundle<FluentResource>> {
    static FTL_ENG: &str = include_str!("../translation/eng.ftl");
    let res =
        FluentResource::try_new(FTL_ENG.to_owned()).map_err(|e| format!("parse eng.ftl: {e:?}"))?;
    let mut bundle = FluentBundle::new(vec![]);
    bundle
        .add_resource(res)
        .map_err(|e| format!("add resource: {e:?}"))?;
    Ok(bundle)
}

fn test_rng(seed: u8) -> DeterministicByteStream {
    DeterministicByteStream::from_seed([seed; 32])
}

// Minimal local helper: mimic produce_password_within_time_test logic
fn produce_with(
    all: &[char],
    _req: &[Vec<char>],
    len: usize,
    min_score: u8,
    eval: &impl PasswordStrengthEvaluator,
    rng: &mut ChaCha8Rng,
    max_attempts: u64,
) -> TestResult<Option<(String, u8, f64, bool)>> {
    use rand::RngCore;
    let mut attempts = 0;
    let mut best_pwd: Option<String> = None;
    let mut best_score = 0u8;
    let mut best_bits = 0.0;
    while attempts < max_attempts {
        attempts += 1;
        let mut bytes = vec![0u8; len * 16];
        rng.fill_bytes(&mut bytes);
        // simple candidate: cycle bytes into indices
        let mut pwd = String::with_capacity(len);
        if all.is_empty() {
            return Ok(None);
        }
        for byte in bytes.iter().take(len) {
            let idx = (*byte as usize) % all.len();
            pwd.push(all[idx]);
        }
        if pwd.chars().count() < 8 {
            continue;
        }
        let mut chars = pwd.chars();
        let Some(first) = chars.next() else {
            continue;
        };
        if chars.all(|c| c == first) {
            continue;
        }
        let (score, bits) = eval
            .score_entropy(&pwd)
            .map_err(|e| format!("score_entropy failed: {e}"))?;
        if score >= min_score {
            return Ok(Some((pwd, score, bits, true)));
        }
        if score > best_score || (score == best_score && bits > best_bits) {
            best_score = score;
            best_bits = bits;
            best_pwd = Some(pwd);
        }
    }
    Ok(best_pwd.map(|p| (p, best_score, best_bits, false)))
}

#[test]
fn early_exit_when_target_reached() -> TestResult<()> {
    // All ascii lower-case characters
    let all: Vec<char> = (b'a'..=b'z').map(|c| c as char).collect();
    let req: Vec<Vec<char>> = vec![];
    let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
    // Score sequence: 0, 0, then 4 with some entropy
    let eval = MockEvaluator::new(vec![(0, 10.0), (0, 12.0), (4, 80.0)]);

    let res = produce_with(&all, &req, 12, 4, &eval, &mut rng, 100)
        .map_err(|e| format!("produce_with failed: {e}"))?;
    let res = res.ok_or_else(|| "expected to produce a candidate".to_string())?;

    let (_pwd, score, _bits, reached) = res;
    assert_eq!(score, 4);
    assert!(reached, "should early exit on reaching target score");
    Ok(())
}

#[test]
fn best_effort_when_unmet_non_strict() -> TestResult<()> {
    let all: Vec<char> = (b'a'..=b'z').map(|c| c as char).collect();
    let req: Vec<Vec<char>> = vec![];
    let mut rng = ChaCha8Rng::from_seed([9u8; 32]);
    // Always return score 3 with 57.1 bits
    let eval = MockEvaluator::new(vec![(3, 57.1)]);

    let res = produce_with(&all, &req, 12, 4, &eval, &mut rng, 256)
        .map_err(|e| format!("produce_with failed: {e}"))?;
    let res = res.ok_or_else(|| "expected a best effort candidate".to_string())?;

    let (_pwd, score, bits, reached) = res;
    assert_eq!(score, 3);
    assert!((bits - 57.1).abs() < 0.05);
    assert!(!reached);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn quiet_output_is_password_only() -> TestResult<()> {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        all: false,
        no_prompt: false,
        numbers: true,
        no_numbers: false,
        uppercase: true,
        no_uppercase: false,
        lowercase: true,
        no_lowercase: false,
        symbols: true,
        no_symbols: false,
        symbols_set: None,
        timeout_ms: 150,
        min_score: 2, // allow loose target for speed
        strict: false,
        show_strength: true, // should be ignored in quiet
        quiet: true,
    };

    let mut ui = MockUI::new(vec!["n", "n"]);
    let mut rng = test_rng(0x21);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e}"))?;
    // Only the password, no heading nor strength
    assert!(report.header.is_none());
    assert!(report.strength_line.is_none());
    assert!(report.warnings.is_empty());
    assert!(!report.password.as_str().is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn show_strength_adds_line() -> TestResult<()> {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        all: false,
        no_prompt: false,
        numbers: true,
        no_numbers: false,
        uppercase: true,
        no_uppercase: false,
        lowercase: true,
        no_lowercase: false,
        symbols: true,
        no_symbols: false,
        symbols_set: None,
        timeout_ms: 150,
        min_score: 1,
        strict: false,
        show_strength: true,
        quiet: false,
    };
    let mut ui = MockUI::new(vec!["n", "n"]);
    let mut rng = test_rng(0x22);
    let bundle = mock_bundle()?;
    let report = generate_password_flow(&mut ui, &bundle, &args, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e}"))?;
    assert_eq!(report.header.as_deref(), Some("Password Generation Result"));
    assert!(
        report
            .strength_line
            .as_deref()
            .unwrap_or_default()
            .contains("Strength:")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn evaluator_injection_is_used_in_flow() -> TestResult<()> {
    let args = RupassArgs {
        language: None,
        password_length: Some(15),
        all: true,
        no_prompt: true,
        numbers: false,
        no_numbers: false,
        uppercase: false,
        no_uppercase: false,
        lowercase: false,
        no_lowercase: false,
        symbols: false,
        no_symbols: false,
        symbols_set: None,
        timeout_ms: 10,
        min_score: 4,
        strict: false,
        show_strength: false,
        quiet: true,
    };

    let evaluator = MockEvaluator::new(vec![(4, 80.0)]);
    let mut ui = MockUI::default();
    let mut rng = test_rng(0x23);
    let bundle = mock_bundle()?;
    generate_password_flow_with_evaluator(&mut ui, &bundle, &args, &evaluator, &mut rng)
        .await
        .map_err(|e| format!("generation failed: {e}"))?;
    assert!(evaluator.call_count() > 0);
    Ok(())
}
