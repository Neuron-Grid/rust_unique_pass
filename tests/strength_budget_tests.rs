use async_trait::async_trait;
use fluent::{FluentBundle, FluentResource};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rust_unique_pass::cli::UserInterface;
use rust_unique_pass::core::app_errors::{GenerationError, Result};
use rust_unique_pass::password::password_generation::PasswordStrengthEvaluator;
use rust_unique_pass::{RupassArgs, generate_password_flow, generate_password_flow_with_evaluator};
use std::collections::VecDeque;

// Mock evaluator for deterministic scenarios
use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn score_entropy(&self, _pwd: &str) -> (u8, f64) {
        let i = self.idx.fetch_add(1, Ordering::Relaxed);
        let pos = i.min(self.seq.len().saturating_sub(1));
        self.seq[pos]
    }
}

// Lightweight UI mock to capture stdout lines
#[derive(Default)]
struct MockUI {
    inputs: VecDeque<String>,
    outputs: Vec<String>,
}

impl MockUI {
    fn new(src: Vec<&str>) -> Self {
        Self {
            inputs: src.into_iter().map(String::from).collect(),
            outputs: Vec::new(),
        }
    }
    fn outputs_joined(&self) -> String {
        self.outputs.join("")
    }
}

#[async_trait(?Send)]
impl UserInterface for MockUI {
    async fn prompt(&mut self, _msg: &str) -> Result<String> {
        self.inputs.pop_front().ok_or(GenerationError::InvalidInput)
    }
    async fn print(&mut self, msg: &str) -> Result<()> {
        self.outputs.push(msg.to_owned());
        Ok(())
    }
}

// Use embedded English FTL for bundle
fn mock_bundle() -> FluentBundle<FluentResource> {
    static FTL_ENG: &str = include_str!("../translation/eng.ftl");
    let res = FluentResource::try_new(FTL_ENG.to_owned()).expect("parse eng.ftl");
    let mut bundle = FluentBundle::new(vec![]);
    bundle.add_resource(res).expect("add resource");
    bundle
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
) -> Option<(String, u8, f64, bool)> {
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
            return None;
        }
        for byte in bytes.iter().take(len) {
            let idx = (*byte as usize) % all.len();
            pwd.push(all[idx]);
        }
        if pwd.chars().count() < 8 {
            continue;
        }
        if pwd.chars().all(|c| c == pwd.chars().next().unwrap()) {
            continue;
        }
        let (score, bits) = eval.score_entropy(&pwd);
        if score >= min_score {
            return Some((pwd, score, bits, true));
        }
        if score > best_score || (score == best_score && bits > best_bits) {
            best_score = score;
            best_bits = bits;
            best_pwd = Some(pwd);
        }
    }
    best_pwd.map(|p| (p, best_score, best_bits, false))
}

#[test]
fn early_exit_when_target_reached() {
    // All ascii lower-case characters
    let all: Vec<char> = (b'a'..=b'z').map(|c| c as char).collect();
    let req: Vec<Vec<char>> = vec![];
    let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
    // Score sequence: 0, 0, then 4 with some entropy
    let eval = MockEvaluator::new(vec![(0, 10.0), (0, 12.0), (4, 80.0)]);

    let res =
        produce_with(&all, &req, 12, 4, &eval, &mut rng, 100).expect("should produce a candidate");

    let (_pwd, score, _bits, reached) = res;
    assert_eq!(score, 4);
    assert!(reached, "should early exit on reaching target score");
}

#[test]
fn best_effort_when_unmet_non_strict() {
    let all: Vec<char> = (b'a'..=b'z').map(|c| c as char).collect();
    let req: Vec<Vec<char>> = vec![];
    let mut rng = ChaCha8Rng::from_seed([9u8; 32]);
    // Always return score 3 with 57.1 bits
    let eval = MockEvaluator::new(vec![(3, 57.1)]);

    let res = produce_with(&all, &req, 12, 4, &eval, &mut rng, 256)
        .expect("should return best effort candidate");

    let (_pwd, score, bits, reached) = res;
    assert_eq!(score, 3);
    assert!((bits - 57.1).abs() < 0.05);
    assert!(!reached);
}

#[tokio::test(flavor = "current_thread")]
async fn quiet_output_is_password_only() {
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
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .expect("generation should succeed");
    let out = ui.outputs_joined();
    // Only the password, no heading nor strength
    assert!(!out.contains("Password Generation Result"));
    assert!(!out.contains("Strength:"));
    assert!(out.trim().lines().count() >= 1);
}

#[tokio::test(flavor = "current_thread")]
async fn show_strength_adds_line() {
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
    generate_password_flow(&mut ui, &mock_bundle(), &args)
        .await
        .expect("generation should succeed");
    let out = ui.outputs_joined();
    assert!(out.contains("Password Generation Result"));
    assert!(out.contains("Strength:"));
}

#[tokio::test(flavor = "current_thread")]
async fn evaluator_injection_is_used_in_flow() {
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
    let res =
        generate_password_flow_with_evaluator(&mut ui, &mock_bundle(), &args, &evaluator).await;

    assert!(res.is_ok());
    assert!(evaluator.call_count() > 0);
}
