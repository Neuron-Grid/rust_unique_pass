use async_trait::async_trait;
use rust_unique_pass::{
    GenerationError, Result, RupassArgs, UserInterface, generate_password_flow, initialize_bundle,
};

#[derive(Default)]
struct MockUI {
    outputs: Vec<String>,
}

#[async_trait(?Send)]
impl UserInterface for MockUI {
    async fn prompt(&mut self, _msg: &str) -> Result<String> {
        Err(GenerationError::InvalidInput)
    }

    async fn print(&mut self, msg: &str) -> Result<()> {
        self.outputs.push(msg.to_owned());
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn strict_unmet_returns_error_when_min_score_unreachable() {
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
        timeout_ms: 1,
        min_score: 255,
        strict: true,
        show_strength: false,
        quiet: true,
    };

    let bundle = initialize_bundle(&args).expect("bundle should initialize");
    let mut ui = MockUI::default();
    let res = generate_password_flow(&mut ui, &bundle, &args).await;

    assert!(matches!(res, Err(GenerationError::StrictTargetUnmet)));
}
