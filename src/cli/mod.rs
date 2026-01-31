#[path = "cli.rs"]
mod cli_items;
pub use cli_items::*;

pub mod user_interface;
pub use user_interface::*;

pub mod reporting;
pub use reporting::{ReportOutput, build_report_output, format_generation_error, run_cli};
