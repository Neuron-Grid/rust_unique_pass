#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_unique_pass::crypto::zxcvbn_wrapper::zxcvbn_entropy_score;
use std::string::String;

fuzz_target!(|data: &[u8]| {
    let password = String::from_utf8_lossy(data);
    let _ = zxcvbn_entropy_score(&password);
});
