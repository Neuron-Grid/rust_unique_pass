/* Copyright 2023-2024 Neuron Grid

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use rust_unique_pass::{
    app_errors::Result,
    generate_pass::generate_password_flow,
    i18n::{initialize_bundle, parse_args},
    user_interface::StdioInterface,
};

fn main() -> Result<()> {
    let args = parse_args();
    let bundle = initialize_bundle(&args)?;
    let mut ui = StdioInterface;
    generate_password_flow(&mut ui, &bundle, &args)?;
    Ok(())
}
