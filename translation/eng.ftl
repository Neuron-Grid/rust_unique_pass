# Copyright 2023-2025 Neuron Grid
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file for full details.

# error messages
error_invalid_input = "Invalid input.
 Please enter y or n."
error_invalid_number = "Please enter a valid number."
error_password_too_short = "A minimum of 15 characters is recommended for passwords."
error_user_input = "Failed to read line of user."
error_parse = "Failed to parse."
read_error = "Read error"
error_bundle_load = "Could not load translation package."
error_generation = "Error generating password."

# Questions and prompts
error_no_charset_selected  = "Error: No character set selected.
 Specify at least one of --numbers (-n), --uppercase (-u), --lowercase (-w), --symbols (-s), or --all.
 In non-interactive mode (--no-prompt), these flags are required."
question_change_special_chars = "Change the special characters used?"
question_enter_special_chars = "Enter special characters to use. (e.g. !@#|¥)"
question_lowercase = "Include lowercase letters?"
question_numbers = "Include numbers?"
question_password_length = "Please enter a password length.
 15 or more is recommended."
question_special_chars = "Include special characters?"
question_uppercase = "Include uppercase letters?"

# default messages
default_special_chars_message = "The special characters used by default are: { $specialChars }"

# Other messages
generated_password = "Password Generation Result"

# New messages for time-budgeted strength search
warning_best_effort_used = "Warning: Could not reach target score { $targetScore } within { $budgetMs } ms. Using best candidate: score { $bestScore } ({ $entropyBits } bits)."
error_target_unmet_strict = "Error: Could not reach target score { $targetScore } within { $budgetMs } ms."
info_strength_line = "Strength: { $score }/4 (entropy: { $entropyBits } bits)"
