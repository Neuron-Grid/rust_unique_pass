# Copyright 2023-2025 Neuron Grid
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file for full details.

# error messages
error_invalid_input = "Ungültige Eingabe.
 bitte geben Sie y oder n ein."
error_invalid_number = "Bitte geben Sie eine gültige Nummer ein."
error_password_too_short = "Es wird empfohlen, für Passwörter mindestens 15 Zeichen zu verwenden."
error_user_input = "Zeile des Benutzers konnte nicht gelesen werden."
error_parse = "Parsen fehlgeschlagen."
read_error = "Konnte nicht geladen werden."
error_bundle_load = "Übersetzungsbündel konnte nicht geladen werden."
error_generation = "Fehler bei der Generierung des Passworts."

# Questions and prompts
error_no_charset_selected  = "Fehler: Kein Zeichensatz ausgewählt.
 Bitte geben Sie mindestens einen der Schalter an: --numbers (-n), --uppercase (-u), --lowercase (-w), --symbols (-s) oder --all.
 Im nicht-interaktiven Modus (--no-prompt) sind diese Schalter verpflichtend."
question_enter_special_chars = "Geben Sie die Sonderzeichen ein, die Sie verwenden möchten. (z. B. = ! @#|¥)"
question_password_length = "Geben Sie die Länge Ihres Passworts ein.
 Es wird ein Minimum von 15 Zeichen empfohlen."
question_change_special_chars = "Möchten Sie die verwendeten Sonderzeichen ändern?"
question_special_chars = "Verwenden Sie Sonderzeichen?"
question_lowercase = "Verwenden Sie Kleinbuchstaben?"
question_uppercase = "Möchten Sie Großbuchstaben verwenden?"
question_numbers = "Verwenden Sie Zahlen?"

# default messages
default_special_chars_message = "Die standardmäßig verwendeten Sonderzeichen sind: { $specialChars }"

# Other messages
generated_password = "Das Passwort wurde generiert."

# Neue Meldungen für zeitbudgetierte Stärkensuche
warning_best_effort_used = "Warnung: Zielwert { $targetScore } konnte innerhalb von { $budgetMs } ms nicht erreicht werden. Bester Kandidat wird verwendet: Wert { $bestScore } ({ $entropyBits } Bits)."
error_target_unmet_strict = "Fehler: Zielwert { $targetScore } konnte innerhalb von { $budgetMs } ms nicht erreicht werden."
info_strength_line = "Stärke: { $score }/4 (Entropie: { $entropyBits } Bits)"
