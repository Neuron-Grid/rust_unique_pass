# Copyright 2023 Neuron Grid
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file for full details.

# エラーメッセージ
error_invalid_input = "無効な入力です。
 yまたはnを入力してください。
 「はい」か「いいえ」でも良いです。"
error_user_input = "ユーザーからの行の読み込みに失敗しました。"
error_invalid_number = "有効な数値を入力してください。"
error_bundle_load = "翻訳バンドルのロードに失敗しました。"
read_error = "読み込みに失敗しました。"
error_parse = "解析に失敗しました。"
error_password_too_short = "パスワードは15文字以上を推奨します。"
error_generation = "パスワードの生成時にエラーが発生しました。"

# 質問とプロンプト
error_no_charset_selected = "エラー: 文字セットが選択されていません。
 --numbers(-n), --uppercase(-u), --lowercase(-w), --symbols(-s)、または --all を指定してください。
 非対話モード(--no-prompt)ではこれらのフラグ指定が必須です。"
question_enter_special_chars = "使用する特殊文字を入力してください (例 = !@#|¥)"
question_password_length = "パスワードの長さを入力してください。
 15文字以上を推奨します。"
question_change_special_chars = "使用する特殊文字を変更しますか？"
question_special_chars = "特殊文字を含めますか？"
question_lowercase = "小文字を含めますか？"
question_uppercase = "大文字を含めますか？"
question_numbers = "数字を含めますか？"

# 特殊文字
default_special_chars_message = "デフォルトで使用される特殊文字は{ $specialChars }です。"

# その他
generated_password = "パスワードが生成されました。"

# 新規: 時間予算ベース探索のメッセージ
warning_best_effort_used = "警告: 目標スコア { $targetScore } に { $budgetMs } ms 以内に到達できませんでした。最良候補を使用します: スコア { $bestScore } ({ $entropyBits } bits)。"
error_target_unmet_strict = "エラー: { $budgetMs } ms 以内に目標スコア { $targetScore } に到達できませんでした。"
info_strength_line = "強度: { $score }/4 (エントロピー: { $entropyBits } bits)"
