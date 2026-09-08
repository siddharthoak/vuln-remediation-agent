import sys

with open('agents/fixer/code_fixer.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add model_name to ChangeSummary
content = content.replace(
    "completion_tokens: Optional[int] = None\n",
    "completion_tokens: Optional[int] = None\n    model_name: Optional[str] = None\n"
)

# 2. Map result.model_name in _execute_fix and _execute_transitive_fix
content = content.replace(
    "completion_tokens=result.completion_tokens,\n        )",
    "completion_tokens=result.completion_tokens,\n            model_name=result.model_name,\n        )"
)

# 3. Add model_name to token_usage
content = content.replace(
    '"completion_tokens": summary.completion_tokens,\n        }',
    '"completion_tokens": summary.completion_tokens,\n            "model_name": summary.model_name,\n        }'
)

with open('agents/fixer/code_fixer.py', 'w', encoding='utf-8') as f:
    f.write(content)
