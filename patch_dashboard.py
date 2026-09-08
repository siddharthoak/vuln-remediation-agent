import sys

with open('dashboard/backend/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    'd["completion_tokens"] = completion_tokens',
    'd["completion_tokens"] = completion_tokens\n        d["model_name"] = (tu or {}).get("model_name")'
)

with open('dashboard/backend/app.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('dashboard/backend/templates/partials/run_history.html', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    '<div class="label">Tokens ({{ r.prompt_tokens }}p / {{ r.completion_tokens }}c)</div>',
    '<div class="label">Tokens ({{ r.prompt_tokens }}p / {{ r.completion_tokens }}c){% if r.model_name %} - {{ r.model_name }}{% endif %}</div>'
)

with open('dashboard/backend/templates/partials/run_history.html', 'w', encoding='utf-8') as f:
    f.write(content)
