import sys

with open('dashboard/backend/templates/partials/run_history.html', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    '{% if r.total_tokens %}',
    '{% if r.total_tokens is not none %}'
)

with open('dashboard/backend/templates/partials/run_history.html', 'w', encoding='utf-8') as f:
    f.write(content)
