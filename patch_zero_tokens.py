import sys

with open('dashboard/backend/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """    tokens_by_component: dict = {}
    for r in records:
        if r.get("total_tokens"):
            comp = r.get("component_name") or "Unknown"
            tokens_by_component[comp] = tokens_by_component.get(comp, 0) + r["total_tokens"]"""

new_code = """    tokens_by_component: dict = {}
    for r in records:
        comp = r.get("component_name") or "Unknown"
        tokens_by_component[comp] = tokens_by_component.get(comp, 0) + (r.get("total_tokens") or 0)"""

content = content.replace(old_code, new_code)

with open('dashboard/backend/app.py', 'w', encoding='utf-8') as f:
    f.write(content)
