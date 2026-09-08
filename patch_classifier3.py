import re

with open('agents/classifier/classifier.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Insert kb_entry lookup before bucket 1
content = re.sub(
    r'(# .*Bucket 1: no fix available .*\n\s*if _is_unknown_version\(new_ver\):)',
    r'kb_entry = self._kb.find_applicable(component, old_ver, new_ver)\n\n        \1 and kb_entry is None:',
    content
)

# 2. Modify Bucket 4 to allow if kb_entry exists
content = content.replace(
    """            if introduced_by_complex or deep_chain:""",
    """            if (introduced_by_complex or deep_chain) and kb_entry is None:"""
)

with open('agents/classifier/classifier.py', 'w', encoding='utf-8') as f:
    f.write(content)
