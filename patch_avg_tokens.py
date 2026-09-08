import sys

with open('dashboard/backend/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

replacement = """    tokens_per_issue = {}
    for r in records:
        vid = r.get("vulnerability_id") or r.get("component_name") or r.get("tracking_id")
        if vid:
            tokens_per_issue[vid] = tokens_per_issue.get(vid, 0) + r["total_tokens"]
    avg_tokens_per_issue = (sum(tokens_per_issue.values()) / len(tokens_per_issue)) if tokens_per_issue else None"""

content = content.replace("""    tokens_per_pr = {}
    for r in records:
        if r.get("pr_number") is not None:
            tokens_per_pr[r["pr_number"]] = tokens_per_pr.get(r["pr_number"], 0) + r["total_tokens"]
    avg_tokens_per_pr = (sum(tokens_per_pr.values()) / len(tokens_per_pr)) if tokens_per_pr else None""", replacement)

content = content.replace('"avg_tokens_per_pr": avg_tokens_per_pr,', '"avg_tokens_per_issue": avg_tokens_per_issue,')

with open('dashboard/backend/app.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('dashboard/backend/templates/partials/metrics.html', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('avg_tokens_per_pr', 'avg_tokens_per_issue')
content = content.replace('Avg tokens per PR', 'Avg tokens per issue')

with open('dashboard/backend/templates/partials/metrics.html', 'w', encoding='utf-8') as f:
    f.write(content)
