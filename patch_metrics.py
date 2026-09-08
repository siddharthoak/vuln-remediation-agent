import sys

with open('dashboard/backend/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add tokens_by_component calculation
component_calc = """    tokens_by_attempt_bars = _bars(sorted(tokens_by_attempt.items()))

    tokens_by_component: dict = {}
    for r in records:
        if r.get("total_tokens"):
            comp = r.get("component_name") or "Unknown"
            tokens_by_component[comp] = tokens_by_component.get(comp, 0) + r["total_tokens"]
    
    sorted_comps = sorted(tokens_by_component.items(), key=lambda x: x[1], reverse=True)
    tokens_by_component_bars = _bars(sorted_comps[:15])
"""

content = content.replace(
    '    tokens_by_attempt_bars = _bars(sorted(tokens_by_attempt.items()))\n',
    component_calc
)

# Pass it to the template context
content = content.replace(
    '"tokens_by_attempt_bars": tokens_by_attempt_bars,',
    '"tokens_by_attempt_bars": tokens_by_attempt_bars,\n        "tokens_by_component_bars": tokens_by_component_bars,'
)

with open('dashboard/backend/app.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('dashboard/backend/templates/partials/metrics.html', 'r', encoding='utf-8') as f:
    content = f.read()

component_template = """    <h2>Token usage by component (Top 15)</h2>
    {% for b in tokens_by_component_bars %}
      <div class="bar-row" title="{{ b.label }}">
        <div class="bar-label" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 300px;">{{ b.label }}</div>
        <div class="bar-track"><div class="bar-fill" style="width:{{ b.pct }}%"></div></div>
        <div class="bar-value">{{ "{:,}".format(b.value) }}</div>
      </div>
    {% endfor %}

    <h2>Token usage by attempt number</h2>"""

content = content.replace(
    '<h2>Token usage by attempt number</h2>',
    component_template
)

with open('dashboard/backend/templates/partials/metrics.html', 'w', encoding='utf-8') as f:
    f.write(content)
