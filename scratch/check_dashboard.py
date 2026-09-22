import urllib.request
import re

url = "http://localhost:8000/partials/kb"
html = urllib.request.urlopen(url).read().decode("utf-8")

tier2_matches = re.findall(r'<div class="value">(\d+)</div><div class="label">Tier 2 \(playbooks\)</div>', html)
print("Tier 2 Playbook count on dashboard:", tier2_matches[0] if tier2_matches else "Not found")

has_jwt = "jsonwebtoken" in html
has_axios = "axios" in html
has_log4j = "org.apache.log4j:log4j" in html

print(f"jsonwebtoken in dashboard: {has_jwt}")
print(f"axios in dashboard: {has_axios}")
print(f"log4j in dashboard: {has_log4j}")
