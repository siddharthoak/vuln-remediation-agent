import os
import json
import urllib.request
import urllib.error

PAT = 'REDACTED_DUMMY_GITHUB_PAT_VALUE_00000000'
REPO = 'Neurealm-Gaurav/vul-app'

url = f'https://api.github.com/repos/{REPO}/pulls?state=open'
req = urllib.request.Request(url, headers={'Authorization': f'token {PAT}', 'Accept': 'application/vnd.github.v3+json'})
with urllib.request.urlopen(req) as response:
    prs = json.loads(response.read().decode())

for pr in prs:
    print(f"Closing PR {pr['number']}")
    patch_url = f'https://api.github.com/repos/{REPO}/pulls/{pr["number"]}'
    data = json.dumps({'state': 'closed'}).encode('utf-8')
    patch_req = urllib.request.Request(patch_url, data=data, headers={'Authorization': f'token {PAT}', 'Accept': 'application/vnd.github.v3+json'}, method='PATCH')
    try:
        urllib.request.urlopen(patch_req)
        print("Closed")
    except Exception as e:
        print("Failed to close:", e)

    branch = pr['head']['ref']
    print(f"Deleting branch {branch}")
    del_url = f'https://api.github.com/repos/{REPO}/git/refs/heads/{branch}'
    del_req = urllib.request.Request(del_url, headers={'Authorization': f'token {PAT}', 'Accept': 'application/vnd.github.v3+json'}, method='DELETE')
    try:
        urllib.request.urlopen(del_req)
        print("Deleted branch")
    except Exception as e:
        print("Failed to delete branch:", e)

with open('data/tracking.json', 'w') as f:
    f.write('{}')

with open('data/kb.json', 'w') as f:
    f.write('{}')
