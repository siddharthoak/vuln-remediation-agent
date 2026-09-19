FROM python:3.11-slim

WORKDIR /app

# git is required by GitPython for clone/push operations.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git maven curl gnupg && \
    rm -rf /var/lib/apt/lists/*

# nodejs/npm + @google/gemini-cli are only needed for FIX_ENGINE=gemini_cli
# (engines/gemini_cli.py) -- default FIX_ENGINE=adk doesn't use them.
# @google/gemini-cli's package.json declares "engines": {"node": ">=20"}
# (verified against the npm registry) -- Debian bookworm's own apt nodejs
# package is only 18.20.4, too old, so this uses Node's official NodeSource
# setup script (nodejs.org's documented install method for Debian/Ubuntu)
# rather than a base-image swap, to keep this change small and not touch
# anything about the existing python:3.11-slim setup.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# See engines/gemini_cli.py's module docstring for the security caveats
# (unverified tool-exclusion sandboxing) before routing real traffic
# through this engine.
RUN npm install -g @google/gemini-cli

COPY agents/fixer/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY agents/common/ /app/common/
COPY agents/knowledge/ /app/knowledge/
COPY agents/classifier/ /app/classifier/
COPY agents/fixer/ /app/
COPY playbooks/ /app/playbooks/
# POST /scan/demo (dashboard "Load Demo Scan Reports" button) imports this
# directly rather than shelling out -- flat filename to match this image's
# existing flat-namespace imports (scan_report_client, scan_fetcher, ...).
COPY scripts/generate_demo_scan_reports.py /app/demo_scan_reports.py

CMD ["python", "main.py"]
