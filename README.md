# vuln-remediation-agent

Migrated from `nexus-remediation-agent`. Same Fixer + Watcher architecture, swapped backend:

| Component | nexus-remediation-agent | vuln-remediation-agent |
|-----------|------------------------|------------------------|
| LLM | Anthropic Claude (AI Foundry) | Gemini via Vertex AI (Google ADK) |
| Vulnerability source | Nexus IQ Server API | OWASP DC / Trivy / Grype JSON reports |
| Tracking store | Azure Cosmos DB | JSON file (local) / Firestore (GCP) |
| Fixer invocation | Azure AI Foundry SDK | HTTP POST (local) / Cloud Run Job (GCP) |
| Scheduling | AAF hosted agent schedule | `docker compose up -d` (local) / Cloud Scheduler (GCP) |

**What is identical:** `RetryGate`, `PRClient`, `RepoOps`, `CIStatusWatcher`, `TrackingRecord`, the four tool handler methods, `FRESH_FIX_PROMPT`, `RETRY_FIX_PROMPT`, retry bound logic.

---

## Local Testing Guide

Full end-to-end walkthrough — from triggering a scan on the target repo to remediated dependencies on merged `fix/` branches.

**Pipeline at a glance:**

```
[1 Start agents] → [2 Trigger scan] → [3 Auto-fetch reports] → [4 Fixer (Gemini)] → [5 CI runs] → [6 Watcher + retry] → [CI_PASSED]
  docker compose     GitHub Actions        ScanPoller                 fixer-server       GH Actions      watcher daemon         ↓
  up -d              (manual dispatch)     (auto, ~60s poll)                                                              [Dashboard]
                                                                                                                      streamlit run …
```

Both `fixer-server` and `watcher` run as long-lived services. You only need to trigger the GitHub Action — the agents do everything else. The Streamlit dashboard gives you live visibility into every step.

---

### Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2.20
- A GCP project with **Vertex AI API** enabled and billing active
- `gcloud` CLI installed; run `gcloud auth application-default login` before starting
- GitHub PAT with `repo`, `pull_request`, and `actions:read` scopes
- A fork (or your own copy) of `vulnerable-java-app` as the remediation target — the repo the agent will open PRs against

---

### Phase 0 — One-time local setup

```bash
# Clone this repo
git clone <vuln-remediation-agent-repo>
cd vuln-remediation-agent

# Create your config/.env
cp .env.example config/.env
```

Edit `config/.env` — the required values:

| Variable | Example | Where to get it |
|---|---|---|
| `GITHUB_REPO_TARGET` | `your-org/vulnerable-java-app` | The fork you set up |
| `GITHUB_PAT` | `ghp_xxxxxxxxxxxx` | GitHub → Settings → Developer settings → Tokens (needs `repo` + `pull_request` + `actions:read` scopes) |
| `GOOGLE_CLOUD_PROJECT` | `my-gcp-project-id` | GCP Console → Project info |
| `GOOGLE_APPLICATION_CREDENTIALS` | `/gcp/adc.json` | Leave as-is — this is the in-container path where `docker-compose.yml` mounts the SA key |

Place your GCP Service Account JSON at `config/my-google-service-account.json`. `docker-compose.yml` mounts it into every container at `/gcp/adc.json`. The SA account needs the `roles/aiplatform.user` role on the GCP project.

```bash
# Install dashboard dependencies (host-side, one-time)
pip install streamlit pandas

# Build all images
docker compose build
```

---

### Phase 1 — Start the agents

```bash
docker compose up -d
```

This starts two always-on services:

| Service | What it runs |
|---|---|
| `fixer-server` | **ScanPoller** (background thread) — polls `security-scan.yml` workflow runs every 60s; downloads the artifact and kicks off fixes when a new completed run is detected. **HTTP server** on `:8080` — accepts `POST /retry` from the Watcher for CI-failure re-fix attempts. |
| `watcher` | Daemon loop — runs a PR-watching cycle every 15 minutes, polls CI status, and triggers retries via `fixer-server` on CI failure. |

Tail logs while you work:

```bash
docker compose logs -f fixer-server watcher
```

---

### Phase 2 — Trigger a security scan on the target repo

The `security-scan.yml` workflow in `vulnerable-java-app` runs on every PR targeting `main`, and on manual `workflow_dispatch`. Either path works.

**Option A — Manual dispatch (recommended for local testing)**

1. Go to your fork on GitHub → **Actions** tab
2. Select **Security Scan** in the left sidebar
3. Click **Run workflow** → select branch `main` → **Run workflow**

**Option B — Open a PR to trigger automatically**

```bash
# In your vulnerable-java-app fork
git checkout -b test/trigger-scan

# Introduce a new CVE — e.g., add commons-codec 1.6 (CVE-2024-26308)
# Edit pom.xml → add under <dependencies>:
#   <dependency>
#     <groupId>commons-codec</groupId>
#     <artifactId>commons-codec</artifactId>
#     <version>1.6</version>
#   </dependency>

git add pom.xml
git commit -m "test: add commons-codec 1.6 (CVE-2024-26308)"
git push origin test/trigger-scan
# Open a PR from test/trigger-scan → main in the GitHub UI
```

The workflow runs three scanners — OWASP Dependency-Check (~4 min), Trivy (~1 min), Grype (~1 min). All three run even if one fails (`if: always()` on each step). Total runtime: 5–10 minutes.

**You don't need to do anything else.** The `fixer-server`'s ScanPoller detects the completed run within `SCAN_POLL_INTERVAL` seconds, downloads the `vulnerability-reports` artifact into `./scan-reports/`, and immediately starts the fix flow. Watch `docker compose logs -f fixer-server` to see it happen.

---

### What happens automatically after the scan completes

**Fixer (inside `fixer-server`):**

1. ScanPoller detects the new completed run and downloads the `vulnerability-reports` artifact.
2. `ScanReportClient` reads the three JSON files and produces a deduplicated findings list.
3. A `CREATED` tracking record is written to `./data/tracking.json` (bind-mounted, readable by the dashboard) for each finding.
4. Up to `MAX_PARALLEL_FIXES=5` findings are processed concurrently. For each:

| Step | What happens |
|---|---|
| Clone | Local hardlink clone of `GITHUB_REPO_TARGET` into a temp directory |
| Bump pom.xml | XML-parser rewrite of the dependency version — never string-replace |
| Gemini tool-use loop | ADK `Agent` runs `FRESH_FIX_PROMPT` with four tools: `grep_files` → `read_file` → `apply_file_change` → `run_maven_compile` |
| Self-correction | If `run_maven_compile` returns `FAILURE`, Gemini reads stderr and calls `apply_file_change` again. Repeats until compile passes or model ends the turn. |
| Commit + push | Branch `fix/<component>-<safe-version>` pushed. Only after compile gate passes. |
| Open PR | Idempotent: skips if a PR from that branch already exists. |
| Update record | `PR_OPENED` → `CI_PENDING` with `pr_number`, `branch_name`, token usage. |

> **Gemini uses parametric knowledge in this phase.** It infers what APIs changed between versions from training data. In Phase 2 (see [Roadmap](#phase-2-roadmap--knowledge-base--classifier)), a Knowledge Agent will pre-hydrate a Knowledge Store from official release notes before the Fixer runs, replacing inference with retrieved ground truth.

Verify PRs were opened:

```bash
gh pr list --repo your-org/vulnerable-java-app --head "fix/"
```

**Watcher (on its next 15-minute cycle):**

For each open `fix/` PR:

| CI result | Watcher action |
|---|---|
| **CI passed** | Record updated to `CI_PASSED`. PR is ready for human review. |
| **CI timed out** | Warning logged. Record stays `CI_PENDING`. Re-checked on next cycle. |
| **CI failed — under retry limit** | Record → `CI_FAILED`. Child record created: `RETRY_REQUESTED` with `failure_log_excerpt` (CI failure log, truncated to 4,000 chars). `POST /retry` sent to `fixer-server`. |
| **CI failed — limit reached** | Record → `FAILED_MAX_RETRIES`. Escalation comment posted on the PR. Fixer never invoked again for this PR. |

**What fixer-server does on retry:**

1. Reads the `RETRY_REQUESTED` tracking record by ID.
2. Validates: status must be exactly `RETRY_REQUESTED`; attempt number ≤ `MAX_RETRY_ATTEMPTS`.
3. Checks out the **existing PR branch** — no new branch.
4. Runs `RETRY_FIX_PROMPT` with the CI failure log at the top. Gemini sees exactly what broke and why.
5. Pushes a corrective commit to the same branch. CI reruns automatically.
6. Updates tracking record to `CI_PENDING`. Watcher picks it up on its next cycle.

---

### Phase 3 — Observe with the dashboard

```bash
streamlit run streamlit_dashboard.py
```

Open [http://localhost:8501](http://localhost:8501). Run this in a separate terminal alongside the agents — it reads `./data/tracking.json` directly from the bind mount and auto-refreshes every 30 seconds. No Docker required.

**Sidebar** shows live agent health:
- **Fixer-server** — time since the last ScanPoller checkpoint write (goes yellow if the server is idle or unreachable)
- **Scan reports** — which scanner JSON files are present in `./scan-reports/` and how old they are

**Run History tab** — filterable table of every fix attempt with status, version change, PR number, token usage, and resolution time.

**Retry Lineage tab** — select any PR number to see the full attempt chain. Each attempt expands to show component details, token usage, and the CI failure excerpt that was injected into the retry prompt.

**Metrics tab** — resolution rate, in-progress / escalated counts, avg/p50/p95 time-to-resolution, total token consumption, and charts for status distribution and retry depth.

**State machine:**

```
CREATED → PR_OPENED → CI_PENDING → CI_PASSED              (human review)
                    → CI_FAILED  → RETRY_REQUESTED → CI_PENDING  (retry loop)
                                                   → FAILED_MAX_RETRIES
```

---

### Ad-hoc / manual operations

The one-shot `fixer` service is available for manual use (it's excluded from `docker compose up -d` via a Docker profile):

```bash
# Fresh scan using reports already in ./scan-reports/
docker compose run --rm --profile manual fixer

# Fresh scan + trigger + download (AUTO_FETCH_SCAN)
docker compose run --rm --profile manual -e AUTO_FETCH_SCAN=1 fixer

# Manual retry for a specific tracking ID
docker compose run --rm --profile manual -e RETRY_TRACKING_ID=<id> fixer
```

To force a CI failure for testing, temporarily add a Maven Enforcer rule:

```xml
<!-- Add to vulnerable-java-app pom.xml temporarily -->
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-enforcer-plugin</artifactId>
  <version>3.4.1</version>
  <executions><execution><goals><goal>enforce</goal></goals>
    <configuration><rules>
      <requireProperty>
        <property>DELIBERATELY_FAIL</property>
        <message>Set DELIBERATELY_FAIL to trigger retry</message>
      </requireProperty>
    </rules></configuration>
  </execution></executions>
</plugin>
```

Set `MAX_RETRY_ATTEMPTS=1` in `config/.env` to reach `FAILED_MAX_RETRIES` quickly.

---

### Test scenario matrix

| Scenario | How to trigger | What to observe |
|---|---|---|
| **Happy path** | `docker compose up -d`; `streamlit run streamlit_dashboard.py`; trigger scan | `fix/` PRs opened automatically; dashboard shows records progressing to `CI_PASSED` |
| **Informed retry** | Force CI failure via Enforcer rule | `RETRY_REQUESTED` record has `failure_log_excerpt`; fixer-server pushes a corrective commit |
| **Retry exhaustion** | `MAX_RETRY_ATTEMPTS=1`; force CI failure | Record reaches `FAILED_MAX_RETRIES` after one retry; PR gets escalation comment |
| **New CVE mid-run** | Add a new vulnerable dep; trigger scan again | ScanPoller detects the new completed run; only the new finding gets a fresh PR |
| **Single scanner** | Remove `grype-report.json` from `scan-reports/` | Fixer logs a warning; continues with Trivy + OWASP DC only |
| **Compile error recovery** | Upgrade a library with a known API removal | First `run_maven_compile` fails; Gemini reads stderr, calls `apply_file_change` again; second compile passes |
| **Idempotent PR** | Scan poller fires twice for the same run | Checkpoint prevents re-download; already-open PRs are skipped |

---

## Phase 2 Roadmap — Knowledge Base & Classifier

> **Not yet implemented.** These agents are planned; see `nexus-remediation-agent/DiscussionPoints-v1.md` for the full specification. The current Fixer goes directly from scan reports to the Gemini tool-use loop, relying on parametric (training-data) knowledge.

Phase 2 inserts two new agents before the Fixer, changing what happens after the ScanPoller triggers:

```
[scan reports] → [Knowledge Agent] → [Classifier] → [Fixer] → ...
                   (hydrates KB)      (buckets)     (with KB)
```

### Knowledge Agent

For each `(component, old_version, new_version)` tuple:

1. Check the **Knowledge Store** — if an entry exists, skip (no-op).
2. Query official release notes and migration guides via web search scoped to trusted domains.
3. Extract: removed/renamed APIs, changed method signatures, new required imports, known breaking patterns.
4. Persist a structured entry to the Knowledge Store.

When the Fixer subsequently processes a finding, it reads the Knowledge Store first. If a pre-hydrated entry exists, it is injected into the Gemini prompt as retrieved ground truth — anchoring suggestions to documented facts rather than parametric memory, which is critical for recently published versions.

**Tier 1 (learned patterns):** After a fix is confirmed by CI, the Watcher writes the exact `find`/`replace` pairs that worked as a KB entry. On the next run with the same version pair (in any repo), the Fixer applies them via `apply_file_change` — zero LLM calls unless pattern application fails.

**Tier 2 (curated playbooks):** Engineer-authored YAML migration guides for major-version upgrades (log4j 1→2, Spring Boot 2→3). Read by the Fixer before any major-version attempt regardless of whether the version pair has been seen before.

### Classifier Agent

Assigns every finding to one of four buckets before the Fixer runs:

| Bucket | Trigger condition | Action |
|---|---|---|
| **1 — No path** | No remediation target in scan; transitive dep; EOL library | GitHub Issue created immediately; Fixer skipped |
| **2 — Patch / Minor** | Same major version; no breaking KB entries | Fixer runs (with KB context if available) |
| **3 — Major + KB** | Major version delta; Tier 1/2 KB hit or Knowledge Agent output exists | Fixer runs with KB injected into prompt |
| **4 — Complex / framework** | Spring Boot, Hibernate, Angular; major delta; no KB entry or migration plan | GitHub Issue created with breaking-change analysis; Fixer not invoked |

The Classifier writes its bucket decision and rationale to each finding's tracking record. The Fixer reads the bucket at startup and exits immediately for Buckets 1 and 4 — no Gemini call made.

**Why this matters for testing:** Without the Classifier, the current Fixer attempts every finding including transitive dependencies and framework-level upgrades. Adding the Classifier adds a pre-flight gate that prevents wasted fix attempts and creates GitHub Issues for cases that need human triage.

---

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_REPO_TARGET` | ✓ | — | `owner/repo` of the repo to remediate |
| `GITHUB_PAT` | ✓ | — | PAT with `repo` + `pull_request` + `actions:read` scopes |
| `GOOGLE_CLOUD_PROJECT` | ✓ | — | GCP project for Vertex AI |
| `VERTEX_LOCATION` | | `us-central1` | Vertex AI region |
| `VERTEX_MODEL` | | `gemini-2.0-flash-001` | Gemini model name |
| `GOOGLE_APPLICATION_CREDENTIALS` | ✓ | — | In-container path to GCP credentials JSON; `docker-compose.yml` mounts `./config/my-google-service-account.json` here as `/gcp/adc.json` |
| `FIXER_SERVER_MODE` | | `0` | Set to `1` to run the fixer as a long-lived server (ScanPoller + HTTP retry endpoint). Set automatically by `fixer-server` in `docker-compose.yml`. |
| `SCAN_POLL_INTERVAL` | | `60` | Seconds between GitHub Actions polls in server mode |
| `WATCHER_DAEMON` | | `0` | Set to `1` to run the watcher as a daemon loop instead of a one-shot batch job. Set automatically by the `watcher` service in `docker-compose.yml`. |
| `WATCHER_SLEEP_SECONDS` | | `900` | Seconds between watcher cycles in daemon mode (default 15 min) |
| `MAX_RETRY_ATTEMPTS` | | `3` | Hard retry bound per PR |
| `MAX_PARALLEL_FIXES` | | `5` | Concurrent fixer workers |
| `CI_POLL_INTERVAL` | | `30` | Seconds between CI status checks |
| `CI_TIMEOUT_SECONDS` | | `1800` | Max wait for CI (30 min) |
| `SCAN_REPORT_PATH` | | `/reports` | Directory containing scanner JSON files |
| `TRACKING_STORE_PATH` | | `/data/tracking.json` | State file path inside container |
| `FIXER_RETRY_URL` | | — | HTTP endpoint for retry invocation (set to `http://fixer-server:8080/retry` by the watcher service) |
| `AUTO_FETCH_SCAN` | | `0` | Set to `1` on one-shot fixer runs to trigger + download the scan workflow before fixing (alternative to ScanPoller for manual use) |
| `RETRY_TRACKING_ID` | | — | Set by Watcher for retry runs, or pass manually to the one-shot fixer |
