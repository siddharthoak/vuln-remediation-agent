# vuln-remediation-agent

Migrated from `nexus-remediation-agent`. Same Fixer + Watcher architecture, swapped backend:

| Component | nexus-remediation-agent | vuln-remediation-agent |
|-----------|------------------------|------------------------|
| LLM | Anthropic Claude (AI Foundry) | Gemini via Vertex AI (Google ADK) |
| Vulnerability source | Nexus IQ Server API | OWASP DC / Trivy / Grype JSON reports |
| Tracking store | Azure Cosmos DB | JSON file (local) / Firestore (GCP) |
| Fixer invocation | Azure AI Foundry SDK | HTTP POST (local) / Cloud Run Job (GCP) |
| Scheduling | AAF hosted agent schedule | `podman compose up -d` (local) / Cloud Scheduler (GCP) |

**What is identical:** `RetryGate`, `PRClient`, `RepoOps`, `CIStatusWatcher`, `TrackingRecord`, the four tool handler methods, `FRESH_FIX_PROMPT`, `RETRY_FIX_PROMPT`, retry bound logic.

---

## Local Testing Guide

Full end-to-end walkthrough — from triggering a scan on the target repo to remediated dependencies on merged `fix/` branches.

**Pipeline at a glance:**

```
[1 Start agents] → [2 Trigger scan] → [3 Auto-fetch] → [4 KB hydrate + classify] → [5 Fixer (Gemini)] → [6 CI runs] → [7 Watcher + retry] → [CI_PASSED]
  podman compose     GitHub Actions      ScanPoller       Knowledge Agent               fixer-server       GH Actions     watcher daemon          ↓
  up -d              (manual dispatch)   (60s poll)       + Classifier                  (B2/B3 only)                                          [Dashboard]
                                                          B1/B4 → GitHub Issues                                                     http://172.31.144.52:8501
```

`fixer-server`, `watcher`, and `dashboard` all run as long-lived services started by `podman compose up -d`. You only need to trigger the GitHub Action — the agents do everything else. The dashboard (server-rendered FastAPI + HTMX, containerized alongside the agents) gives you live visibility into every step.

---

### Prerequisites

- Podman ≥ 4 and podman-compose ≥ 1.0 (Docker Compose is also supported)
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
# Build all images (fixer-server, watcher, dashboard).
# Direct builds avoid a podman-compose 1.6 Windows issue that drops the
# per-service Dockerfile argument.
podman build -f agents/fixer/Dockerfile -t vuln-remediation-agent_fixer-server .
podman build -f agents/watcher/Dockerfile -t vuln-remediation-agent_watcher .
podman build -f dashboard/Dockerfile -t vuln-remediation-agent_dashboard .
```

---

### Phase 1 — Start the agents

```bash
podman compose up -d --no-build
```

This starts two always-on services:

| Service | What it runs |
|---|---|
| `fixer-server` | **ScanPoller** (background thread) — polls `security-scan.yml` workflow runs every 60s; downloads the artifact and kicks off fixes when a new completed run is detected. **HTTP server** on `:8080` — accepts `POST /retry` from the Watcher for CI-failure re-fix attempts. |
| `watcher` | Daemon loop — runs a PR-watching cycle every 15 minutes, polls CI status, and triggers retries via `fixer-server` on CI failure. |

Tail logs while you work:

```bash
podman compose logs -f fixer-server watcher
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

**You don't need to do anything else.** The `fixer-server`'s ScanPoller detects the completed run within `SCAN_POLL_INTERVAL` seconds, downloads the `vulnerability-reports` artifact into `./scan-reports/`, and immediately starts the fix flow. Watch `podman compose logs -f fixer-server` to see it happen.

---

### What happens automatically after the scan completes

**Fixer (inside `fixer-server`):**

1. ScanPoller detects the new completed run and downloads the `vulnerability-reports` artifact.
2. `ScanReportClient` reads the three JSON files and produces a deduplicated findings list.
3. A `CREATED` tracking record is written to `./data/tracking.json` (bind-mounted, readable by the dashboard) for each finding.
4. **Knowledge Agent** hydrates the Knowledge Store (`./data/kb.json`) for each `(component, from, to)` tuple not already present — fetching from OSV.dev and GitHub Releases, then extracting structured migration info via Gemini.
5. **Classifier** assigns each finding to a bucket; Bucket 1/4 findings create a GitHub Issue immediately and are skipped by the Fixer.
6. Up to `MAX_PARALLEL_FIXES=5` Bucket 2/3 findings are processed concurrently. For each:

| Step | What happens |
|---|---|
| Clone | Local hardlink clone of `GITHUB_REPO_TARGET` into a temp directory |
| Bump pom.xml | XML-parser rewrite of the dependency version — never string-replace |
| KB context | If a KB entry exists (tier1_learned / tier2_playbook / knowledge_agent), it is rendered into `FRESH_FIX_PROMPT` — breaking changes, migration steps, and find/replace patterns become ground truth for Gemini |
| Gemini tool-use loop | ADK `Agent` runs `FRESH_FIX_PROMPT` with five tools: `grep_files` → `read_file` → `apply_file_change` → `run_maven_compile` / `run_maven_test` |
| Self-correction | If `run_maven_compile` returns `FAILURE`, Gemini reads stderr and calls `apply_file_change` again; after compilation it can run `run_maven_test`. |
| Fast path / safety gate | A successful post-bump compile skips the LLM and records a pom.xml-only change. Before commit/push, a deterministic diff review rejects unexpected changes and verifies the requested version. |
| Commit + push | Branch `fix/<component>-<safe-version>` pushed only after compile and diff gates pass. |
| Open PR | Idempotent: skips if a PR from that branch already exists. |
| Update record | `PR_OPENED` → `CI_PENDING` with `pr_number`, `branch_name`, `kb_bucket`, token usage. |

Verify PRs were opened:

```bash
gh pr list --repo your-org/vulnerable-java-app --head "fix/"
```

**Watcher (on its next 15-minute cycle):**

For each open `fix/` PR:

| CI result | Watcher action |
|---|---|
| **CI passed** | Record updated to `CI_PASSED`. **PatternLearner** extracts find/replace patterns from the PR diff via Gemini and writes a `tier1_learned` KB entry — so the next run of the same upgrade uses confirmed patterns directly. PR is ready for human review. |
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

The dashboard is its own container (`dashboard/`, server-rendered Jinja2 + HTMX pages served by FastAPI -- no JS build step) and starts automatically with `podman compose up -d` alongside `fixer-server` and `watcher` — no separate host-side install step.

Open [http://172.31.144.52:8501](http://172.31.144.52:8501). It reads `./data/tracking.json` and `./data/kb.json` from the same bind mount the fixer-server and watcher write to (read-only), and polls its own backend every 30 seconds.

**Sidebar** shows live agent health:
- **Fixer-server** — time since the last ScanPoller checkpoint write (goes yellow if the server is idle or unreachable)
- **Scan reports** — which scanner JSON files are present in `./scan-reports/` and how old they are

**Run History tab** — filterable table of every fix attempt with status, version change, PR number, KB bucket, token usage, and resolution time.

**Retry Lineage tab** — select any PR number to see the full attempt chain. Each attempt expands to show component details, token usage, and the CI failure excerpt that was injected into the retry prompt.

**Metrics tab** — resolution rate, in-progress / escalated counts, avg/p50/p95 time-to-resolution, total token consumption, and charts for status distribution and retry depth.

**Knowledge Base tab** — browse all KB entries currently in `./data/kb.json`. Filterable by source tier (`tier1_learned`, `tier2_playbook`, `knowledge_agent`). Each entry expands to show breaking changes, migration steps, find→replace patterns, and API removals.

**State machine:**

```
CREATED → PR_OPENED → CI_PENDING → CI_PASSED              (human review)
                    → CI_FAILED  → RETRY_REQUESTED → CI_PENDING  (retry loop)
                                                   → FAILED_MAX_RETRIES
```

---

### Ad-hoc / manual operations

The one-shot `fixer` service is available for manual use (it's excluded from `podman compose up -d` via a Compose profile):

```bash
# Fresh scan using reports already in ./scan-reports/
podman compose --profile manual run --rm fixer

# Fresh scan + trigger + download (AUTO_FETCH_SCAN)
podman compose --profile manual run --rm -e AUTO_FETCH_SCAN=1 fixer

# Manual retry for a specific tracking ID
podman compose --profile manual run --rm -e RETRY_TRACKING_ID=<id> fixer
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

### Testing a transitive dependency fix

Use a scanner report that names a dependency pulled by another Maven dependency
(for example `org.yaml:snakeyaml`). Then:

```bash
# Confirm the vulnerable component is in the resolved graph.
# Run this from a local checkout of the target Maven repository.
podman run --rm -v "${TARGET_REPO}:/workspace:Z" -w /workspace \
  maven:3.9-eclipse-temurin-17 mvn -B dependency:tree \
  -Dincludes=org.yaml:snakeyaml

# Run the remediation using the reports already in ./scan-reports/
podman compose --profile manual run --rm fixer

# Follow the locality decision and remediation result
podman compose logs --tail 200 fixer-server
```

Expected behavior: a one-hop transitive dependency is pinned through the
project-level `<dependencyManagement>` section without adding a direct
dependency; the image then runs `mvn compile`. Deeper chains or dependencies
introduced by complex frameworks are escalated to a GitHub triage issue.
Confirm the resulting `pom.xml`, resolved version, and CI scan before declaring
the CVE fixed. A `401 Bad credentials` message means `GITHUB_PAT` in
`config/.env` must be replaced before the fixer or watcher can fetch a scan,
clone the target repository, or open a PR.

---

### Test scenario matrix

| Scenario | How to trigger | What to observe |
|---|---|---|
| **Happy path** | `podman compose up -d`; trigger scan | `fix/` PRs opened automatically; dashboard at `:8501` shows records progressing to `CI_PASSED` |
| **Informed retry** | Force CI failure via Enforcer rule | `RETRY_REQUESTED` record has `failure_log_excerpt`; fixer-server pushes a corrective commit |
| **Retry exhaustion** | `MAX_RETRY_ATTEMPTS=1`; force CI failure | Record reaches `FAILED_MAX_RETRIES` after one retry; PR gets escalation comment |
| **New CVE mid-run** | Add a new vulnerable dep; trigger scan again | ScanPoller detects the new completed run; only the new finding gets a fresh PR |
| **Single scanner** | Remove `grype-report.json` from `scan-reports/` | Fixer logs a warning; continues with Trivy + OWASP DC only |
| **Compile error recovery** | Upgrade a library with a known API removal | First `run_maven_compile` fails; Gemini reads stderr, calls `apply_file_change` again; second compile passes and tests can run |
| **Idempotent PR** | Scan poller fires twice for the same run | Checkpoint prevents re-download; already-open PRs are skipped |
| **B1 triage issue** | Scan report contains `UNKNOWN` as safe version | Classifier assigns Bucket 1; GitHub Issue opened; no PR created; no Gemini call |
| **B4 framework triage** | Spring Boot 3→4 with no KB entry | Bucket 4; GitHub Issue with `oss-remediation-triage` label; Fixer not invoked |
| **B3 KB-assisted fix** | log4j 1.x → 2.x (tier2 playbook exists) | Bucket 3; `FRESH_FIX_PROMPT` includes playbook migration steps; check Gemini uses them |
| **Tier 1 learning** | Any B2/B3 fix that reaches `CI_PASSED` | Watcher writes `tier1_learned` entry to `./data/kb.json`; visible in dashboard KB tab |
| **Skip KB hydration** | Set `KB_HYDRATION=0` in `config/.env` | Knowledge Agent step skipped; existing playbooks still used; faster local iteration |

---

## Phase 2 — Knowledge Base & Classifier

Phase 2 inserts two new agents before the Fixer. After the ScanPoller downloads the artifact, the pipeline is:

```
[scan reports] → [Knowledge Agent] → [Classifier] → [Fixer] → ...
                   (hydrates KB)      (buckets)     (with KB)
```

### Knowledge Agent (`agents/knowledge/`)

For each `(component, old_version, new_version)` tuple in the findings:

1. Check the **Knowledge Store** — if an entry already exists, skip (no-op).
2. Fetch release notes from OSV.dev (CVE + Maven ecosystem lookup) and GitHub Releases (filtered by major-version range).
3. Call Gemini with a structured extraction prompt → JSON response with breaking changes, API removals, migration steps, find/replace patterns.
4. Persist a `knowledge_agent` entry to `./data/kb.json` (or Firestore in production).

Controlled by `KB_HYDRATION=1` (default on in `fixer-server`). Set to `"0"` to skip for faster local testing.

### Knowledge Store tiers (`agents/common/knowledge_store.py`)

Three tiers, resolved highest-priority first:

| Tier | Source | Written by |
|---|---|---|
| `tier1_learned` | Exact find/replace patterns extracted from a merged fix PR diff | Watcher PatternLearner (after `CI_PASSED`) |
| `tier2_playbook` | Engineer-authored YAML files in `playbooks/` | Loaded at startup; `log4j-1to2.yaml`, `spring-boot-2to3.yaml`, `commons-collections-3to4.yaml` |
| `knowledge_agent` | Gemini-extracted structured data from OSV.dev + GitHub Releases | Knowledge Agent (runs before each fresh fix batch) |

Lookup matches on: exact `(component, from_version, to_version)` → same component + major range → artifact ID stem + major range.

### Classifier (`agents/classifier/classifier.py`)

Assigns every finding to one of four buckets before the Fixer runs:

| Bucket | Trigger condition | Action |
|---|---|---|
| **1 — No path** | `UNKNOWN` or empty safe version | GitHub Issue created; Fixer skipped |
| **2 — Patch / Minor** | Same major version, or major upgrade that is not a complex framework | Fixer runs (KB context injected if available) |
| **3 — Major + KB** | Major version delta; KB entry found (any tier) | Fixer runs with KB injected into prompt |
| **4 — Complex / framework** | Spring Boot, Hibernate, Struts, Jersey, etc.; major delta; no KB entry | GitHub Issue created with triage label; Fixer not invoked |

The bucket and rationale are stored in the tracking record (`kb_bucket`, `kb_entry_id`). Triage issues get the `oss-remediation-triage` GitHub label.

### Tier 1 learning — PatternLearner (`agents/watcher/pattern_learner.py`)

After the Watcher detects `CI_PASSED` on a `fix/` PR:

1. Fetches the PR file diff (excluding `pom.xml`).
2. Calls Gemini to extract find/replace patterns from changed source files.
3. Merges the patterns into the existing KB entry (upgrading it to `tier1_learned`), or creates a new `tier1_learned` entry if none exists.

On the next run with the same `(component, from_major, to_major)`, the Fixer uses the confirmed patterns as ground truth.

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
| `TRACKING_STORE_PATH` | | `./data/tracking.json` locally, `/data/tracking.json` in Docker | Shared tracking state file read by the dashboard |
| `TRACKING_STORE_BACKEND` | | — | Set to `memory` only for isolated tests; otherwise the local file store is used automatically |
| `FIXER_RETRY_URL` | | — | HTTP endpoint for retry invocation (set to `http://fixer-server:8080/retry` by the watcher service) |
| `AUTO_FETCH_SCAN` | | `0` | Set to `1` on one-shot fixer runs to trigger + download the scan workflow before fixing (alternative to ScanPoller for manual use) |
| `RETRY_TRACKING_ID` | | — | Set by Watcher for retry runs, or pass manually to the one-shot fixer |
| `KB_STORE_PATH` | | `./data/kb.json` | Path to the Knowledge Store JSON file (bind-mounted into containers at `/data/kb.json`) |
| `KB_HYDRATION` | | `0` | Set to `1` to enable the Knowledge Agent pre-hydration step before each fresh fix batch. Set to `"1"` automatically by `fixer-server` in `docker-compose.yml`. Set to `"0"` to skip hydration for faster local testing (existing playbooks still apply). |
| `FIRESTORE_PROJECT` | | — | If set, `FirestoreKBStore` is used instead of `FileKnowledgeStore`. Set to your GCP project ID for production deployments. |

## Supported dependency ecosystems

The fixer supports direct and transitive remediation for:

- **Maven:** `pom.xml`, including dependency-management overrides and Maven
  transitive locality resolution.
- **npm-compatible Node projects:** `package.json` with npm, Yarn, or pnpm
  installation/build/test commands selected from `packageManager` or lockfiles.
  Locality resolution uses the selected package manager's dependency-tree
  command, including native `pnpm list` and Yarn tree output.
- **Python:** `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`,
  `Pipfile`, and `setup.cfg`. Python locality and verification run in an
  isolated per-repository virtual environment. Dependency manifest, constraint,
  and lockfile updates are transactional: failed lock refreshes restore the
  original files. Transitive pins for `pyproject.toml` and `setup.cfg` are
  written to `constraints.txt`.

Poetry, Pipenv, uv, and pdm lockfiles are refreshed when their corresponding
CLI is available. Pipenv is included in the fixer image, and `Pipfile.lock`
versions are used for isolated verification. If another project has a lockfile
but its lock tool is unavailable, the finding is surfaced for triage instead of
silently producing a stale lockfile.
