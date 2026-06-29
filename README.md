# vuln-remediation-agent

Migrated from `nexus-remediation-agent`. Same Fixer + Watcher architecture, swapped backend:

| Component | nexus-remediation-agent | vuln-remediation-agent |
|-----------|------------------------|------------------------|
| LLM | Anthropic Claude (AI Foundry) | Gemini via Vertex AI (Google ADK) |
| Vulnerability source | Nexus IQ Server API | OWASP DC / Trivy / Grype JSON reports |
| Tracking store | Azure Cosmos DB | JSON file (local) / Firestore (GCP) |
| Fixer invocation | Azure AI Foundry SDK | HTTP POST (local) / Cloud Run Job (GCP) |
| Scheduling | AAF hosted agent schedule | `docker compose run` / Cloud Scheduler |

**What is identical:** `RetryGate`, `PRClient`, `RepoOps`, `CIStatusWatcher`, `TrackingRecord`, the four tool handler methods, `FRESH_FIX_PROMPT`, `RETRY_FIX_PROMPT`, retry bound logic.

---

## Local Testing Guide

Full end-to-end walkthrough — from opening a PR on the target repo to a remediated dependency on a merged `fix/` branch.

**Pipeline at a glance:**

```
[1 Open PR] → [2 Scan runs] → [3 Download reports] → [4 Fixer (Gemini)] → [5 CI runs] → [6 Watcher + retry] → [CI_PASSED]
  GitHub         GH Actions       You (manual)            Docker              GH Actions      Docker
```

---

### Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2.20
- A GCP project with **Vertex AI API** enabled and billing active
- `gcloud` CLI installed; run `gcloud auth application-default login` before starting
- GitHub PAT with `repo` and `pull_request` scopes
- A fork (or your own copy) of `vulnerable-java-app` as the remediation target — the repo the agent will open PRs against

---

### Phase 0 — One-time local setup

```bash
# Clone this repo
git clone <vuln-remediation-agent-repo>
cd vuln-remediation-agent

# Create your .env
cp .env.example .env
```

Edit `.env` — the required values:

| Variable | Example | Where to get it |
|---|---|---|
| `GITHUB_REPO_TARGET` | `your-org/vulnerable-java-app` | The fork you set up |
| `GITHUB_PAT` | `ghp_xxxxxxxxxxxx` | GitHub → Settings → Developer settings → Tokens |
| `GOOGLE_CLOUD_PROJECT` | `my-gcp-project-id` | GCP Console → Project info |
| `GOOGLE_APPLICATION_CREDENTIALS` | `/Users/you/.config/gcloud/application_default_credentials.json` | Written by `gcloud auth application-default login` |

```bash
# Build the fixer, watcher, and fixer-server images
docker compose build
```

> **ADC credentials** — `docker-compose.yml` mounts `GOOGLE_APPLICATION_CREDENTIALS` into every container at `/gcp/adc.json`. Make sure this path on your host machine points to the file written by `gcloud auth application-default login`.

---

### Phase 1 — Trigger a security scan on the target repo

The `security-scan.yml` workflow in `vulnerable-java-app` runs on every PR targeting `main`, and on manual `workflow_dispatch`. Either path works.

**Option A — Manual dispatch (no PR needed)**

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

---

### Phase 2 — Download and stage the scan reports

After the workflow run completes, download the `vulnerability-reports` artifact and place it in `./scan-reports/`:

```bash
# Using gh CLI
gh run download \
  --repo your-org/vulnerable-java-app \
  --name vulnerability-reports \
  --dir /tmp/vuln-reports

mkdir -p scan-reports
cp /tmp/vuln-reports/trivy-report.json           scan-reports/
cp /tmp/vuln-reports/grype-report.json           scan-reports/
cp -r /tmp/vuln-reports/dependency-check-report  scan-reports/
```

Expected directory layout:

```
scan-reports/
├── trivy-report.json
├── grype-report.json
└── dependency-check-report/
    └── dependency-check-report.json
```

`ScanReportClient` reads all three formats, deduplicates findings by `(component_name, current_version)`, and presents a merged list to the Fixer. A missing file logs a warning but does not abort the run — you can test with a single scanner's output.

---

### Phase 3 — Run the Fixer (fresh scan mode)

```bash
docker compose run --rm fixer
```

**What happens inside the container:**

1. `ScanReportClient` reads the three JSON files from `/reports` (bind-mounted from `./scan-reports/`) and produces a deduplicated findings list.
2. A `CREATED` tracking record is written to `tracking.json` (on the `tracking-data` Docker volume) for each finding.
3. Up to `MAX_PARALLEL_FIXES=5` findings are processed concurrently. For each:

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

---

### Phase 4 — Run the Watcher and the retry loop

The Watcher polls CI status on all open `fix/` PRs. On failure it triggers an informed retry via the fixer-server.

**Start the fixer-server** (keep running):

```bash
docker compose up -d fixer-server
docker compose logs -f fixer-server   # tail logs in a second terminal
```

**Run the Watcher:**

```bash
# Run once; re-run to simulate the 15-minute polling schedule
docker compose run --rm watcher
```

**What happens for each open PR:**

| CI result | Watcher action |
|---|---|
| **CI passed** | Record updated to `CI_PASSED`. PR is ready for human review. |
| **CI timed out** | Warning logged. Record stays `CI_PENDING`. Re-checked on next watcher run. |
| **CI failed — under retry limit** | Record → `CI_FAILED`. Child record created: `RETRY_REQUESTED` with `failure_log_excerpt` (CI failure log, truncated to 4,000 chars). POST sent to `http://fixer-server:8080/retry`. |
| **CI failed — limit reached** | Record → `FAILED_MAX_RETRIES`. Escalation comment posted on the PR. Fixer never invoked again for this PR. |

**What fixer-server does on retry (Entry Point B):**

1. Reads the `RETRY_REQUESTED` tracking record by ID.
2. Validates: status must be exactly `RETRY_REQUESTED`; attempt number ≤ `MAX_RETRY_ATTEMPTS`.
3. Checks out the **existing PR branch** — no new branch.
4. Runs `RETRY_FIX_PROMPT` with the CI failure log at the top. Gemini sees exactly what broke and why.
5. Pushes a corrective commit to the same branch. CI reruns automatically.
6. Updates tracking record to `CI_PENDING`. Watcher picks it up on the next run.

**To force a CI failure for testing**, temporarily add a Maven Enforcer rule that checks for an undefined property:

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

Set `MAX_RETRY_ATTEMPTS=1` in `.env` to reach `FAILED_MAX_RETRIES` quickly.

---

### Phase 5 — Inspect tracking state

```bash
# Pretty-print the full tracking store
docker run --rm \
  -v vuln-remediation-agent_tracking-data:/data \
  alpine sh -c "cat /data/tracking.json" \
  | python3 -m json.tool

# Watch it update in real time (second terminal)
watch -n 5 'docker run --rm \
  -v vuln-remediation-agent_tracking-data:/data \
  alpine sh -c "cat /data/tracking.json" | python3 -m json.tool'
```

**State machine:**

```
CREATED → PR_OPENED → CI_PENDING → CI_PASSED              (human review)
                    → CI_FAILED  → RETRY_REQUESTED → CI_PENDING  (retry loop)
                                                   → FAILED_MAX_RETRIES
```

**Key fields in each record:**

| Field | What it tells you |
|---|---|
| `tracking_id` | UUID — unique per fix attempt |
| `parent_tracking_id` | Set on retry records; links back to the original attempt |
| `attempt_number` | 1 = fresh fix, 2+ = retries |
| `pr_number` | GitHub PR number opened by the agent |
| `branch_name` | `fix/<component>-<safe-version>` |
| `failure_log_excerpt` | CI failure log injected into the retry prompt (retry records only) |
| `token_usage` | Gemini prompt + completion tokens for this attempt |

**Manual retry (without fixer-server):**

```bash
# The Watcher logs the RETRY_TRACKING_ID it would have POSTed.
# Pass it directly to the fixer container:
docker compose run --rm -e RETRY_TRACKING_ID=<id-from-watcher-log> fixer
```

---

### Test scenario matrix

| Scenario | How to trigger | What to observe |
|---|---|---|
| **Happy path** | Run fixer with the default 8-CVE pom.xml | 8 `fix/` PRs opened; records progress to `CI_PASSED` |
| **Informed retry** | Force CI failure; run watcher | `RETRY_REQUESTED` record has `failure_log_excerpt`; fixer-server pushes a corrective commit |
| **Retry exhaustion** | `MAX_RETRY_ATTEMPTS=1`; force CI failure | Record reaches `FAILED_MAX_RETRIES` after one retry; PR gets escalation comment |
| **New CVE mid-run** | Add a new vulnerable dep; re-run scan; re-stage reports; re-run fixer | Only the new finding gets a fresh PR (existing records not re-processed) |
| **Single scanner** | Remove `grype-report.json` from `scan-reports/` | Fixer logs a warning; continues with Trivy + OWASP DC only |
| **Compile error recovery** | Upgrade a library with a known API removal | First `run_maven_compile` fails; Gemini reads stderr, calls `apply_file_change` again; second compile passes |
| **Idempotent PR** | Run fixer twice without merging PRs | Second run skips PR creation for branches that already have an open PR |

---

## Phase 2 Roadmap — Knowledge Base & Classifier

> **Not yet implemented.** These agents are planned; see `nexus-remediation-agent/DiscussionPoints-v1.md` for the full specification. The current Fixer goes directly from scan reports to the Gemini tool-use loop, relying on parametric (training-data) knowledge.

Phase 2 inserts two new agents before the Fixer, changing what happens in Phase 3 above:

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
| `GITHUB_PAT` | ✓ | — | PAT with `repo` + `pull_request` scopes |
| `GOOGLE_CLOUD_PROJECT` | ✓ | — | GCP project for Vertex AI |
| `VERTEX_LOCATION` | | `us-central1` | Vertex AI region |
| `VERTEX_MODEL` | | `gemini-2.0-flash-001` | Gemini model name |
| `GOOGLE_APPLICATION_CREDENTIALS` | ✓ | ADC default path | Path to ADC JSON on host machine |
| `MAX_RETRY_ATTEMPTS` | | `3` | Hard retry bound per PR |
| `MAX_PARALLEL_FIXES` | | `5` | Concurrent fixer workers |
| `CI_POLL_INTERVAL` | | `30` | Seconds between CI status checks |
| `CI_TIMEOUT_SECONDS` | | `1800` | Max wait for CI (30 min) |
| `SCAN_REPORT_PATH` | | `/reports` | Directory containing scanner JSON files |
| `TRACKING_STORE_PATH` | | `/data/tracking.json` | State file path inside container |
| `FIXER_RETRY_URL` | | — | HTTP endpoint for retry invocation (fixer-server mode) |
| `RETRY_TRACKING_ID` | | — | Set by Watcher for Mode B (retry) runs |
# vuln-remediation-agent
