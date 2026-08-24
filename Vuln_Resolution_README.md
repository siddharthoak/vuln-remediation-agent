# Vuln Resolution — Engineering Onboarding Guide

Welcome to the team. This document is your entry point into `vuln-remediation-agent`.
It assumes zero prior context on this codebase — it will not assume you know what
"the Fixer" or "bucket 3" means before explaining it once.

The existing [`README.md`](./README.md) is the **operator's runbook** — how to stand the
system up locally with Docker and walk through a test scenario. Read that *after* this
document, when you actually want to run it. This document is the **engineer's map** — what
the system is for, how a request flows through the code, and where the open design
questions are that you should be thinking about as you ramp up.

---

## 1. The objective

Java projects accumulate vulnerable open-source dependencies (a CVE gets published against
`log4j-core 2.14.1`, say). Today that discovery-to-fix loop is manual: a scanner flags it,
someone opens a Jira ticket, an engineer eventually bumps the version in `pom.xml`, fixes
whatever broke, and opens a PR.

This project automates that loop end to end:

1. **Detect** — read vulnerability scan output (OWASP Dependency-Check, Trivy, Grype) for a
   target Java/Maven repo.
2. **Decide** — figure out, per finding, whether it's safe to auto-fix, and whether we have
   enough migration knowledge to do it well.
3. **Fix** — bump the dependency version and make whatever source-level changes the version
   bump requires (an LLM does this part, inside guardrails), verify it compiles, and open a
   PR.
4. **Recover** — if CI fails on that PR, diagnose why and push a corrective commit,
   bounded by a retry limit, escalating to a human when exhausted.
5. **Learn** — every fix that reaches green CI gets mined for the exact code patterns it
   used, so the *next* time the same upgrade is needed, the system uses a confirmed pattern
   instead of guessing again.

The system deliberately does **not** try to merge anything itself. A human always reviews
and merges the PR. The goal is to eliminate the toil of triage and first-draft fixing, not
to remove humans from the loop.

---

## 2. Repository layout

```
agents/
  fixer/            The agent that actually edits code and opens PRs.
    main.py           Entry point — three modes: fresh scan / retry / long-running server.
    code_fixer.py     The LLM tool-use loop that edits source files. Read this first.
    scan_report_client.py   Parses Trivy/Grype/OWASP-DC JSON into VulnerabilityFinding objects.
    scan_poller.py    Background thread: polls GitHub Actions for new scan runs.
    scan_fetcher.py   Triggers + downloads a scan workflow run on demand.
    repo_ops.py       git clone/branch/commit/push wrapper (GitPython).
    pr_client.py      Opens PRs and triage GitHub Issues (PyGitHub).
    instructions.md   ADK agent persona/instructions (deployment metadata, not the prompt).

  watcher/           The agent that babysits open fix PRs.
    main.py           Entry point — polls open `fix/` PRs every N minutes.
    ci_status.py      Polls GitHub Actions status for a PR.
    retry_gate.py     The ONLY place that decides "retry again" vs "give up".
    pattern_learner.py  Mines a merged fix's diff into a reusable KB entry.

  classifier/
    classifier.py     Pure-Python bucketing of each finding (no LLM, no network).

  knowledge/
    main.py            Hydrates the Knowledge Base from OSV.dev + GitHub Releases via Gemini.
    release_fetcher.py Fetches raw release-note/changelog text for the Knowledge Agent.

  common/
    tracking_store.py  The state machine / audit log for every fix attempt (JSON or Firestore).
    knowledge_store.py The three-tier Knowledge Base (see §4).

playbooks/           Hand-authored YAML migration guides (Tier 2 KB). e.g. log4j-1to2.yaml.
data/                 Local JSON stores: tracking.json, kb.json, scan checkpoints.
scan-reports/         Where downloaded/local scanner JSON output lands.
infra/agents/*.yaml   ADK deployment manifests (Cloud Run).
docker-compose.yml    Local orchestration: fixer-server + watcher + (manual) fixer profile.
streamlit_dashboard.py  Read-only dashboard over data/tracking.json and data/kb.json.
```

**Rule of thumb for navigating:** `agents/fixer/main.py` is the orchestrator for "make a
fix"; `agents/watcher/main.py` is the orchestrator for "did the fix work, and if not, try
again." Almost everything else is a component one of those two call.

---

## 3. How the code actually flows

Walk this in order — it's the same order the system executes in.

### Step 1 — Turn scanner JSON into findings
`ScanReportClient.get_vulnerability_report()` (`agents/fixer/scan_report_client.py:59`) reads
whichever of `trivy-report.json` / `grype-report.json` /
`dependency-check-report/dependency-check-report.json` are present, and merges them into a
deduplicated list of `VulnerabilityFinding(component_name, current_version,
recommended_version, severity, cve_ids)`, keyed on `(component_name, current_version)`.
Trivy's fix version wins over Grype's over OWASP DC's (OWASP DC frequently can't compute a
safe version at all, hence `"UNKNOWN — check NVD..."`).

### Step 2 — Knowledge Base hydration
`KnowledgeAgent.hydrate()` (`agents/knowledge/main.py`) runs once per batch, before
classification. For every `(component, from, to)` tuple **not already in the KB**, it fetches
OSV.dev + GitHub Releases data and asks Gemini to extract structured migration info
(breaking changes, API removals, step-by-step migration, find/replace patterns), then writes
a `knowledge_agent`-tier entry. This step can be skipped with `KB_HYDRATION=0` for faster
iteration — existing playbook/learned entries still apply.

### Step 3 — Classify every finding into a bucket
`Classifier.classify()` (`agents/classifier/classifier.py:52`) is pure Python — no LLM, no
network call. For each finding it decides one of four buckets:

| Bucket | Meaning | What happens |
|---|---|---|
| 1 | No safe version known (`UNKNOWN`) | GitHub triage Issue opened. Fixer never runs. |
| 2 | Patch/minor bump, or a major bump on a component *not* flagged complex | Fixer runs (KB injected if one happens to exist). |
| 3 | Major version bump **and** a KB entry exists (any tier) | Fixer runs with KB migration knowledge injected into the prompt. |
| 4 | Major version bump on a "complex framework" (Spring Boot, Hibernate, Struts, JSF, ...) **and no KB entry** | GitHub triage Issue opened. Fixer never runs — the risk of a wrong auto-fix is judged too high without ground truth. |

The "complex framework" list is a hardcoded set in `classifier.py:22` (`COMPLEX_FRAMEWORKS`).
Buckets 1 and 4 short-circuit straight to `PRClient.open_triage_issue()` — the Fixer/LLM is
never invoked for them, which is a deliberate cost and safety control.

### Step 4 — Fix (buckets 2 and 3 only)
This is orchestrated by `_do_fresh_scan()` in `agents/fixer/main.py:143`, up to
`MAX_PARALLEL_FIXES` (default 5) findings at a time via a `ThreadPoolExecutor`. Per finding:

1. **Clone.** The repo is cloned once (`RepoOps.clone`), then each worker does a fast local
   hardlink clone from that shared copy (`RepoOps.clone_local`) so N parallel fixes don't
   each pay a full GitHub network clone.
2. **Deterministic branch.** `RepoOps.make_branch_name()` hashes `component@version` into
   `fix/<component>-<8-char-hash>` — re-running the pipeline for the same vulnerability
   always produces the same branch, so retriggers don't create duplicate PRs.
3. **Bump `pom.xml`.** `CodeFixer._bump_pom_version()`
   (`agents/fixer/code_fixer.py:349`) is an XML-parser edit — **the LLM never touches
   `pom.xml`**. It handles three shapes: a literal version string, a Maven property
   reference (`${some.version}`, rewrites the property), and a BOM-managed dependency with
   no explicit `<version>` (adds one). If the dependency element isn't found in `pom.xml` at
   all, this raises `PomXMLError` — see §6, this is the transitive-dependency gap.
4. **Gemini tool-use loop.** `CodeFixer._call_model()` builds either `FRESH_FIX_PROMPT` or
   `RETRY_FIX_PROMPT` (`code_fixer.py:68` / `:111`) and hands it to a Google ADK `Agent` with
   four tools:
   - `grep_files(pattern, extensions?)`
   - `read_file(relative_path)`
   - `apply_file_change(relative_path, find, replace, ...)` — the `find` string must be an
     **exact verbatim substring** the model already saw via `read_file`; this is the main
     guardrail against hallucinated edits.
   - `run_maven_compile()` — runs `mvn compile -q`, no tests.
   The model is expected to grep for usages, read the affected files, apply the minimal edit,
   and compile. If compile fails, it reads the stderr and tries again — up to `MAX_TOOL_ROUNDS
   = 10` LLM turns (`code_fixer.py:48`). **Compilation success is the only automated gate
   before a PR is opened** — there's no test run, no lint, no review pass. Keep that in mind
   for §5 and §7.
5. **Commit + push.** Only after the tool loop returns cleanly.
6. **Open PR.** `PRClient.open_remediation_pr()` — idempotent, returns the existing PR if one
   is already open for that branch.
7. **Tracking record.** Every finding gets a `TrackingRecord`
   (`agents/common/tracking_store.py`) that moves through
   `CREATED → PR_OPENED → CI_PENDING → ...`. This is the audit trail the dashboard reads.

### Step 5 — Watch and retry
`agents/watcher/main.py` runs on a timer (`WATCHER_SLEEP_SECONDS`, default 15 min). For every
open `fix/`-prefixed PR not already in a terminal status:

- Poll CI (`CIStatusWatcher.wait_for_ci`).
- **CI passed** → mark `CI_PASSED`, then call `PatternLearner.learn_from_pr()`
  (`agents/watcher/pattern_learner.py`) which diffs the PR (excluding `pom.xml`), asks Gemini
  to extract the find/replace patterns actually used, and upserts a `tier1_learned` KB entry.
  This is how the system gets smarter over successive runs of the *same* upgrade.
- **CI failed** → delegate to `RetryGate.process_ci_failure()`
  (`agents/watcher/retry_gate.py:44`), the **only** place that decides retry-vs-give-up. It
  counts prior attempts for the PR; under the limit, it writes a `RETRY_REQUESTED` tracking
  record with the CI failure log attached and calls the Fixer's retry endpoint (HTTP locally,
  a Cloud Run Job invocation in GCP). At the limit, it marks `FAILED_MAX_RETRIES` and posts an
  escalation comment on the PR — automation stops, a human takes over.
- **CI timed out** → no state change, re-checked next cycle.

On the fixer side, `CodeFixer.run_retry_fix()` (`code_fixer.py:268`) **validates** the
tracking record before doing anything (`InvalidRetryError` if status isn't exactly
`RETRY_REQUESTED`, or the attempt count already exceeds the max) — this is what stops
anything other than a Watcher-issued retry from ever invoking a fix. It then checks out the
*existing* PR branch (no new branch) and runs `RETRY_FIX_PROMPT`, which puts the CI failure
log at the very top of the prompt so the model diagnoses root cause instead of repeating the
first attempt.

### The state machine, in one picture

```
CREATED → PR_OPENED → CI_PENDING → CI_PASSED              (human review from here)
                    → CI_FAILED  → RETRY_REQUESTED → CI_PENDING   (loop, bounded)
                                                    → FAILED_MAX_RETRIES → (escalated, human takes over)
```

Everything the dashboard shows is a read of `data/tracking.json` — there's no separate
"state" anywhere else, which is worth internalizing: if you want to know what the system did,
that file (or its Firestore equivalent) is the ground truth.

---

## 4. Two design ideas worth understanding by name

**Three-tier Knowledge Base** (`agents/common/knowledge_store.py`) — every dependency
upgrade the Fixer attempts can be backed by "migration knowledge": known breaking changes,
API removals, and concrete find/replace patterns, injected into the prompt via
`_render_kb_context()` (`code_fixer.py:159`). There are three tiers, highest priority first:

| Tier | Origin | Trust level |
|---|---|---|
| `tier1_learned` | Extracted from a diff that *actually passed CI* | Highest — it's proven to compile in this exact repo |
| `tier2_playbook` | Hand-authored YAML in `playbooks/` | High — an engineer wrote it deliberately |
| `knowledge_agent` | Gemini-extracted from OSV.dev/GitHub release notes, unverified | Medium — could be wrong or incomplete |

Lookup (`_find_best()` in `knowledge_store.py:249`) matches most-specific first: exact
`(component, from, to)` → same component + matching major range → artifact-stem + major
range (so `spring-boot-starter-web` can match a `spring-boot` playbook).

**The four-bucket classifier** exists as a cost/risk control, not just a routing table. Every
bucket-2/3 finding costs an LLM tool-use loop (several dollars-worth of tokens and multiple
compile cycles); buckets 1 and 4 are explicitly the cases where the team decided that cost
isn't worth it without either a known safe version or migration ground truth.

---

## 5. Can we reuse the existing `/code-review` skill here?

Worth understanding what's *not* currently in the loop: nothing reviews the LLM's diff for
quality or correctness before the PR goes up. The only automated gate is
`mvn compile -q` — no tests, no lint, no "does this edit still make semantic sense" check.
`FRESH_FIX_PROMPT` even tells the model to self-report via a JSON rationale block, but nobody
reads that rationale critically before opening the PR.

Claude Code's built-in `code-review` skill (what `/code-review` invokes) is designed to scan
a diff for correctness bugs and reuse/simplification issues — that's a reasonable fit for
*exactly* the gap above. A plausible integration point: after step 4.4 (compile succeeds,
before step 4.5 commit+push) or as a required CI check on `fix/*` PRs, run a review pass over
the diff and either block the PR / auto-retry on findings, or surface them as a PR comment
for the human reviewer to triage faster.

Two things to work out before proposing this as a real change:
- **Where it runs.** Inline inside `code_fixer.py` (another tool-use round, another Gemini or
  Claude call, delays the PR) vs. as a separate CI/GitHub Action step on the opened PR
  (async, doesn't block PR creation, but means bad PRs are visible before they're caught).
- **What "finding" means for a machine-generated dependency-bump diff.** The skill is tuned
  for human-authored diffs; a diff whose entire mandate is "only change what's strictly
  required by the version bump" has a much narrower correctness surface (wrong import,
  incomplete find/replace, unrelated refactor the model wasn't supposed to make) — those are
  worth checking for, but generic "is this good code" review may be noisy here.

This is a genuinely open question, not a decided plan — raise it with the team before
building it. Read the `code-review` skill definition to see what signal it actually produces
before committing to an integration shape.

---

## 6. Is there a better way to fix these than the current LLM loop?

The current approach — bump the version deterministically via XML parsing, then let an LLM
free-form edit source files with a compile-gate loop — is deliberately general: it works for
any dependency, any language construct, without anyone having to hand-write a migration for
every possible library. That generality is also its weakness. Things worth knowing about, and
raising if you see them bite in practice:

- **No test gate.** `run_maven_compile()` only compiles; it never runs the target repo's test
  suite. A fix can compile and still be behaviorally wrong. Adding an opt-in
  `run_maven_test()` tool (with a timeout, since test suites can be slow) is a fairly direct
  improvement, at the cost of slower fix cycles and possible false failures from flaky tests.
- **Buckets 2/3 could sometimes skip the LLM entirely.** A same-major/patch-level bump
  (bucket 2, patch case) very often needs *only* the `pom.xml` version bump — no source
  changes at all. Right now every bucket-2/3 finding still pays for a full tool-use loop even
  when `apply_file_change` is never called. A cheap pre-check (does `mvn compile` already
  succeed right after the version bump, before invoking the model at all?) could skip the LLM
  round trip for the common case and only escalate to the agent on compile failure.
- **Tier-2 playbooks are structurally similar to [OpenRewrite](https://docs.openrewrite.org/)
  recipes** (well-known Java refactoring/migration tool with existing recipes for Log4j,
  Spring Boot, etc.). For the handful of well-known frameworks in `COMPLEX_FRAMEWORKS`, a
  deterministic OpenRewrite recipe run (where one already exists upstream) would be more
  reliable than an LLM free-editing the same migration from a hand-written playbook — worth
  evaluating as an alternative fix strategy specifically for bucket 3/4 cases with known
  recipes, falling back to the LLM loop where no recipe exists.
- **The self-correction loop only sees compiler stderr**, not static analysis or dependency
  conflict output. If a bump introduces a runtime-only break (e.g., a removed reflection-based
  config key) it will compile fine and fail downstream in CI or later in the retry loop — by
  design this is caught, just later and more expensively than it could be.

None of this is a call to rewrite the approach — it's context for evaluating *when* the
current LLM-loop approach is being asked to do too much, versus when a deterministic path
would already exist.

---

## 7. How does this handle transitive dependencies?

The Fixer resolves Maven's dependency tree before classifying findings, so direct and
transitive dependencies follow separate remediation paths.

**The scanners see the whole resolved dependency graph, including transitive dependencies.**
Trivy/Grype/OWASP-DC all report on whatever `mvn dependency:tree` would show — a CVE in
`xstream`, which nobody imported directly but which `some-parent-library` pulls in
transitively, shows up as a finding exactly like a direct dependency would.

Direct findings are bumped in their declared dependency entry. One-hop transitive findings
are pinned through a project-level `<dependencyManagement>` override; deeper or higher-risk
chains are routed to a triage issue. If resolution or XML processing fails, the finding is
also surfaced as triage rather than being silently left in `CREATED`.

**How transitive vulnerabilities are actually meant to be fixed in Maven** — pick whichever
applies:
1. **Bump the direct dependency that pulls it in**, if a newer version of that direct
   dependency itself uses a patched version of the transitive one. Requires resolving
   `mvn dependency:tree` to find which direct dependency is the parent of the vulnerable
   transitive one.
2. **Force the version via `<dependencyManagement>`**, without ever adding a direct
   `<dependency>` entry — this pins the resolved version of the transitive dependency
   project-wide regardless of which direct dependency pulls it in. This is the standard fix
   when no direct-dependency bump exists yet.
3. **Exclude + re-add**, for cases where the parent dependency can't be forced cleanly (rare,
   more invasive).

On a CI retry, the existing manifest change is not applied again. The CI failure is passed to
the repair engine, including for transitive fixes, so a successful local compile cannot mask
an unresolved CI failure.

---

## 8. Where to go next

- Read `README.md` and actually run the local Docker Compose stack against a fork of
  `vulnerable-java-app` — seeing a real PR come out the other end will make everything above
  concrete.
- Read `agents/fixer/code_fixer.py` top to bottom — it's the highest-density file in the repo
  and almost everything else exists to feed it or react to its output.
- Skim `playbooks/*.yaml` to see what a Tier 2 KB entry actually looks like, then look at how
  `_render_kb_context()` turns it into prompt text.
- If you want a concrete first task, the transitive-dependency silent-drop bug in §7 is
  self-contained, well-scoped, and touches the parts of the codebase (`code_fixer.py`,
  `main.py`, `classifier.py`) you'll need to be comfortable in anyway.
