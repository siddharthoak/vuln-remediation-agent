# Vuln-Remediation-Agent: Master Architectural & Engineering Guide

> **Author / Maintainer Context:**  
> Welcome to the team! This document is the definitive master architecture, implementation reference, and engineering deep-dive for `vuln-remediation-agent`. It was written to onboard you from zero context to complete technical mastery of the codebase: what problem this system solves, how it is architected, why specific technologies and languages were chosen, how every single module and file works, the battle-tested security controls implemented after extensive audits, and answers to the tough technical questions you will face as you build and maintain this platform.

---

## Table of Contents

1. [Executive Summary & Project Mission](#1-executive-summary--project-mission)
2. [Heritage & Evolutionary Timeline: From Nexus to GCP/Vertex](#2-heritage--evolutionary-timeline-from-nexus-to-gcpvertex)
3. [The 13 Security & Architectural Audit Breakthroughs](#3-the-13-security--architectural-audit-breakthroughs)
4. [Technology Stack & Rationale: "Why Did We Build It This Way?"](#4-technology-stack--rationale-why-did-we-build-it-this-way)
   - [Why Python 3.11+?](#why-python-311)
   - [Why Google ADK + Vertex AI (Gemini 2.5 Flash)?](#why-google-adk--vertex-ai-gemini-25-flash)
   - [Why Pluggable Engines (ADK vs. Gemini CLI)?](#why-pluggable-engines-adk-vs-gemini-cli)
   - [Why Multi-Scanner Support (Trivy, Grype, OWASP Dependency-Check)?](#why-multi-scanner-support-trivy-grype-owasp-dependency-check)
   - [Why Server-Rendered FastAPI + HTMX over a React/Vue SPA?](#why-server-rendered-fastapi--htmx-over-a-reactvue-spa)
   - [Why Dual Storage: FileLock JSON + Google Cloud Firestore?](#why-dual-storage-filelock-json--google-cloud-firestore)
   - [Why GitPython & GitHub App JWT Authentication?](#why-gitpython--github-app-jwt-authentication)
5. [End-to-End System Architecture](#5-end-to-end-system-architecture)
   - [High-Level Architectural Diagram](#high-level-architectural-diagram)
   - [Service Topography in Podman / Docker Compose](#service-topography-in-podman--docker-compose)
   - [Dashboard Controls, Buttons & Live Views](#dashboard-controls-buttons--live-views)
6. [Repository & Component Layout](#6-repository--component-layout)
7. [The Five-Stage Remediation Pipeline](#7-the-five-stage-remediation-pipeline)
   - [Stage 1: Ingestion & Scan Polling](#stage-1-ingestion--scan-polling)
   - [Stage 2: Dependency Locality Resolution & Hygiene](#stage-2-dependency-locality-resolution--hygiene)
   - [Stage 3: The Three-Tier Knowledge Base & Pre-Hydration](#stage-3-the-three-tier-knowledge-base--pre-hydration)
   - [Stage 4: Risk-Based Triage & 4-Bucket Classification](#stage-4-risk-based-triage--4-bucket-classification)
   - [Stage 5: Autonomous Code Fixer & Pluggable Engine Execution](#stage-5-autonomous-code-fixer--pluggable-engine-execution)
8. [Multi-Ecosystem Engine Deep-Dive](#8-multi-ecosystem-engine-deep-dive)
   - [Maven Ecosystem (`pom.xml`)](#maven-ecosystem-pomxml)
   - [Node.js / npm Ecosystem (`package.json`, npm, yarn, pnpm)](#nodejs--npm-ecosystem-packagejson-npm-yarn-pnpm)
   - [Python Ecosystem (`pyproject.toml`, `requirements.txt`, Pipfile, Poetry, uv, pdm)](#python-ecosystem-pyprojecttoml-requirementstxt-pipfile-poetry-uv-pdm)
9. [The Autonomous Watcher, CI Monitoring & Closed-Loop Learning](#9-the-autonomous-watcher-ci-monitoring--closed-loop-learning)
   - [CI Status Polling & Asynchronous Verification](#ci-status-polling--asynchronous-verification)
   - [The Retry Gate & Hard Retry Bounds](#the-retry-gate--hard-retry-bounds)
   - [PatternLearner: Mining Green PRs into Tier 1 Knowledge](#patternlearner-mining-green-prs-into-tier-1-knowledge)
10. [State Machine, Persistence & Audit Trail](#10-state-machine-persistence--audit-trail)
11. [Advanced Capabilities](#11-advanced-capabilities)
    - [Multi-Repository Transitive Chain Coordination](#multi-repository-transitive-chain-coordination)
    - [Night Mode Scheduled Execution](#night-mode-scheduled-execution)
    - [Clean-Slate Environment Reset with Knowledge Preservation](#clean-slate-environment-reset-with-knowledge-preservation)
12. [Defensive Engineering, Sandboxing & Security Controls](#12-defensive-engineering-sandboxing--security-controls)
13. [Developer & Operator Handbook](#13-developer--operator-handbook)
    - [Prerequisites & Local Bootstrapping](#prerequisites--local-bootstrapping)
    - [Configuration Reference (.env and config.json)](#configuration-reference-env-and-configjson)
    - [Authoring a Tier 2 Playbook](#authoring-a-tier-2-playbook)
    - [Adding a New Package Ecosystem](#adding-a-new-package-ecosystem)
    - [Running Tests & Validating Changes](#running-tests--validating-changes)
14. [The 25 Essential Engineering Questions (FAQ)](#14-the-25-essential-engineering-questions-faq)
15. [Future Vision & Architectural Roadmap](#15-future-vision--architectural-roadmap)

---

## 1. Executive Summary & Project Mission

### The Core Problem: The Open Source Dependency Vulnerability Gap
Modern software engineering depends entirely on open-source software (OSS) dependencies. A typical production enterprise application imports hundreds, sometimes thousands, of third-party libraries across direct and transitive dependency trees. Vulnerabilities (Common Vulnerabilities and Exposures, or CVEs) are constantly discovered in these libraries.

Traditionally, addressing an open-source vulnerability is an expensive, slow, and human-toil-heavy manual workflow:
1. A security scanner (e.g., Trivy, Grype, OWASP Dependency-Check, Snyk, Nexus IQ) flags a vulnerable package in a CI pipeline.
2. An alert or Jira ticket is filed, interrupting development teams.
3. An engineer manually pulls the repository, navigates the build manifest (`pom.xml`, `package.json`, or `pyproject.toml`), bumps the version, and encounters compilation or test failures due to breaking API changes between the two versions.
4. The engineer spends hours searching release notes and migration guides, editing source files, verifying locally, pushing a branch, and opening a Pull Request.
5. If CI fails on the branch, another cycle of investigation and fixing is triggered.

Because this cycle is slow and tedious, critical security vulnerabilities often linger in codebases for weeks or months, exposing systems to exploitation.

### The System Objective
`vuln-remediation-agent` automates this entire discovery-to-verified-PR cycle end-to-end:
- **Detects** vulnerability findings from industry-standard scanners (Trivy, Grype, OWASP Dependency-Check).
- **Analyzes** dependency locality (determining whether a vulnerability is direct or transitive, and tracing its ancestor hierarchy).
- **Triages & Classifies** the risk of each finding using deterministic rules into four distinct processing buckets.
- **Hydrates Knowledge** autonomously from OSV.dev and GitHub Releases to discover breaking changes and code migration steps.
- **Remediates** code using surgical XML/JSON manifest edits combined with a bounded LLM tool-use loop (Google ADK / Vertex AI Gemini 2.5) that inspects source files, makes verbatim substring edits, and compiles locally.
- **Validates** all changes through deterministic automated git diff reviews and local test execution suites prior to opening a PR.
- **Monitors & Self-Heals** PRs via a dedicated background Watcher daemon that reads remote GitHub Actions CI logs, feeds failure logs back into the LLM repair engine on the same branch, and applies corrective commits up to a hard retry limit.
- **Learns Continuously** by mining git diffs of successful fixes that passed CI, storing verified find/replace patterns into a persistent Knowledge Base so future upgrades of the same library become instantaneous, deterministic, and token-free.

### Core Philosophy: Human-in-the-Loop & Zero-Hallucination Guardrails
1. **The agent never merges code.** It produces clean, compilable, CI-passing, auditable Pull Requests with detailed rationale. A human engineer retains final authority to review and merge.
2. **The LLM never edits build manifests.** Versions in `pom.xml`, `package.json`, and Python requirement files are updated strictly via deterministic parsers (XML trees, JSON serializers, or AST transformers).
3. **The LLM cannot hallucinate free-form edits.** File edits require an exact verbatim substring match previously returned by a file inspection tool call.
4. **Fast paths bypass the LLM entirely.** When bumping a manifest compiles and tests cleanly without source changes, the system skips LLM invocation, saving significant latency and API costs.

---

## 2. Heritage & Evolutionary Timeline: From Nexus to GCP/Vertex

The system originally began as `nexus-remediation-agent`. Understanding this evolution explains why certain abstractions exist and how the architecture was hardened:

| Architectural Dimension | Legacy (`nexus-remediation-agent`) | Current (`vuln-remediation-agent`) | Technical Rationale |
| :--- | :--- | :--- | :--- |
| **LLM Engine** | Anthropic Claude 3.5 Sonnet on Azure AI Foundry | Gemini 2.5 Flash on Google Vertex AI (Google ADK) | Lower latency, larger context window, superior cost economics, and native Google ADK agent support. |
| **Vulnerability Source** | Proprietary Nexus IQ Server API | Multi-scanner standard JSON reports (Trivy, Grype, OWASP DC) | Vendor independence. Can ingest scans from GitHub Actions, local runs, or any CI provider without commercial server licenses. |
| **State Tracking** | Azure Cosmos DB | Dual-mode: Local Atomic JSON (`FileTrackingStore`) + Cloud Firestore (`FirestoreTrackingStore`) | Zero external infrastructure required for local simulation and air-gapped development, seamless GCP scalability in production. |
| **Agent Scheduling** | Azure AI Foundry Hosted Agent Schedules | Background daemons (`podman-compose` / `docker-compose`) & Cloud Scheduler | Standardized container orchestration runnable anywhere (developer laptop, on-prem VM, Cloud Run). |
| **Fixer Invocation** | Azure AI Project SDK Run Triggers | Asynchronous HTTP Server (`:8080`) & Cloud Run Jobs v2 API | Standard REST/HTTP communication locally; robust serverless container execution in GCP. |
| **Supported Ecosystems** | Maven only (monolithic implementation in `code_fixer.py`) | Pluggable `PackageEcosystem` (Maven, npm/yarn/pnpm Node.js, pip/poetry/uv Python) | Clean separation of concerns; enables non-Java enterprise stacks without rewriting the core agent. |

### Preserved Core Abstractions
Despite swapping the underlying LLM provider, vulnerability sources, and cloud backends, the foundational core abstractions proved robust and were preserved:
- The **4-Bucket Classification Taxonomy**.
- The **TrackingRecord Dataclass & State Machine**.
- The **RetryGate Bounded Attempt Counter**.
- The **PRClient Idempotent PR Operations**.
- The **ADK Local Function Tool Interfaces** (`read_file`, `grep_files`, `apply_file_change`, `compile`, `test`).
- The **Prompts Structure** (`FRESH_FIX_PROMPT`, `RETRY_FIX_PROMPT`).

---

## 3. The 13 Security & Architectural Audit Breakthroughs

Before this codebase was finalized, it underwent a rigorous security and architectural audit. Understanding these 13 issues and their fixes is essential for any engineer touching this repository:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        THE 13 AUDIT FIXES AT A GLANCE                           │
├────────────────────────────────┬────────────────────────────────────────────────┤
│ 1. Maven Transitive Locality   │ Pinned depth-2 transitives via <depManagement> │
│ 2. Risk-Based Transitive Gate  │ Escalated depth >= 3 & frameworks to triage    │
│ 3. PomXMLError Handling        │ Clear error surfaces, no silent drops          │
│ 4. Tracking Visibility         │ Unexpected failures marked ESCALATED + Issue   │
│ 5. CI Retry Correctness        │ is_retry skips manifest bump, passes CI log    │
│ 6. Fast-Path LLM Bypass        │ Compile-first after bump; skips LLM if green   │
│ 7. Runtime Test Gate           │ Mandatory bounded mvn test before git commit   │
│ 8. Deterministic Diff Review   │ Read-only git status/diff check rejects leaks  │
│ 9. Doc & Config Consistency    │ Aligned documentation with actual agent gates │
│ 10. Maven DFS Precedence Bug   │ Full-tree scan prioritizes depth-1 over DFS    │
│ 11. Concurrency Race Conditions│ FileLock (O_CREAT|O_EXCL) + atomic os.replace  │
│ 12. Path Traversal Sandboxing  │ Enforced is_relative_to cryptographic check    │
│ 13. Build Secret Scrubbing     │ Scrubbed GITHUB_PAT & ADC from build env       │
└────────────────────────────────┴────────────────────────────────────────────────┘
```

### Detailed Breakdown of Audit Fixes:

1. **Maven Transitive-Dependency Remediation**
   - *Problem:* Scanners reported vulnerabilities from the complete resolved dependency graph, but the agent only looked for `<dependency>` tags in `pom.xml`. Transitive findings failed to match and were silently dropped.
   - *Fix:* Added `mvn dependency:tree` resolution. Transitive findings at depth 2 are pinned via project-level `<dependencyManagement>` blocks without declaring direct dependencies.

2. **Risk-Based Transitive Triage**
   - *Problem:* Forcing arbitrary versions deep in a dependency tree has a massive blast radius and can break runtime classpaths.
   - *Fix:* Automated remediation is restricted to depth 2 (one hop below a direct dependency). Findings at depth 3+ or introduced by complex frameworks are routed to human triage issues.

3. **Explicit XML & Manifest Processing Errors**
   - *Problem:* Malformed XML or missing dependency elements caused silent drops or unhandled exceptions that left records orphaned.
   - *Fix:* Created `PomXMLError`, `PackageJsonError`, and `PythonManifestError`. Errors route findings to triage issues and mark the tracking record `TRIAGE_OPENED`.

4. **Unexpected-Failure Visibility**
   - *Problem:* Generic unhandled exceptions logged an error and exited, leaving tracking records stuck in `CREATED` indefinitely.
   - *Fix:* Wrapped worker flows to update tracking status to `ESCALATED`, attach the traceback/error excerpt, and open an escalation issue on GitHub.

5. **CI Retry Correctness**
   - *Problem:* When retrying a CI failure on an existing branch, the fixer re-attempted the manifest version bump. Because the manifest was already bumped, it failed to find the old version, incorrectly misclassifying the finding.
   - *Fix:* Introduced `is_retry=True`. Retries skip reapplying the manifest edit, check out the existing branch, and feed the CI failure log directly into `RETRY_FIX_PROMPT`.

6. **LLM Cost Reduction via Compile Fast-Path**
   - *Problem:* Every single dependency bump invoked the LLM, even when simply changing the version number in the manifest was 100% sufficient (common in patch and minor updates).
   - *Fix:* After a direct bump, the ecosystem executes `verify_build()`. If compilation succeeds, it returns immediately without calling the LLM, saving hundreds of thousands of tokens and cutting latency from minutes to seconds.

7. **Runtime Verification with Test Suites**
   - *Problem:* Code that compiles can still fail at runtime due to behavioral regressions or broken contract tests.
   - *Fix:* Added a mandatory `verify_tests()` gate (`mvn -B test -q`, `npm test`, or `pytest`) prior to committing. Test failures escalate to human review and prevent publishing broken branches.

8. **Deterministic Automated Diff Review**
   - *Problem:* LLMs can hallucinate edits to unrelated files, drop license headers, or format code unnecessarily.
   - *Fix:* Implemented `review_dependency_diff()` in `repo_ops.py`. It inspects `git status --porcelain` and `git diff`. Untracked files, unapproved file modifications, or missing version changes instantly reject the fix and abort the push.

9. **Documentation & Config Consistency**
   - *Problem:* Documentation referenced obsolete flags and missing environment variables.
   - *Fix:* Synchronized `.env.example`, `config.yaml.example`, and operational documentation with real code paths.

10. **Maven DFS Precedence Bug**
    - *Problem:* `mvn dependency:tree` outputs in Depth-First Search order. If a direct dependency also appeared as a transitive dependency of another package earlier in the output, the parser falsely marked it as transitive and attempted a `<dependencyManagement>` override instead of a direct bump.
    - *Fix:* Refactored `_parse_tree()` in `maven.py` to search the entire tree for a `depth == 1` match first before falling back to transitive matches.

11. **Race Conditions in Local Persistence**
    - *Problem:* Multi-threaded and multi-processed workers reading and writing `tracking.json` and `kb.json` simultaneously caused race conditions, truncated JSON, and `JSONDecodeError`.
    - *Fix:* Built `FileLock` (`agents/common/file_lock.py`) using atomic OS-level file descriptor locks (`os.O_CREAT | os.O_EXCL`). Writes write to a temporary file (`.tmp.<pid>_<uuid>`) and perform an atomic `os.replace`.

12. **Path Traversal & Arbitrary File Sandboxing**
    - *Problem:* In `adk_vertex.py`, tool handlers combined `self._repo_path / relative_path`. Path traversal sequences (`../../etc/passwd` or absolute `/gcp/adc.json`) allowed prompt injection attacks to read or overwrite host files.
    - *Fix:* Added cryptographic path sandboxing:
      ```python
      target = (self._repo_path / relative_path).resolve()
      if not target.is_relative_to(self._repo_path.resolve()):
          return "ERROR: Path traversal detected."
      ```

13. **Build Subprocess Secret Scrubbing**
    - *Problem:* The fixer executed Maven/npm commands using `subprocess.run()`, inheriting all container environment variables. A malicious dependency or prompt injection modifying a build script could dump `GITHUB_PAT` or GCP credentials.
    - *Fix:* Build runners explicitly sanitize environment dictionaries before executing subprocesses, stripping `GITHUB_PAT`, `GOOGLE_APPLICATION_CREDENTIALS`, and other sensitive tokens.

---

## 4. Technology Stack & Rationale: "Why Did We Build It This Way?"

### Why Python 3.11+?
When building an agentic platform that interacts with git repositories, build tools, XML/JSON manifests, and AI APIs, language choice dictates development speed and maintenance overhead:
1. **Rich Subprocess & Process Management:** Python's `subprocess`, `multiprocessing`, and `concurrent.futures` enable robust execution of build tools (`mvn`, `npm`, `pnpm`, `yarn`, `pipdeptree`), timeouts, and stdout/stderr capture without external runtime dependencies.
2. **First-Class AI/ML Ecosystem:** Google ADK, Google GenAI SDK, and Vertex AI libraries are maintained as tier-1 Python packages.
3. **Advanced AST & Manifest Parsing:** Built-in XML parsing (`xml.etree.ElementTree`), JSON processing, and access to `GitPython` and `PyGithub` allow clean manipulation of codebases without shell scripting.
4. **Strong Typing with Dataclasses & Protocols:** Python's `typing.Protocol` enables compile-time type-checked structural subtyping (duck typing) for `PackageEcosystem`, `FixEngine`, and `TrackingStoreProtocol`.

### Why Google ADK + Vertex AI (Gemini 2.5 Flash)?
1. **Google Agent Development Kit (ADK):** Provides high-level abstractions for defining agents (`Agent`), tools (`FunctionTool`), sessions (`InMemorySessionService`), and execution runners (`Runner`).
2. **Gemini 2.5 Flash Economics & Speed:** High-speed token generation with a 1M+ token context window. In a remediation loop where compiler error logs and file contents must be inspected across multiple rounds, Gemini Flash provides sub-second tool response times at a fraction of the cost of frontier reasoning models.
3. **Vertex AI Enterprise Readiness:** Authentication via Google Cloud Application Default Credentials (ADC), enterprise IAM roles, and private VPC compliance for enterprise deployments.

### Why Pluggable Engines (ADK vs. Gemini CLI)?
The architecture decouples the fixer from Vertex AI using the `FixEngine` protocol (`agents/fixer/engines/base.py`):
- **`AdkVertexEngine` (Default):** Runs an in-memory tool loop via Google ADK. The model calls Python functions (`read_file`, `grep_files`, `apply_file_change`, `run_maven_compile`, `run_maven_test`) inside the container.
- **`GeminiCliEngine` (Experimental):** Executes Google's official Gemini CLI (`gemini`) in a headless subprocess with `--yolo` and `--skip-trust`. Designed for zero-dependency local environments where only the Node.js CLI binary is available.
- *Switching engines* requires only setting `FIX_ENGINE=adk` or `FIX_ENGINE=gemini_cli`.

### Why Multi-Scanner Support (Trivy, Grype, OWASP Dependency-Check)?
No single security scanner is complete:
- **Trivy (Aqua Security):** Exceptional at detecting OS packages and language manifests, provides accurate `FixedVersion` fields.
- **Grype (Anchore):** Deep vulnerability database, parses nested archives and PURLs effectively.
- **OWASP Dependency-Check:** The enterprise standard for Java/Maven, but notoriously struggles to calculate recommended safe versions (often outputting `"UNKNOWN"`).

By parsing all three formats in `ScanReportClient` (`agents/fixer/scan_report_client.py`), the agent merges findings, deduplicates by `(component, version)`, aggregates CVE IDs, and takes the highest severity rating. Trivy and Grype safe versions resolve the missing version gaps left by OWASP DC.

### Why Server-Rendered FastAPI + HTMX over a React/Vue SPA?
The dashboard (`dashboard/`) was intentionally built with **FastAPI + Jinja2 + HTMX** rather than a modern JavaScript single-page application:
1. **Zero JS Build Pipeline:** No `node_modules`, no Webpack/Vite bundler, no TypeScript compilation step. The container image builds in under 5 seconds from `python:3.11-slim`.
2. **Self-Polling Fragments:** HTMX attributes like `hx-get="/partials/run-history"` combined with `hx-trigger="every 30s"` allow individual UI widgets to poll the server independently. When a user switches tabs, the discarded DOM element stops polling automatically—zero JavaScript state management required.
3. **Vendored Assets:** `htmx.min.js` is vendored locally in `static/`, ensuring the dashboard operates in completely air-gapped or offline networks without CDN access.

### Why Dual Storage: FileLock JSON + Google Cloud Firestore?
State management implements `TrackingStoreProtocol` (`agents/common/tracking_store.py`):
- **Local / Developer Environment (`FileTrackingStore`):** Stores state in a mounted JSON file (`data/tracking.json`). It uses POSIX/Windows file locking (`FileLock`) and atomic `.tmp` file replacement so multiple concurrent containers and worker processes can safely read and write without data corruption.
- **GCP Production Environment (`FirestoreTrackingStore`):** Automatically activated when `FIRESTORE_PROJECT` is set. Replaces file storage with Google Cloud Firestore (Native mode) using ADC authentication, supporting distributed Cloud Run instances.

### Why GitPython & GitHub App JWT Authentication?
`RepoOps` uses GitPython rather than shelling out to raw `git clone` commands:
1. **Leak Prevention:** Subprocess commands like `git clone https://<PAT>@github.com/...` expose access tokens in process listings (`ps aux`) and OS logs. GitPython handles authentication headers programmatically.
2. **Hardlink Local Clones:** To enable parallel fixes without cloning the repository over the network multiple times, `RepoOps.clone_local()` creates local hardlinked clones from a single shared base clone, cutting disk and network usage to near zero.
3. **GitHub App Authentication:** `agents/common/github_auth.py` generates RS256 JWT tokens using the GitHub App's private key PEM and exchanges them for short-lived (1-hour) installation tokens. If a token expires during an 8-hour batch run, `PRClient` transparently refreshes it.

---

## 5. End-to-End System Architecture

### High-Level Architectural Diagram

```
                              ┌────────────────────────────────────────────────────────┐
                              │                 Target GitHub Repository               │
                              │           (e.g., your-org/vulnerable-app)              │
                              └───────┬────────────────────────────────┬───────────────┘
                                      │ (1) Dispatch / Push            ▲
                                      ▼                                │ (6) Open PR /
                        ┌───────────────────────────┐                  │     Push Retries
                        │   GitHub Actions CI/CD    │                  │
                        │    security-scan.yml      │                  │
                        └─────────────┬─────────────┘                  │
                                      │ (2) Artifacts:                 │
                                      │     trivy, grype, owasp        │
                                      ▼                                │
  ┌────────────────────────────────────────────────────────────────────┴───────────────────────────────────┐
  │                                    VULN-REMEDIATION-AGENT SYSTEM                                       │
  │                                                                                                        │
  │  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
  │  │                                  SERVICE: fixer-server (:8080)                                   │  │
  │  │                                                                                                  │  │
  │  │   ┌────────────────────┐     (3) Download     ┌────────────────────┐                             │  │
  │  │   │     ScanPoller     │ ───────────────────► │ ScanReportClient   │                             │  │
  │  │   │  (Background 60s)  │                      │ (JSON Parser/Dedup)│                             │  │
  │  │   └────────────────────┘                      └─────────┬──────────┘                             │  │
  │  │                                                         ▼                                        │  │
  │  │   ┌────────────────────┐     (4) Tree Locality┌────────────────────┐                             │  │
  │  │   │ KnowledgeAgent     │ ◄─────────────────── │ PackageEcosystem   │                             │  │
  │  │   │ (OSV.dev + Gemini) │                      │ (Maven/npm/Python) │                             │  │
  │  │   └─────────┬──────────┘                      └─────────┬──────────┘                             │  │
  │  │             ▼ (Hydrate KB)                              ▼                                        │  │
  │  │   ┌────────────────────┐                      ┌────────────────────┐                             │  │
  │  │   │   KnowledgeStore   │                      │     Classifier     │                             │  │
  │  │   │ (T1/T2/T3 Storage) │ ◄─────────────────── │ (4-Bucket Routing) │                             │  │
  │  │   └─────────┬──────────┘                      └─────────┬──────────┘                             │  │
  │  │             │                                           │                                        │  │
  │  │             │                                  ┌────────┴────────┐                               │  │
  │  │             │                         Bucket 1,4                 Bucket 2,3                      │  │
  │  │             │                                  ▼                 ▼                               │  │
  │  │             │                         ┌────────────────┐ ┌───────────────────────────────────┐   │  │
  │  │             │                         │   PRClient     │ │ ProcessPoolExecutor (Workers)     │   │  │
  │  │             │                         │ (Triage Issue) │ │   ┌─────────────────────────────┐ │   │  │
  │  │             │                         └────────────────┘ │   │ CodeFixer + Fast Path       │ │   │  │
  │  │             └──────────────────────────────────────────┼─┼─► │ (Direct Bump -> verify_build)│ │   │  │
  │  │                                                        │ │   └──────────────┬──────────────┘ │   │  │
  │  │                                                        │ │                  │ Compile Fail   │   │  │
  │  │                                                        │ │                  ▼                │   │  │
  │  │   ┌────────────────────┐        POST /retry            │ │   ┌─────────────────────────────┐ │   │  │
  │  │   │ HTTP Retry Server  │ ◄─────────────────────────┐   │ │   │ AdkVertexEngine (Gemini 2.5)│ │   │  │
  │  │   │ (Spawns Retry Fix) │                           │   │ │   │ (read/grep/apply/test loop) │ │   │  │
  │  │   └────────────────────┘                           │   │ │   └──────────────┬──────────────┘ │   │  │
  │  │                                                    │   │ │                  ▼                │   │  │
  │  │                                                    │   │ │   ┌─────────────────────────────┐ │   │  │
  │  │                                                    │   │ │   │ verify_tests + Diff Review  │ │   │  │
  │  │                                                    │   │ │   └─────────────────────────────┘ │   │  │
  │  │                                                    │   │ └──────────────────┬────────────────┘   │  │
  │  │                                                    │   └────────────────────┼────────────────────┘  │
  │  │                                                    │                        │ Push fix branch       │
  │  │                                                    │                        ▼                       │
  │  │                                                    │              ┌──────────────────┐              │
  │  │                                                    │              │ PRClient         │ ─────────────┤
  │  │                                                    │              │ (Consolidated PR)│              │
  │  │                                                    │              └──────────────────┘              │
  │  └────────────────────────────────────────────────────┼────────────────────────────────────────────────┘  │
  │                                                       │                                                    │
  │  ┌────────────────────────────────────────────────────┴─────────────┐  ┌────────────────────────────────┐  │
  │  │ SERVICE: watcher (Daemon Loop every 15m)                         │  │ SERVICE: dashboard (:8501)     │  │
  │  │                                                                  │  │                                │  │
  │  │   ┌───────────────────┐          ┌───────────────────────────┐   │  │  FastAPI Server (HTMX/Jinja2)  │  │
  │  │   │ CIStatusWatcher   │ ───────► │ RetryGate                 │   │  │  - Live Agent Health Sidebar   │  │
  │  │   │ (Polls GH Actions)│          │ (Enforces Retry Budget)   │   │  │  - Run History & Filtering     │  │
  │  │   └─────────┬─────────┘          └─────────────┬─────────────┘   │  │  - Retry Lineage Explorer      │  │
  │  │             │ CI Passed                        │ CI Failed       │  │  - System Performance Metrics  │  │
  │  │             ▼                                  ▼ (Under limit)   │  │  - Knowledge Base Viewer       │  │
  │  │   ┌───────────────────┐                  POST /retry             │  │  - Multi-Repo Config & Reset   │  │
  │  │   │ PatternLearner    │          (Triggers corrective commit)    │  └────────────────┬───────────────┘  │
  │  │   │ (Mines PR Diff)   │                                          │                   │                  │
  │  │   └─────────┬─────────┘                                          │                   │                  │
  │  │             ▼ Upserts Tier 1                                     │                   │                  │
  │  └─────────────┼────────────────────────────────────────────────────┘                   │                  │
  │                │                                                                        │                  │
  │                ▼                                                                        ▼                  │
  │       ┌──────────────────┐                                                     ┌──────────────────┐        │
  │       │  data/kb.json    │ ◄────────────────────────────────────────────────── │ data/tracking.json│       │
  │       │ (Knowledge Store)│                                                     │ (Audit Trail)    │        │
  │       └──────────────────┘                                                     └──────────────────┘        │
  └────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Service Topography in Podman / Docker Compose

The application is fully containerized in `docker-compose.yml` into three always-on services and one on-demand profile:

1. **`fixer-server` (`agents/fixer/Dockerfile`):**
   - Runs `ScanPoller` in a background thread checking GitHub Actions every 60s.
   - Runs an HTTP server on `:8080` exposing `/status`, `/scan`, and `/retry`.
   - Mounts `./scan-reports` to `/reports`, `./data` to `/data`, `./config` to `/config`, and the GCP service account key to `/gcp/adc.json`.
2. **`watcher` (`agents/watcher/Dockerfile`):**
   - Runs `agents/watcher/main.py` in daemon mode (`WATCHER_DAEMON=1`).
   - Wakes up every `WATCHER_SLEEP_SECONDS` (default 60s locally, 900s in production).
   - Evaluates CI status on open PRs, triggers `POST /retry` on `fixer-server:8080` when CI fails, and runs `PatternLearner` when CI passes.
3. **`dashboard` (`dashboard/Dockerfile`):**
   - Runs Uvicorn serving the FastAPI app on internal port `8000`, mapped to host port `8501`.
   - Read-only bind-mount of `/data` and `/reports`—observes pipeline state without interfering with agents.
4. **`fixer` (Manual Profile):**
   - Defined under profile `manual`. Allows running one-shot fresh scans (`podman compose --profile manual run --rm fixer`) or targeted tracking retries.

### Dashboard Controls, Buttons & Live Views

The dashboard is a server-rendered FastAPI application using Jinja2 templates and HTMX.
Buttons do not run browser-side remediation logic. Each button sends an HTTP request to
the dashboard, the dashboard updates shared configuration or dispatches an agent action,
and the returned HTML fragment replaces the relevant card. This means the dashboard is
an operator control plane and observation surface; the `fixer-server` and `watcher`
remain responsible for the actual background work.

#### Target Repository card

| Control | Request | Detailed behavior |
| :--- | :--- | :--- |
| **Repository / Chain input** | Form field | Accepts one repository or multiple repositories separated by commas, semicolons, or newlines. Names are normalized, duplicates are removed from uploaded chains, and a multi-repository chain is stored in the configured order. The multi-repository coordinator later resolves the dependency graph and processes repositories bottom-up rather than blindly using the text order. |
| **GitHub PAT field** | Form field | Supplies or replaces the GitHub credential when a GitHub App is not configured. When a GitHub App is active, leaving this field empty preserves App-based authentication; stored PAT values are masked in the UI. |
| **Nightly Start Time** | Form field | Sets the daily `HH:MM` start time interpreted in `NIGHTLY_RUN_TIMEZONE` (default `Asia/Kolkata`). The value is validated before it is persisted. |
| **Nightly Run Duration** | Form field | Sets the daily active operating window (1 to 24 hours). When Night Mode is enabled, both the fixer and watcher stay continuously active and polling throughout this window. |
| **Save & Switch** | `POST /api/config` | Validates and persists the repository chain, optional PAT, start time, and duration. It refreshes the dashboard configuration card and clears cached GitHub PR state. Saving a repository change is not the same as triggering a scan; the operator must use **Trigger Scan** or wait for the next scheduled cycle. Changes to the schedule are detected dynamically by running daemons without requiring container restarts. |
| **Night Mode: ON / OFF** | `POST /api/toggle-night-mode` | Toggles the shared `nightly_run_enabled` flag. ON places the fixer and watcher into scheduled active window execution; OFF returns them to immediate 24/7 continuous execution. When switched OFF, the dashboard also attempts to dispatch an immediate fixer scan so a sleeping system can wake without waiting for the former schedule. |
| **Trigger Scan** | `POST /api/trigger-scan` | Calls GitHub Actions `security-scan.yml` with `ref: main`. It does not perform the scan inside the dashboard and does not wait for the workflow to finish. Once GitHub completes the workflow, `ScanPoller` discovers the completed run, downloads the `vulnerability-reports` artifact, and starts the remediation pipeline. |
| **Reset** | `POST /api/reset` | Requires confirmation because it is destructive to operational state. For every configured repository it closes agent remediation PRs and triage issues, deletes remote `fix/*` branches, clears tracking/checkpoint/report state, and preserves the Knowledge Base (`data/kb.json`). It does not delete learned migration patterns. |

The main content area contains four live views:

| View | Purpose and refresh behavior |
| :--- | :--- |
| **Run History** | Groups tracking records by repository and scan-trigger minute, then shows finding, old/new versions, locality, classifier bucket, status, PR, token usage, and elapsed resolution time. Filters can narrow by status, component, repository, or locality. The view refreshes approximately every 30 seconds. |
| **Retry Lineage** | Shows the parent fresh attempt and child `RETRY_REQUESTED` attempts for a selected PR, including attempt numbers and failure excerpts. This explains why a corrective commit was created and whether the retry budget is being consumed. |
| **Metrics** | Presents aggregate counts and timing/token measurements derived from tracking records. It is empty until the system has produced run data and refreshes approximately every 30 seconds. |
| **Knowledge Base** | Lists learned, playbook, and knowledge-agent entries. Entries can be filtered by source and refresh approximately every 60 seconds. A `tier1_learned` entry is only created after a remediation PR reaches `CI_PASSED`. |

#### What the operator sees after a button press

The UI returns an inline notice rather than redirecting to a separate page. A successful
configuration save reports the active repository or chain; a scan dispatch reports that
GitHub accepted the workflow request; a reset reports the repositories, PRs, branches,
and issues affected; and validation or GitHub errors are shown as an error notice. A
successful button response therefore means that the requested control-plane action was
accepted, not that the complete vulnerability remediation has already finished. Progress
must be followed in Run History, GitHub Actions, the PR, or service logs.

### Detailed Runtime Sequence: From Operator Action to Verified PR

The complete process is asynchronous. The dashboard starts an action, GitHub Actions
produces scan evidence, and the long-running agents continue independently. The normal
sequence is:

1. **Configure the target.** The operator enters one repository or a chain, credentials,
   and optional schedule, then selects **Save & Switch**. The dashboard persists shared
   settings in `data/config.json` (and updates the configured environment file when
   present). No vulnerability scan is started by this step.
2. **Start or wait for scanning.** The operator selects **Trigger Scan**, or Night Mode
   reaches its configured time. GitHub dispatches `security-scan.yml` on `main`. The
   workflow runs the configured scanners and uploads the `vulnerability-reports`
   artifact. The dashboard's scan state can show that work is active, but it does not
   own the GitHub workflow.
3. **Detect exactly one completed run.** The fixer `ScanPoller` checks workflow runs at
   `SCAN_POLL_INTERVAL` (normally 60 seconds). It ignores queued/in-progress runs,
   skips unsuccessful conclusions, downloads only a run newer than
   `data/scan_poll_checkpoint.json`, and records the processed run ID. The checkpoint
   prevents a service restart or duplicate poll from reprocessing the same artifact.
4. **Parse and normalize findings.** The report client extracts Trivy, Grype, and OWASP
   Dependency-Check JSON, deduplicates matching component/version pairs, chooses the
   highest severity, and selects the best available safe version. Invalid or unsupported
   report data is surfaced as an error rather than silently becoming a successful run.
5. **Resolve dependency locality.** The fixer clones the repository and determines
   whether each finding is direct or transitive. Maven uses `dependency:tree`; npm and
   Python use their ecosystem-specific dependency commands. Parent-first remediation is
   attempted where supported, and unsafe deep transitive findings are routed to triage.
6. **Hydrate and select migration knowledge.** Missing knowledge can be fetched from
   OSV.dev and GitHub release information. The Knowledge Store then selects the most
   specific available entry, preferring proven Tier 1 patterns, then human-authored
   Tier 2 playbooks, then unverified knowledge-agent output.
7. **Classify each finding.** The pure-Python classifier assigns bucket 1–4. Bucket 1
   (no safe version) and bucket 4 (risky major/complex or deep transitive change) open
   triage issues without invoking the LLM. Buckets 2 and 3 continue into remediation.
8. **Create isolated fix work.** Bucket 2/3 findings are processed in bounded parallel
   workers. Each worker uses a deterministic branch/record identity, updates the
   manifest through an ecosystem parser, and records `CREATED` before making further
   progress.
9. **Use the fast path first.** The updated manifest is compiled and tested. If the
   dependency bump alone succeeds, the LLM is skipped. If it fails, the LLM receives
   compiler output and knowledge context and uses only sandboxed grep/read/exact-edit/
   build tools for a bounded correction loop.
10. **Review and publish.** Tests, allowed-file checks, expected manifest-version checks,
    and deterministic diff review run before commit. A valid change is pushed to the
    remediation branch and an idempotent GitHub PR is opened. The tracking record moves
    through `PR_OPENED` and `CI_PENDING`.
11. **Watch the PR.** The watcher periodically finds open `fix/*` PRs, waits for GitHub
    Actions checks, and does not modify source code itself. A pass changes records to
    `CI_PASSED` and invokes PatternLearner. A failure is sent to RetryGate, which either
    creates a bounded retry request or marks the attempt exhausted and escalates it.
12. **Learn or escalate.** A green PR produces a Tier 1 Knowledge Base entry from the
    successful diff. A failed or unsafe attempt remains visible in the tracking store and
    receives a triage/escalation path. Human review and merge are always required; the
    system never merges the PR automatically.

---

## 6. Repository & Component Layout

Here is the exact layout of the repository and the architectural responsibility of every critical directory:

```
vuln-remediation-agent/
│
├── agents/                           # Core Agent Logic
│   ├── classifier/                   # Phase 2 Finding Classification
│   │   ├── __init__.py
│   │   └── classifier.py             # Pure Python 4-Bucket Classification Engine
│   │
│   ├── common/                       # Shared Cross-Agent Libraries
│   │   ├── __init__.py
│   │   ├── config.py                 # Dynamic multi-source configuration & repo chain management
│   │   ├── file_lock.py              # OS-level O_CREAT|O_EXCL atomic file lock
│   │   ├── github_auth.py            # GitHub App RS256 JWT & Installation token generator
│   │   ├── knowledge_store.py        # 3-Tier KB data model, scoring, and file/Firestore backends
│   │   ├── nightly_scheduler.py      # Active window evaluation, timezone scheduler & dynamic cancellation
│   │   ├── reset_ops.py              # Shared environment reset implementation
│   │   └── tracking_store.py         # State machine, audit records, and File/Firestore stores
│   │
│   ├── fixer/                        # Fixer Agent (Code Fixer, Scanners, Git Operations)
│   │   ├── Dockerfile                # Multi-stage image with Maven, OpenJDK 17, Node, Python
│   │   ├── code_fixer.py             # Orchestrator for manifest bumps, fast-paths, prompts, & LLM
│   │   ├── main.py                   # Fixer entry point: Mode A (scan), Mode B (retry), Mode C (server)
│   │   ├── multi_repo_chain.py       # Topological sort & multi-repo transitive coordinator
│   │   ├── pr_client.py              # PyGitHub client for opening PRs, triage issues, & comments
│   │   ├── repo_ops.py               # GitPython wrapper: local hardlink clone, branches, diff review
│   │   ├── scan_fetcher.py           # On-demand workflow dispatch and artifact download
│   │   ├── scan_poller.py            # 60s background poller for completed security scans
│   │   ├── scan_report_client.py     # Parser for Trivy, Grype, and OWASP Dependency-Check JSON
│   │   ├── ecosystems/               # Pluggable Dependency Ecosystem Implementations
│   │   │   ├── base.py               # PackageEcosystem Protocol & DependencyLocality dataclass
│   │   │   ├── factory.py            # Manifest detection factory (pom.xml, package.json, etc.)
│   │   │   ├── maven.py              # Maven implementation: dependency:tree, pom.xml, compile, test
│   │   │   ├── npm.py                # Node.js implementation: npm/yarn/pnpm, overrides, build, test
│   │   │   └── python.py             # Python implementation: pip/poetry/uv, lockfiles, venv isolation
│   │   └── engines/                  # Pluggable Model Execution Backends
│   │       ├── base.py               # FixEngine Protocol, FixResult, EngineExecutionError
│   │       ├── factory.py            # Engine selector (adk vs gemini_cli)
│   │       ├── adk_vertex.py         # Google ADK + Vertex AI Gemini tool-use runner
│   │       ├── gemini_cli.py         # Headless @google/gemini-cli subprocess runner
│   │       └── _subprocess_utils.py  # Async CLI runner with timeout handling
│   │
│   ├── knowledge/                    # Knowledge Hydration Agent
│   │   ├── __init__.py
│   │   ├── main.py                   # KnowledgeAgent: queries APIs and runs Gemini extraction
│   │   └── release_fetcher.py        # Fetcher for OSV.dev and GitHub Releases APIs
│   │
│   └── watcher/                      # Watcher Agent (CI Monitoring & Learning)
│       ├── Dockerfile                # Lightweight watcher container image
│       ├── ci_status.py              # GitHub Actions check run and commit status poller
│       ├── main.py                   # Watcher daemon loop and PR dispatcher
│       ├── pattern_learner.py        # Mined git diff patterns -> Tier 1 KB entries
│       └── retry_gate.py             # Bounded retry logic and Cloud Run / HTTP fixer invokers
│
├── config/                           # Secrets & Configuration (ignored in git)
│   ├── .env                          # Local environment variables
│   ├── github-app.pem                # GitHub App private key PEM (optional)
│   └── my-google-service-account.json# GCP Service Account key for Vertex AI / ADC
│
├── dashboard/                        # Observability Web UI
│   ├── Dockerfile                
│   └── backend/
│       ├── app.py                    # FastAPI server-rendered endpoints & WebSocket/HTMX handlers
│       ├── requirements.txt
│       ├── static/                   # Vendored htmx.min.js
│       └── templates/                # Jinja2 templates (index.html, partials/*.html)
│
├── data/                             # Mounted Storage Volume
│   ├── config.json                   # Dynamic configuration updated via Dashboard UI
│   ├── kb.json                       # Three-Tier Knowledge Base JSON persistence
│   ├── scan_poll_checkpoint.json     # ScanPoller high-water-mark run ID
│   └── tracking.json                 # Audit log and state machine persistence
│
├── playbooks/                        # Tier 2 Migration Playbooks (Engineer-Authored)
│   ├── commons-collections-3to4.yaml
│   ├── express-3to4.yaml
│   ├── log4j-1to2.yaml
│   └── spring-boot-2to3.yaml
│
├── scan-reports/                     # Downloaded or local scan reports (trivy, grype, owasp)
├── docker-compose.yml                # Local service orchestration
├── reset.py                          # Clean slate reset utility
└── requirements.txt                  # Root development dependencies
```

---

## 7. The Five-Stage Remediation Pipeline

When a scan is detected, the system executes five distinct stages in chronological order:

```
[Stage 1: Ingest Scan] ──► [Stage 2: Locality & Hygiene] ──► [Stage 3: KB Hydrate]
                                                                     │
[Stage 5: Fix & Gate]  ◄── [Stage 4: 4-Bucket Classify]  ◄───────────┘
```

### Stage 1: Ingestion & Scan Polling
The pipeline begins when security scanning completes on the target repository.
1. **Detection:** The `ScanPoller` thread polls `https://api.github.com/repos/{repo}/actions/workflows/security-scan.yml/runs`.
2. **Checkpointing:** When a run concludes with `conclusion == "success"`, the poller compares its `run_id` against `data/scan_poll_checkpoint.json`. If greater, it downloads the `vulnerability-reports.zip` artifact.
3. **Report Merging:** `ScanReportClient` unpacks the files into `scan-reports/` and executes `get_vulnerability_report()`.
4. **Deduplication:** Multiple scanner outputs are reconciled into a single list of `VulnerabilityFinding` objects:
   - Primary identifier: `(component_name, current_version)`.
   - Severity: Resolved to the highest reported severity (`critical` > `high` > `medium` > `low`).
   - Recommended Safe Version: PURL parsing extracts clean semver strings. Trivy's `FixedVersion` takes precedence over Grype, which takes precedence over OWASP.

### Stage 2: Dependency Locality Resolution & Hygiene
Scanners report vulnerabilities against the flat, resolved dependency tree; they do not know whether a package was directly imported in the project manifest or pulled in transitively 5 layers deep.
1. **Locality Resolution:** Before classification, `main.py` clones the target repository and calls `ecosystem.resolve_locality(repo_path, component_name)`:
   - Maven executes `mvn -B dependency:tree -Dincludes=groupId:artifactId`.
   - npm executes `npm ls`, `pnpm list`, or `yarn list --json`.
   - Python executes `pipdeptree` inside an isolated virtual environment.
2. **DFS Resolution Bug Protection:** In Maven, `_parse_tree()` scans the output to detect if `depth == 1` exists anywhere in the tree. If found, `is_transitive = False`. If only found at depth $\ge 2$, it records `is_transitive = True`, sets `transitive_depth = depth`, and identifies the direct ancestor package in `introduced_by`.
3. **Dependency Hygiene (Parent-First Upgrades):** Before forcing an artificial version override, the ecosystem checks if upgrading the direct parent dependency (`introduced_by`) resolves the transitive vulnerability naturally:
   - `try_parent_dependency_upgrade()` queries Maven Central or npm registry for newer patch/minor releases of the direct parent.
   - It tests candidate parent versions. If a parent upgrade cleanly pulls in the patched transitive version and compiles/tests cleanly, it adopts the parent upgrade instead!

### Stage 3: The Three-Tier Knowledge Base & Pre-Hydration
Migration knowledge provides ground truth to the agent, dramatically reducing LLM guessing and compilation failures.
1. **Pre-Hydration:** `KnowledgeAgent.hydrate()` runs before classification. For each finding tuple `(component, from_version, to_version)` not already in the Knowledge Store:
   - Queries `OSV.dev` for vulnerability advisories and commit references.
   - Queries `GitHub Releases API` for official release notes and changelogs between the two versions.
   - Invokes Gemini 2.5 Flash with `EXTRACTION_PROMPT` to parse breaking changes, API removals, migration steps, and mechanical find/replace patterns into a JSON `KnowledgeEntry`.
2. **The Three Tiers:**
   - **Tier 1 (`tier1_learned`):** Mined from real git diffs that passed CI in this repository. Highest priority and trust.
   - **Tier 2 (`tier2_playbook`):** Authored by human engineers in `playbooks/*.yaml` (e.g., Log4j 1.x to 2.x package rename).
   - **Tier 3 (`knowledge_agent`):** Extracted automatically from release notes by the LLM.
3. **Scoring & Lookup:** When the Fixer requests context, `knowledge_store._find_best()` scores all entries:
   $$\text{Score} = \text{Specificity Match (Exact: 1000, Major Range: 100, Stem: 10)} + \text{Tier Priority (T1: 3, T2: 2, T3: 1)}$$

### Stage 4: Risk-Based Triage & 4-Bucket Classification
`Classifier.classify()` (`agents/classifier/classifier.py`) evaluates the finding using pure Python logic—no network calls, no LLM tokens. Every finding is assigned to one of four buckets:

| Bucket | Category | Criteria | Action Taken |
| :---: | :--- | :--- | :--- |
| **1** | **No Safe Path** | `recommended_version` is `UNKNOWN` or empty, and no KB entry exists. | Opens a GitHub triage issue labeled `oss-remediation-triage`. Fixer is skipped. |
| **2** | **Patch / Minor** | Same major version bump, OR a major bump on a non-complex library. | Invokes the Fixer (with KB context if available). |
| **3** | **Major + KB** | Major version bump AND a valid KB entry exists (any tier). | Invokes the Fixer with breaking changes and migration steps injected into the prompt. |
| **4** | **Complex / Risky** | Major upgrade on a complex framework (Spring, Hibernate, Struts, React, etc.) with **no KB entry**, OR transitive depth $\ge 3$. | Opens a GitHub triage issue labeled `oss-remediation-triage`. Fixer is skipped to prevent high-blast-radius breakages. |

*Why this matters:* Buckets 1 and 4 act as an automated financial and operational circuit breaker. LLM tokens are not wasted on unsolvable findings or dangerous major framework rewrites without verified migration playbooks.

### Stage 5: Autonomous Code Fixer & Pluggable Engine Execution
For Bucket 2 and 3 findings, `_fix_one_process_worker` executes inside an isolated OS process via `ProcessPoolExecutor`:

```
Direct Finding ──► Bump Manifest ──► verify_build() ──► [SUCCESS?] ──► SKIP LLM (Fast Path!)
                                                             │
                                                             ▼ [FAIL]
                                                 Inject Compiler Error
                                                             │
                                                             ▼
                                                 Run LLM Tool Loop (ADK)
                                                             │
                                                             ▼
                                                 Local verify_tests()
                                                             │
                                                             ▼
                                                 Deterministic Diff Review
                                                             │
                                                             ▼
                                                 Commit & Push to fix/*
```

1. **Manifest Version Bump:** `ecosystem.bump_direct_dependency()` parses the manifest using XML or JSON trees and rewrites the version. If the version is defined in a Maven property (e.g., `${log4j.version}`), it locates and updates the property element.
2. **The Compile Fast-Path:** Immediately after bumping the manifest, the ecosystem executes `verify_build()`. If the project compiles with zero errors, the fixer skips the LLM entirely and records a manifest-only change!
3. **Deterministic Compatibility Fixes:** For known migrations with standardized package moves (e.g., Struts 2.3 $\to$ 2.5 filter package moves), `_apply_known_compatibility_fixes()` applies the string replacements deterministically.
4. **LLM Tool-Use Loop (ADK Engine):** If compilation fails, `AdkVertexEngine` launches Gemini 2.5 Flash with five FunctionTools:
   - `grep_files(pattern, extensions)`: Locates affected import statements and class usages.
   - `read_file(relative_path)`: Reads the file into context (bounded at 50,000 chars, path-sandboxed).
   - `apply_file_change(relative_path, find, replace)`: Applies exact verbatim substring replacement.
   - `run_maven_compile()` / `run_npm_install()` / `run_python_install()`: Runs the build and returns compiler error text so the model can self-correct across up to 10 rounds.
   - `run_maven_test()` / `run_npm_test()` / `run_python_test()`: Executes test suites.
5. **Runtime Verification Gate:** Before any commit is made, the ecosystem executes `verify_tests()`. If unit or integration tests fail, the attempt is aborted and marked `ESCALATED`.
6. **Deterministic Diff Review:** `review_dependency_diff()` executes `git status` and `git diff`. Untracked files, unauthorized edits to unrelated files, or missing version changes instantly reject the remediation.
7. **Consolidated PR Creation:** All successful fixes in the batch are committed to a unified remediation branch (`fix/vulnerability-remediation`), and `PRClient.open_combined_remediation_pr()` opens an executive summary PR on GitHub with structured markdown tables and rationale.

---

## 8. Multi-Ecosystem Engine Deep-Dive

The system supports three major programming language ecosystems via the `PackageEcosystem` protocol (`agents/fixer/ecosystems/base.py`):

```python
class PackageEcosystem(Protocol):
    def resolve_locality(self, repo_path: Path, component_name: str) -> DependencyLocality: ...
    def bump_direct_dependency(self, repo_path: Path, component_name: str, current_version: str, target_version: str) -> None: ...
    def add_transitive_override(self, repo_path: Path, component_name: str, target_version: str) -> None: ...
    def try_parent_dependency_upgrade(self, repo_path: Path, transitive_component: str, target_transitive_version: str, parent_component: str) -> Optional[Tuple[str, str, str]]: ...
    def verify_build(self, repo_path: Path) -> Tuple[bool, str]: ...
    def verify_tests(self, repo_path: Path) -> Tuple[bool, str]: ...
    def get_project_coordinates(self, repo_path: Path) -> dict: ...
    def has_dependency(self, repo_path: Path, component_name: str) -> bool: ...
```

### Maven Ecosystem (`pom.xml`)
- **Locality:** Runs `mvn -B dependency:tree -Dincludes=groupId:artifactId`.
- **XML Namespace Handling:** Uses `_pom_namespace_helpers()` to seamlessly handle both default Maven POM namespaces (`xmlns="http://maven.apache.org/POM/4.0.0"`) and bare XML tags without breaking ElementTree xpath searches.
- **Direct Version Bumping:** Handles literal versions, property substitutions (`${prop}`), and BOM-managed dependencies without explicit version tags.
- **Transitive Pinning:** Injects or updates `<dependencyManagement><dependencies><dependency>` tags, preserving Maven's standard top-level XML element order.
- **Build Verification:** `mvn compile -q --batch-mode` with environment secret scrubbing.
- **Test Verification:** `mvn -B test -q` with a 600-second timeout.

### Node.js / npm Ecosystem (`package.json`, npm, yarn, pnpm)
- **Package Manager Detection:** Checks for `packageManager` declaration in `package.json` or lockfile presence:
  - `pnpm-lock.yaml` $\to$ `pnpm`
  - `yarn.lock` $\to$ `yarn`
  - `package-lock.json` $\to$ `npm`
- **Locality:** Executes `pnpm list --json`, `yarn list --json`, or `npm ls <pkg> --json --all`.
- **Direct Version Bumping:** Preserves semver prefix markers (`^` or `~`).
- **Transitive Pinning:** Utilizes native `package.json` `"overrides"` (supported by modern npm and pnpm) or `"resolutions"` (Yarn).
- **Build Verification:** Runs `install --ignore-scripts` followed by `npm run build` (if a build script exists).
- **Test Verification:** Runs `test` (skipping dummy default npm test scripts like `exit 1`).

### Python Ecosystem (`pyproject.toml`, `requirements.txt`, Pipfile, Poetry, uv, pdm)
- **Manifest Support:** Detects and parses `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `Pipfile`, and `setup.cfg`.
- **Lockfile Transactionality:** Updates lockfiles for Poetry (`poetry.lock`), Pipenv (`Pipfile.lock`), uv (`uv.lock`), and pdm (`pdm.lock`). If a lockfile refresh or dependency install fails, `_atomic_update()` rolls back all manifest and lockfile changes.
- **Transitive Pinning:** Writes transitive overrides into `constraints.txt` using the `-c constraints.txt` standard.
- **Environment Isolation:** Provisions an isolated virtual environment (`.venv`) per repository in `tempfile.gettempdir()`, using `pipdeptree` for clean dependency-tree locality analysis.

---

## 9. The Autonomous Watcher, CI Monitoring & Closed-Loop Learning

The Watcher (`agents/watcher/main.py`) acts as the autonomous babysitter for open PRs:

### CI Status Polling & Asynchronous Verification
On every cycle (default: every 15 minutes in daemon mode), the Watcher queries GitHub for open PRs with the `fix/` branch prefix:
1. `ci_status.CIStatusWatcher` inspects the GitHub Actions Check Runs and Commit Statuses for the PR's head commit.
2. If checks are pending or in progress, the watcher waits up to `CI_TIMEOUT_SECONDS` (default: 30 minutes).
3. If CI passes, the tracking record transitions to `CI_PASSED`.

### The Retry Gate & Hard Retry Bounds
If CI fails on a remediation PR:
1. `RetryGate.process_ci_failure()` (`agents/watcher/retry_gate.py`) is triggered.
2. It counts previous attempts for the PR from the Tracking Store.
3. **Under the limit ($< \text{MAX\_RETRY\_ATTEMPTS}$):**
   - Fetches the exact failure log excerpt from the GitHub Actions step (truncated to 4,000 characters).
   - Creates a child tracking record with status `RETRY_REQUESTED`.
   - Invokes the Fixer via `POST http://fixer-server:8080/retry` (or Cloud Run Jobs in GCP).
   - The Fixer checks out the **existing PR branch** and runs `RETRY_FIX_PROMPT`, placing the CI failure log at the very top.
   - Pushes a corrective commit to the branch, triggering CI again.
4. **Limit exhausted ($\ge \text{MAX\_RETRY\_ATTEMPTS}$):**
   - Transitions record to `FAILED_MAX_RETRIES`.
   - Calculates time-to-resolution.
   - Posts a structured escalation comment on the GitHub PR explaining that automated retries are exhausted and includes the last failure log.

```
                  ┌────────────────────────┐
                  │ CI Fails on fix/ PR    │
                  └───────────┬────────────┘
                              ▼
                  ┌────────────────────────┐
                  │ Attempts >= Limit (3)? │
                  └─────┬────────────┬─────┘
                   Yes  │            │ No
                        ▼            ▼
  ┌────────────────────────┐  ┌────────────────────────┐
  │ Status:                │  │ Status:                │
  │ FAILED_MAX_RETRIES     │  │ RETRY_REQUESTED        │
  │ Post Escalation Comment│  │ POST /retry to Fixer   │
  │ Automation Stops       │  │ Push corrective commit │
  └────────────────────────┘  └────────────────────────┘
```

### PatternLearner: Mining Green PRs into Tier 1 Knowledge
When a PR reaches `CI_PASSED`, the system becomes smarter:
1. `PatternLearner.learn_from_pr()` fetches the unified git diff of the PR from GitHub (excluding the build manifest).
2. It sends the diff to Gemini 2.5 with `PATTERN_EXTRACTION_PROMPT`.
3. The LLM extracts mechanical find/replace patterns (e.g., renamed methods or package imports).
4. Persists the patterns into `data/kb.json` as a `tier1_learned` entry.
5. *The Result:* Future upgrades of the same dependency across any repository will use these confirmed patterns directly as ground truth, eliminating guessing.

---

## 10. State Machine, Persistence & Audit Trail

The Tracking Store (`agents/common/tracking_store.py`) provides complete observability into the lifecycle of every vulnerability.

### Complete Status State Machine

```
   [Scan Ingestion]
          │
          ▼
       CREATED ────────────► TRIAGE_OPENED (Bucket 1/4 or XML Error)
          │
          ▼
      PR_OPENED
          │
          ▼
      CI_PENDING ◄──────────────────────┐
          │                             │
    ┌─────┴────────────────┐            │ Corrective Commit
    ▼                      ▼            │
CI_PASSED              CI_FAILED        │
   │                       │            │
(Pattern Learned)          ▼            │
                    RETRY_REQUESTED ────┘
                           │
                           ▼ (Attempt Limit Exceeded)
                   FAILED_MAX_RETRIES
```

### Additional Terminal States:
- `ESCALATED`: Assigned when unexpected tool failures, git merge conflicts, diff review failures, or rate limits occur. Automatically opens a triage issue for manual follow-up.
- `ENGINE_ERROR`: Assigned when the LLM engine binary crashes, times out, or encounters CLI execution failures. Does not consume a retry budget.

### TrackingRecord Schema Highlights:
- `tracking_id`: UUIDv4 unique identifier.
- `vulnerability_id`: Primary CVE ID (e.g., `CVE-2024-26308`).
- `repo`, `component_name`, `old_version`, `new_version`: Coordinates of the upgrade.
- `status`: Current `TrackingStatus` value.
- `attempt_number`: 1 for fresh fixes, incremented on each retry.
- `token_usage`: Dictionary capturing `prompt_tokens`, `completion_tokens`, and `model_name`.
- `failure_log_excerpt`: Truncated compiler or CI error text.
- `is_transitive`, `introduced_by`, `transitive_depth`: Locality audit data.
- `kb_bucket`, `kb_entry_id`, `classifier_rationale`: Triage decisions.

---

## 11. Advanced Capabilities

### Multi-Repository Transitive Chain Coordination
In enterprise microservices, an upstream shared library (Repo C) publishes a JAR/package consumed by an intermediate service (Repo B), which is in turn consumed by an edge application (Repo A):

$$\text{Repo C (Upstream Core)} \longrightarrow \text{Repo B (Internal Service)} \longrightarrow \text{Repo A (Edge App)}$$

`MultiRepoChainCoordinator` (`agents/fixer/multi_repo_chain.py`) automates this complex multi-repo workflow:
1. **Graph Discovery:** Clones each configured repository, inspects project coordinates (`groupId`, `artifactId`, `version`), and maps dependencies between them.
2. **Topological Sort:** Computes the bottom-up remediation order (Root Provider $\to$ Intermediate $\to$ Consumer).
3. **Sequential Remediation:**
   - Upgrades the vulnerable component in Repo C and opens a PR.
   - Upgrades Repo B's manifest to point to Repo C's new release and pins the transitive override.
   - Upgrades Repo A's manifest similarly.
4. **Linked PRs:** Opens cross-referenced Pull Requests on GitHub with links to upstream fix PRs.
5. **Offline Zip Support:** If repositories are uploaded as `.zip` archives via the Dashboard, the coordinator unzips, remediates, verifies, and packages the results into downloadable remediated archives in `data/downloads/`.

### Night Mode Scheduled Execution
Running LLMs and build pipelines during peak hours can exhaust API rate limits or consume expensive CI runner minutes.

Night Mode is a shared runtime mode used by both long-running daemon services:
`fixer-server` controls scan discovery, auto-dispatch, and vulnerability remediation,
while `watcher` controls PR observation and CI status verification. When Night Mode
is enabled, both services operate within a scheduled **daily active window**
`[start_time, start_time + duration)`.

#### Configuration and persistence

- **`is_nightly_run_enabled()`:** Reads the toggle from `data/config.json`, then the
  configured environment file, then the process environment. The dashboard writes the
  selected value back to shared configuration so all daemon containers observe the same state.
- **`get_nightly_run_time()`:** Reads the daily `HH:MM` start time, defaulting to `00:00`.
- **`get_nightly_scan_max_wait_seconds()`:** Converts the dashboard duration from hours
  to an active window of 3,600–86,400 seconds (1 to 24 hours). This defines the duration
  the daemons stay actively running and polling each day.
- **`NIGHTLY_RUN_TIMEZONE`:** Interprets the configured start time as an IANA timezone, default
  `Asia/Kolkata`.

#### Active Window Model and Dynamic Wake-Up Behavior

The active window is defined as `[start_time, start_time + duration)` evaluated in
`NIGHTLY_RUN_TIMEZONE`. The scheduler (`get_active_window_status()`) handles both single-day
windows (e.g., 15:39 for 2 hours ends at 17:39) and overnight windows spanning midnight
(e.g., 23:00 for 4 hours ends at 03:00).

```text
Night Mode ON
    |
    v
Evaluate current time against [start_time, start_time + duration)
    |
    +-- Inside Window --> [ACTIVE EXECUTION]
    |       |
    |       +-- fixer-server: polls every poll_interval (60s), auto-dispatches scan, remediates
    |       +-- watcher: checks PR CI status every cycle_interval (60s), retries / resolves
    |       +-- repeats until window duration expires
    |
    +-- Outside Window --> [SLEEPING UNTIL NEXT WINDOW]
            |
            | every ~5s: check if Night Mode is toggled OFF
            | every ~5s: check if schedule/duration changed in config
            | every ~5s: check if current time entered active window
            |
            +-- disabled --> wake up immediately into continuous mode
            +-- schedule changed --> re-evaluate window immediately
            +-- start time reached --> enter ACTIVE EXECUTION
```

Key operational behaviors:
1. **Startup inside the active window:** If containers start or restart when the current
   time is already inside the active window (e.g., started at 16:01 with a window of 15:39–17:39),
   they immediately enter active execution for the remaining window duration without waiting
   for tomorrow.
2. **Dynamic reconfiguration:** `sleep_until_active_window()` evaluates config state every
   5 seconds. Changing the start time or duration in the dashboard wakes the sleep loop
   immediately without requiring container restarts.
3. **Outside-window sleep state:** When outside the window, daemons sleep until the next
   window start. They remain healthy and alive; sleep is an intentional scheduling wait.

#### Fixer Server Behavior in the Active Window

When inside the active window:
1. **Auto-Scan Dispatch:** At the start of each daily window, the fixer automatically marks
   a scan request and resets the dispatch latch (`set_scan_requested(True)` and
   `poller.reset_window_dispatch()`).
2. **Continuous Polling:** The fixer continuously executes `poller.poll_once()` every
   `poll_interval` (default 60 seconds).
3. **Artifact Processing:** Once GitHub Actions finishes `security-scan.yml`, the fixer
   downloads `vulnerability-reports`, runs classification, LLM reasoning, code modifications,
   and pushes remediation PRs.
4. **Retry Listener:** The fixer's HTTP server (`:8080`) remains active throughout to receive
   POST `/retry` requests from the watcher and process corrective attempts.
5. **Window Expiration:** Once the configured duration elapsed, the fixer transitions to
   sleep until the next scheduled window.

#### Watcher Behavior in the Active Window

When inside the active window:
1. **Continuous PR Tracking:** The watcher runs observation cycles every `WATCHER_SLEEP_SECONDS`
   (default 60s) rather than a single cycle.
2. **CI Evaluation:** It inspects all open `fix/*` PRs in configured target repositories.
   - On CI pass: Marks tracking record `CI_PASSED` and updates the Knowledge Base.
   - On CI fail: Dispatches `POST /retry` to `http://fixer-server:8080/retry`.
3. **Window Expiration:** Once the active window ends, the watcher sleeps until the next
   window.

#### Disabling Night Mode (Switching to 24/7 Continuous Mode)

When the operator toggles Night Mode OFF in the dashboard:
1. The dashboard persists `nightly_run_enabled=false`.
2. The 5-second check immediately detects the toggle and breaks out of the sleep loop.
3. Both `fixer-server` and `watcher` switch to continuous immediate polling (24/7), running
   cycles every 60 seconds around the clock.
4. Switching back to Night Mode ON immediately calculates whether the current time is inside
   or outside the configured window and behaves accordingly.

### Clean-Slate Environment Reset with Knowledge Preservation
During testing and local verification, engineers need to reset test repositories back to a clean state.
`reset.py` and `agents/common/reset_ops.py`:
1. Closes all open remediation PRs on GitHub opened by the agent.
2. Deletes remote `fix/*` branches on GitHub origin.
3. Closes all open automated triage issues labeled `oss-remediation-triage`.
4. Resets `data/tracking.json` to `{}`.
5. Resets `data/scan_poll_checkpoint.json`.
6. Purges cached scanner files in `scan-reports/`.
7. **CRITICAL:** Strictly **preserves `data/kb.json`**. Learned patterns and playbooks are never deleted during resets, ensuring cumulative system intelligence across test runs.

---

## 12. Defensive Engineering, Sandboxing & Security Controls

Because this platform autonomously downloads code, edits files, executes shell compilers, and prompts LLMs, security is paramount.

### 1. Path Traversal Sandboxing
The LLM generates file paths when calling tools. To prevent malicious or hallucinated relative paths from accessing host files:
```python
target = (self._repo_path / relative_path).resolve()
if not target.is_relative_to(self._repo_path.resolve()):
    return "ERROR: Path traversal detected."
```

### 2. Secret Scrubbing in Subprocesses
When executing `mvn compile`, `mvn test`, or `npm install`, the environment is sanitized:
```python
safe_env = {
    k: v for k, v in os.environ.items()
    if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS", "GEMINI_API_KEY")
}
subprocess.run(..., env=safe_env)
```
This prevents malicious dependency build plugins (e.g., `exec-maven-plugin`) from exfiltrating credentials to external servers or logging them to stderr.

### 3. Verbatim Substring Editing Constraint
The `apply_file_change` tool enforces that the `find` parameter must match an exact, verbatim substring currently existing in the file on disk. The LLM cannot guess or generate speculative diff hunks. If the substring is not found, the call fails immediately, requiring the model to re-read the file.

### 4. Deterministic Automated Diff Review
Before pushing any commit, `review_dependency_diff()` asserts:
- Working tree contains no untracked files.
- No files were renamed.
- All modified files match the expected files list reported by the tools.
- The build manifest was updated and contains the requested target version.

---

## 13. Developer & Operator Handbook

### Prerequisites & Local Bootstrapping
1. **Container Engine:** Podman $\ge 4.0$ with `podman-compose`, or Docker Desktop / Docker Compose v2.
2. **Google Cloud Platform:** A GCP project with the **Vertex AI API** enabled.
3. **Credentials:**
   - GCP Service Account JSON key saved at `config/my-google-service-account.json`. Needs the `roles/aiplatform.user` IAM role.
   - GitHub Personal Access Token (PAT) with `repo`, `pull_request`, and `actions:read` scopes.

### Configuration Reference (`.env` and `config.json`)
Copy `.env.example` to `config/.env`:

```ini
# Target Repository
GITHUB_REPO_TARGET=your-org/vulnerable-java-app
GITHUB_PAT=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# GCP Vertex AI Configuration
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
VERTEX_LOCATION=us-central1
VERTEX_MODEL=gemini-2.5-flash
GOOGLE_APPLICATION_CREDENTIALS=/gcp/adc.json

# Engine & Concurrency
FIX_ENGINE=adk
MAX_PARALLEL_FIXES=2
MAX_RETRY_ATTEMPTS=3

# Scheduler & Daemons
FIXER_SERVER_MODE=1
SCAN_POLL_INTERVAL=60
WATCHER_DAEMON=1
WATCHER_SLEEP_SECONDS=60
KB_HYDRATION=1

# Night Mode
NIGHTLY_RUN_ENABLED=0
NIGHTLY_RUN_TIME=00:00
NIGHTLY_RUN_TIMEZONE=Asia/Kolkata
```

### Authoring a Tier 2 Playbook
Playbooks reside in `playbooks/` as YAML files (e.g., `playbooks/log4j-1to2.yaml`).
Schema:
```yaml
component: "org.apache.log4j:log4j"
from_major: 1
to_major: 2
confidence: high
breaking_changes:
  - "The org.apache.log4j.* package is replaced by org.apache.logging.log4j.*"
  - "Logger.getLogger() is replaced by LogManager.getLogger()"
api_removals:
  - "org.apache.log4j.Category"
migration_steps:
  - "Replace import org.apache.log4j.Logger with org.apache.logging.log4j.Logger and LogManager"
  - "Update logger instantiation calls"
patterns:
  - find: "import org.apache.log4j.Logger;"
    replace: "import org.apache.logging.log4j.LogManager;\nimport org.apache.logging.log4j.Logger;"
    description: "Replace Log4j 1.x import with Log4j 2.x imports"
  - find: "Logger.getLogger("
    replace: "LogManager.getLogger("
    description: "Update static logger factory"
```

### Adding a New Package Ecosystem
To add support for a new ecosystem (e.g., Go modules / `go.mod` or Rust Cargo / `Cargo.toml`):
1. Create `agents/fixer/ecosystems/golang.py`.
2. Implement the `PackageEcosystem` protocol (`resolve_locality`, `bump_direct_dependency`, `add_transitive_override`, `verify_build`, `verify_tests`).
3. Update `agents/fixer/ecosystems/factory.py` to detect `go.mod` and instantiate `GolangEcosystem()`.
4. Add the appropriate compiler/toolchain to `agents/fixer/Dockerfile`.

### Running Tests & Validating Changes
```bash
# Run unit tests across all agents
pytest agents/fixer/tests/ -v

# Run lint checks
ruff check agents/
```

---

## 14. The 25 Essential Engineering Questions (FAQ)

Here are the critical, non-obvious questions every engineer asks when onboarding onto this codebase:

#### Q1: Why does the system open a Combined PR instead of one PR per CVE?
*Answer:* In enterprise repositories, bumping 10 dependencies via 10 separate PRs creates merge conflicts across `pom.xml`, exhausts CI runners, and creates review fatigue. Consolidated batch PRs remediate the entire scan in a single coherent changeset while tracking each CVE independently in `data/tracking.json`.

#### Q2: What happens if two worker processes try to push to the same branch simultaneously?
*Answer:* `_fix_one_process_worker` in `agents/fixer/main.py` uses an OS-level file lock (`fixer_push_<branch>.lock`). It performs a `git pull --rebase origin <branch>` before pushing. If a rebase conflict occurs, it aborts the rebase, fetches origin, resets hard, and re-applies the fix cleanly under the lock.

#### Q3: Why is `is_transitive` resolved via `mvn dependency:tree` instead of scanner reports?
*Answer:* Security scanners report vulnerabilities against the flat classpath of resolved artifacts. A CVE in `snakeyaml` appears identical in scan output whether imported directly or pulled in 3 layers deep by Jackson. Locality resolution is required to choose the right fix strategy (direct edit vs. `<dependencyManagement>`).

#### Q4: Why doesn't the agent automatically fix transitive dependencies deeper than depth 2?
*Answer:* Overriding a transitive dependency at depth 3+ has an unpredictable blast radius. The direct parent library might rely on an internal API of the older transitive version that was removed in the safe version, causing runtime `NoSuchMethodError` exceptions. Deep chains are routed to human triage.

#### Q5: How does the agent prevent hallucinated edits in source code?
*Answer:* Through the `apply_file_change` tool interface. The model is required to provide an exact `find` string that exists verbatim in the file content previously read via `read_file`. If the string doesn't match character-for-character, the tool call errors out.

#### Q6: Why did the agent move away from Cosmos DB to dual Local JSON + Firestore?
*Answer:* Cosmos DB locked developers into an active Azure subscription even for local unit testing. The dual storage architecture allows zero-dependency local simulation with atomic file locking while supporting Google Cloud Firestore natively in production GCP environments.

#### Q7: Why does `code_fixer.py` prepend `pom.xml` to `files_changed` instead of letting the LLM report it?
*Answer:* Determinism. The version bump in the manifest is applied by Python XML parsers before the LLM engine ever runs. Letting the LLM report changed files risks omission. `files_changed` is assembled deterministically from the manifest bump plus `git diff` outputs.

#### Q8: What prevents an infinite loop if CI keeps failing?
*Answer:* The `RetryGate` strictly enforces `MAX_RETRY_ATTEMPTS` (default: 3). Every CI failure increments `attempt_number` in the Tracking Store. When the limit is reached, the status becomes `FAILED_MAX_RETRIES`, an escalation comment is posted on the PR, and the Fixer is never invoked again for that PR.

#### Q9: How does the system handle rate limits on Vertex AI (HTTP 429)?
*Answer:* `AdkVertexEngine._run_agent_async()` catches `ResourceExhausted` and 429 exceptions, executing an exponential backoff retry loop ($20\text{s}, 40\text{s}, 60\text{s}$) across up to 4 attempts before failing gracefully.

#### Q10: Why does the fast path compile immediately after the version bump?
*Answer:* Many minor and patch updates (e.g., `jackson-databind 2.13.0` $\to$ `2.13.4`) are backwards-compatible. If `mvn compile` passes immediately after bumping the manifest, there is zero need to spend LLM tokens or wait 30 seconds for an agent tool loop.

#### Q11: What is the purpose of `scan_poll_checkpoint.json`?
*Answer:* It maintains the high-water-mark GitHub Actions `run_id`. Without it, restarting the `fixer-server` container would re-download and re-process every historical scan run in the repository.

#### Q12: Why are unit tests run locally (`verify_tests`) before opening a PR if CI will run them anyway?
*Answer:* Pushing broken code to GitHub pollutes git commit histories and wastes remote CI runner minutes. Local test execution gates the commit—if tests fail, the record escalates immediately without opening a public broken PR.

#### Q13: How does `PatternLearner` avoid learning invalid or breaking code patterns?
*Answer:* It only triggers when a PR achieves `CI_PASSED`. It explicitly prompts Gemini to extract only deterministic, safe, mechanical find/replace patterns, ignoring incidental formatting and manifest changes.

#### Q14: How does the dashboard update in real-time without WebSockets or React?
*Answer:* Via HTMX polling fragments. HTML partials contain `hx-trigger="every 30s"`. The browser periodically requests HTML snippets from the FastAPI backend and swaps them into the DOM.

#### Q15: Why are secrets stripped from the environment before running `mvn` or `npm`?
*Answer:* To prevent prompt injection and supply-chain attacks. If a bumped package executes a malicious build script or plugin during compilation, it cannot access `GITHUB_PAT` or GCP credentials.

#### Q16: What happens if a repository uses properties for versions in Maven?
*Answer:* `MavenEcosystem.bump_direct_dependency()` checks if the version string is in `${property.name}` format. If so, it locates `<properties><property.name>` in the XML tree and updates the property value directly.

#### Q17: Why does `reset.py` preserve `kb.json`?
*Answer:* `kb.json` contains cumulative intelligence: Tier 1 learned patterns and Tier 2 playbooks. Resetting test PRs and tracking records shouldn't erase the agent's learned memory.

#### Q18: What is the difference between `ESCALATED` and `ENGINE_ERROR`?
*Answer:* `ESCALATED` indicates a remediation failure (e.g., tests failed, diff review rejected unapproved changes, merge conflict). `ENGINE_ERROR` indicates tooling or infrastructure failure (e.g., Vertex AI API outage, missing CLI binary, timeout). `ENGINE_ERROR` does not consume a retry attempt.

#### Q19: How are multi-repo chains ordered?
*Answer:* `MultiRepoChainCoordinator.resolve_remediation_order()` builds a directed acyclic graph (DAG) of project dependencies and executes a topological sort. Upstream providers are remediated first, downstream consumers last.

#### Q20: Can this agent run completely offline?
*Answer:* Yes. By placing scanner reports directly in `scan-reports/`, setting `KB_HYDRATION=0`, and using local repository paths, the agent runs entirely against local directories.

#### Q21: Why are XML comments preserved during pom.xml editing?
*Answer:* Standard XML serializers can strip developer comments and formatting. The ecosystem registers default POM namespaces and performs surgical node updates to preserve readability.

#### Q22: What happens if a scan report contains a CVE with no recommended version?
*Answer:* The finding is classified as Bucket 1. The agent skips the fixer and opens a GitHub triage issue explaining that no safe version exists in vulnerability databases.

#### Q23: Why does `FileLock` use `os.O_CREAT | os.O_EXCL`?
*Answer:* This combination provides an atomic file creation guarantee at the operating system kernel level on both POSIX and Windows systems, preventing race conditions between concurrent processes.

#### Q24: How does the agent handle Python projects with lockfiles?
*Answer:* `PythonEcosystem` takes a snapshot of all lockfiles (`poetry.lock`, `Pipfile.lock`, `uv.lock`, etc.). If refreshing the lockfile or installing dependencies fails, it executes an atomic rollback restoring the original files.

#### Q25: Why is GitPython preferred over subprocess calls for git operations?
*Answer:* GitPython avoids exposing access tokens in shell command strings, provides structured error objects, and enables high-performance local hardlink cloning.

---

## 15. Future Vision & Architectural Roadmap

As you begin contributing to `vuln-remediation-agent`, keep these upcoming architectural initiatives in mind:

1. **OpenRewrite & AST Refactoring Engine:**
   - Integrate [OpenRewrite](https://docs.openrewrite.org/) recipes for well-known Java framework migrations (e.g., Spring Boot 2 $\to$ 3, Java 11 $\to$ 17). OpenRewrite recipes are 100% deterministic and can replace the LLM loop for major framework upgrades.
2. **Automated PR Auto-Merge with Merge Trains:**
   - For low-risk patch updates that pass all tests and CI checks, integrate GitHub Auto-Merge to merge verified PRs autonomously when green.
3. **Static Analysis & Runtime Call-Graph Pruning:**
   - Integrate call-graph analysis to detect whether a vulnerable method in a third-party dependency is actually invoked by the target application's code, suppressing false-positive CVE alerts.
4. **Multi-Agent Collaborative Fixers:**
   - Decompose complex fixes into specialized subagents: one analyzing compiler error logs, one generating migration patches, and one performing semantic code reviews before commit.

---

*Welcome aboard! You now possess complete visibility into the architecture, design rationale, and engineering implementation of `vuln-remediation-agent`. Dive into the code, inspect the tests, and happy pair programming!*
