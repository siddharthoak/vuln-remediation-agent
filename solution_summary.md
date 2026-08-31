# Vulnerability Remediation Agent: Architectural & Security Audit

This document summarizes the functional and security flaws discovered and fixed in the `vuln-remediation-agent`, in chronological order of their remediation.

## 1. Maven Transitive-Dependency Remediation
- **Problem:** The scanner reported vulnerabilities from the complete resolved Maven dependency graph, but the fixer originally searched only for dependencies declared directly in `pom.xml`. Vulnerable transitive dependencies failed to match and were not remediated.
- **Solution:** Added Maven dependency-tree locality resolution (`mvn dependency:tree`). One-hop (depth-2) transitive findings are now pinned via a project-level `<dependencyManagement>` override, allowing them to be fixed without incorrectly editing the wrong direct dependency.

## 2. Risk-Based Transitive Triage
- **Problem:** Forcing a transitive version deep in the tree has a high blast radius. Automatically changing deeper chains could create unsafe, breaking remediations.
- **Solution:** Automated remediation was restricted to one-hop (depth-2) dependencies. Chains of depth 3 or greater, or dependencies introduced by complex frameworks, are automatically routed to manual human triage to prevent aggressive, unsafe modifications.

## 3. Maven XML and Dependency-Processing Errors
- **Problem:** Missing `pom.xml` files, malformed XML, and targeted dependency lookup failures produced unclear failures or left remediation work silently incomplete.
- **Solution:** Added explicit `PomXMLError` handling. Dependency-processing failures now preserve actionable error messages, route the finding to triage, and update the tracking record accordingly.

## 4. Tracking and Unexpected-Failure Visibility
- **Problem:** Generic exceptions logged an error and returned `None`. The corresponding tracking record remained stuck at `CREATED`, leaving orphaned remediation attempts without human follow-up.
- **Solution:** Unexpected failures now update the tracking record to `ESCALATED`, log a traceback, and automatically attempt to open a triage issue for human review.

## 5. CI Retry Correctness
- **Problem:** Retries ran on a branch where the original manifest change might already exist. Reapplying the version bump could misclassify the finding or bypass repair of the actual CI failure.
- **Solution:** Added explicit `is_retry` handling. Retries now skip reapplying the original manifest edit, pass the CI failure log directly to the repair engine, and focus exclusively on resolving the CI failure.

## 6. LLM Cost Reduction for Buckets 2 and 3
- **Problem:** Every direct dependency upgrade invoked the LLM, even when simply changing the `pom.xml` was sufficient. This wasted tokens and added latency.
- **Solution:** After a successful direct `pom.xml` bump, the fixer immediately runs `mvn compile`. If compilation succeeds, it bypasses the LLM entirely (fast path). The LLM is only invoked if compilation fails.

## 7. Runtime Verification with Maven Tests
- **Problem:** Compilation alone cannot detect behavioral regressions or failing tests after a dependency upgrade.
- **Solution:** Added bounded Maven test execution (`mvn -B test -q`). The fixer now runs a mandatory Maven test gate before committing and pushing. Failures are persisted as `ESCALATED` and routed to triage without publishing the branch.

## 8. Deterministic Automated Diff Review
- **Problem:** LLM-generated changes could include unrelated files, unexpected edits, or incorrect dependency versions.
- **Solution:** Added a strict, read-only repository diff reviewer that uses `git status` and `git diff`. Untracked files, missing requested versions, or edits to unexpected source files instantly fail the review, preventing the PR from being published.

## 9. Documentation and Configuration Consistency
- **Problem:** Documentation described old, obsolete behaviors (e.g., silent-drop) and did not explain new safeguards like CI retries and deterministic diff reviews.
- **Solution:** Extensively updated `README.md` to reflect the new depth-2 triage boundaries, compile fast paths, diff-review safeguards, and other architectural behaviors.

## 10. Maven DFS Precedence Bug
- **Problem:** When determining if a dependency is direct or transitive, the agent relied on `mvn dependency:tree` which outputs in Depth-First Search (DFS) order. If a direct dependency appeared transitively earlier in the tree, the agent falsely flagged it as transitive and attempted to override its version in `<dependencyManagement>`.
- **Solution:** Modified `_parse_tree` in `maven.py` to scan the *entire* dependency tree first to hunt for a direct (`depth=1`) match, falling back to treating it as transitive only if no direct occurrence is found.

## 11. Race Conditions in Local Persistence
- **Problem:** `fixer-server` employs a `ThreadPoolExecutor` with multiple concurrent workers. `FileTrackingStore` and `FileKnowledgeStore` read, modified, and saved a shared JSON file in-place without synchronization, causing permanently lost state updates and `JSONDecodeError`s on concurrent reads.
- **Solution:** Implemented an inter-process locking utility (`FileLock`) using `os.open` with `O_CREAT | O_EXCL`. Replaced direct file writes with atomic file replacements (`os.replace` via `.tmp` files) and wrapped all I/O with the lock.

## 12. Path Traversal & Arbitrary File Modification
- **Problem:** The tool handlers in `adk_vertex.py` combined a base directory with an LLM-provided `relative_path` without validation (`target = self._repo_path / relative_path`). Because absolute paths and `../` sequences natively override the base path in `pathlib`, the LLM could read/write arbitrary files on the host container (e.g., `/gcp/adc.json`), enabling data exfiltration via prompt injection.
- **Solution:** Enforced strict path sandboxing by cryptographically resolving paths and asserting they remain strictly within the repository boundaries using `is_relative_to()`.

## 13. Secret Leakage via Build Sandboxing Failure
- **Problem:** The agent executed `mvn compile` and `mvn test` locally inside its own container using `subprocess.run()`, inherently exposing all its own environment variables (e.g., `GITHUB_PAT`) to the Maven build process. An attacker leveraging prompt injection could instruct the LLM to modify `pom.xml` to include `exec-maven-plugin`, which would dump these secrets during the build phase and hand them back to the LLM.
- **Solution:** Scrubbed the execution environment for both subprocesses in `maven.py` by explicitly removing sensitive environment variables from the `env` dictionary before triggering the Maven builds.
