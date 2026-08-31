# Vulnerability Remediation Agent: Architectural & Security Audit

This document summarizes the functional and security flaws discovered in the `vuln-remediation-agent` during the audit, along with the implemented fixes.

## 1. Maven DFS Precedence Bug
- **Location:** `agents/fixer/ecosystems/maven.py` (`_parse_tree` function)
- **Problem:** When determining if a dependency is direct or transitive, the agent relied on `mvn dependency:tree`, which outputs in Depth-First Search (DFS) order. If a direct dependency appeared transitively earlier in the tree, the agent falsely flagged it as transitive and attempted to override its version in `<dependencyManagement>` instead of updating the direct `<dependencies>` block.
- **Solution:** Modified `_parse_tree` to scan the *entire* dependency tree first to hunt for a direct (`depth=1`) match, falling back to treating it as transitive only if no direct occurrence is found.

## 2. Race Conditions in Local Persistence
- **Location:** `agents/common/tracking_store.py` and `agents/common/knowledge_store.py`
- **Problem:** `fixer-server` employs a `ThreadPoolExecutor` with multiple concurrent workers. Both `FileTrackingStore` and `FileKnowledgeStore` read, modified, and saved a shared JSON file in-place without synchronization. This caused severe race conditions resulting in permanently lost state updates, as well as `JSONDecodeError`s when one process attempted to read while another was writing.
- **Solution:** 
  - Implemented an inter-process locking utility (`FileLock` in `agents/common/file_lock.py`) using `os.open` with `O_CREAT | O_EXCL`.
  - Replaced direct, in-place file writes with atomic file replacements (writing to a `.tmp` file and renaming via `os.replace`).
  - Wrapped all reads and writes in both stores with the `FileLock`.

## 3. Path Traversal & Arbitrary File Modification
- **Location:** `agents/fixer/engines/adk_vertex.py` (`_tool_read_file` and `_tool_apply_file_change`)
- **Problem:** The tool handlers combined a base directory with an LLM-provided `relative_path` without validation (`target = self._repo_path / relative_path`). In Python's `pathlib`, if `relative_path` is an absolute path or contains directory traversals (`../`), it can resolve to arbitrary locations on the host container. This exposed the agent to prompt injection attacks, where a malicious CI log could instruct the LLM to read mounted credentials (e.g., `/gcp/adc.json`) and write them into the repository to be exfiltrated via a PR.
- **Solution:** Enforced strict path sandboxing by cryptographically resolving paths and asserting they remain within the repository boundaries using `(self._repo_path / relative_path).resolve().is_relative_to(self._repo_path.resolve())`.

## 4. Secret Leakage via Build Sandboxing Failure
- **Location:** `agents/fixer/ecosystems/maven.py` (`compile_repo` and `test_repo`)
- **Problem:** The agent executed `mvn compile` and `mvn test` locally inside its own container using `subprocess.run()`, inherently exposing all its own environment variables (e.g., `GITHUB_PAT`, GCP credentials) to the Maven build process. An attacker leveraging prompt injection could instruct the LLM to modify `pom.xml` to include the `exec-maven-plugin`. During compilation, this plugin could dump the sensitive environment variables into the build log, handing the secrets back to the LLM for exfiltration.
- **Solution:** Scrubbed the execution environment for both subprocesses by explicitly removing sensitive environment variables (e.g., `GITHUB_PAT` and `GOOGLE_APPLICATION_CREDENTIALS`) from the `env` payload before triggering the Maven builds.
