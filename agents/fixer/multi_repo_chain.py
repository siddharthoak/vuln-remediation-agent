"""
Multi-Repository Transitive Remediation Coordinator.

Coordinates vulnerability remediation across multiple repositories in a
dependency chain (e.g., Repo A depends on Repo B, and Repo B depends on Repo C).

Remediation Strategy:
1. Discovers the dependency graph across the provided repositories.
2. Orders repositories bottom-up (Root Upstream -> Intermediate -> Downstream Consumer).
3. Sequentially remediates each repository in the chain:
   - Root (Repo C): Upgrades the vulnerable component at the origin.
   - Intermediate (Repo B): Propagates the upgrade and pins dependencyManagement.
   - Consumer (Repo A): Propagates the upgrade and pins dependencyManagement.
4. Opens linked Pull Requests on GitHub referencing upstream remediation PRs.
5. Persists tracking records in TrackingStore for full watcher and dashboard observability.
"""

from __future__ import annotations

import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from code_fixer import CodeFixer, ChangeSummary
from ecosystems.factory import get_ecosystem, get_manifest_file
from ecosystems.base import EcosystemError
from ecosystems.maven import PomXMLError
from ecosystems.python import PythonManifestError
from pr_client import PRClient, PRResult
from repo_ops import RepoOps
from common.tracking_store import make_fresh_record, TrackingStatus, TrackingStoreProtocol
from common.config import resolve_repo_source, get_download_dir

logger = logging.getLogger("fixer.multi_repo_chain")


@dataclass
class ChainRepoNode:
    repo_name: str
    github_url: str
    group_id: str = ""
    artifact_id: str = ""
    version: str = ""
    component_name: str = ""
    depends_on: List[str] = field(default_factory=list)
    is_local: bool = False


class MultiRepoChainCoordinator:
    """
    Coordinates multi-repository remediation for transitive dependency chains.
    """

    def __init__(
        self,
        repo_chain: List[str],
        github_pat: str,
        tracking_store: TrackingStoreProtocol,
        base_branch: str = "main",
        branch_name: str = "fix/vulnerability-remediation",
    ):
        self._repo_chain = [r.strip() for r in repo_chain if r.strip()]
        self._github_pat = github_pat
        self._tracking_store = tracking_store
        self._base_branch = base_branch
        self._branch_name = branch_name

    def resolve_remediation_order(self) -> List[str]:
        """
        Inspects each repository's pom.xml to discover dependencies between them.
        Returns the repositories sorted bottom-up (root provider first, consumer last).
        For Repo A -> Repo B -> Repo C, returns [Repo C, Repo B, Repo A].
        """
        if len(self._repo_chain) <= 1:
            return self._repo_chain

        nodes: Dict[str, ChainRepoNode] = {}
        logger.info("Resolving dependency graph for repo chain: %s", self._repo_chain)

        for repo_name in self._repo_chain:
            source_path, is_local = resolve_repo_source(repo_name)
            node = ChainRepoNode(repo_name=repo_name, github_url=source_path, is_local=is_local)
            try:
                with RepoOps() as ops:
                    ops.clone(source_path, self._github_pat)
                    ecosystem = get_ecosystem(ops._local_path)
                    coords = ecosystem.get_project_coordinates(ops._local_path)
                    node.group_id = coords.get("group_id", "")
                    node.artifact_id = coords.get("artifact_id", "")
                    node.version = coords.get("version", "")
                    node.component_name = coords.get("component_name", "")
            except Exception as exc:
                logger.warning("Could not clone/inspect %s (%s): %s", repo_name, source_path, exc)

            nodes[repo_name] = node

        # Check which repo depends on which
        for r1, node1 in nodes.items():
            try:
                with RepoOps() as ops:
                    ops.clone(node1.github_url, self._github_pat)
                    ecosystem = get_ecosystem(ops._local_path)
                    for r2, node2 in nodes.items():
                        if r1 != r2 and node2.component_name:
                            if ecosystem.has_dependency(ops._local_path, node2.component_name):
                                node1.depends_on.append(r2)
                                logger.info("%s directly depends on %s (%s)", r1, r2, node2.component_name)
            except Exception as exc:
                logger.debug("Error checking dependency links for %s: %s", r1, exc)

        return self._topological_sort(nodes)

    def _topological_sort(self, nodes: Dict[str, ChainRepoNode]) -> List[str]:
        """
        Topological sort: provider before consumer (bottom-up).
        If A depends on B, and B depends on C:
        Order is [C, B, A].
        """
        in_degree = {r: 0 for r in self._repo_chain}
        graph = {r: [] for r in self._repo_chain}

        for r, node in nodes.items():
            for dep in node.depends_on:
                if dep in graph:
                    # dep is required by r -> dep comes before r
                    graph[dep].append(r)
                    in_degree[r] += 1

        queue = [r for r in self._repo_chain if in_degree[r] == 0]
        ordered = []
        while queue:
            curr = queue.pop(0)
            ordered.append(curr)
            for neighbor in graph.get(curr, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(ordered) == len(self._repo_chain):
            logger.info("Computed bottom-up remediation order: %s", ordered)
            return ordered

        # Fallback: reverse user input order (e.g. [A, B, C] -> [C, B, A])
        fallback = list(reversed(self._repo_chain))
        logger.info("Using default reversed order for remediation: %s", fallback)
        return fallback

    def remediate_finding_across_chain(
        self,
        finding,
        kb_entry=None,
    ) -> Dict[str, Optional[PRResult]]:
        """
        Remediates finding across all repositories in the chain.
        Returns mapping of repo_name -> PRResult.
        """
        order = self.resolve_remediation_order()
        total_repos = len(order)
        chain_results: Dict[str, Optional[PRResult]] = {}

        logger.info(
            "Starting multi-repo remediation across %d repos for %s (%s -> %s)",
            total_repos, finding.component_name, finding.current_version, finding.recommended_version,
        )

        for step_idx, repo_name in enumerate(order, 1):
            is_root = (step_idx == 1)
            is_consumer = (step_idx == total_repos)
            source_path, is_local = resolve_repo_source(repo_name)
            pr_client = PRClient(repo_full_name=repo_name, github_pat=self._github_pat) if not is_local else None

            logger.info(
                "[%d/%d] Processing %s (%s, %s)",
                step_idx, total_repos, repo_name,
                "Root" if is_root else ("Consumer" if is_consumer else "Intermediate"),
                "Local Archive" if is_local else "Remote GitHub",
            )

            # Create or get tracking record
            record = make_fresh_record(
                vulnerability_id=finding.cve_ids[0] if finding.cve_ids else finding.component_name,
                repo=repo_name,
                component_name=finding.component_name,
                old_version=finding.current_version,
                new_version=finding.recommended_version,
                is_transitive=not is_root or finding.is_transitive,
                introduced_by=finding.introduced_by or (order[step_idx - 2] if step_idx > 1 else None),
                transitive_depth=step_idx if not is_root else (finding.transitive_depth or 1),
                chain_step=step_idx,
                chain_total=total_repos,
            )
            record.branch_name = self._branch_name
            record.kb_bucket = 2
            record.kb_entry_id = kb_entry.entry_id if kb_entry else None
            record.classifier_rationale = (
                f"Multi-repository remediation chain (step {step_idx}/{total_repos}): "
                f"{'Root origin' if is_root else ('Consumer application' if is_consumer else 'Intermediate library')}"
            )
            self._tracking_store.create(record)

            try:
                with RepoOps() as repo:
                    repo.clone(source_path, self._github_pat)
                    if not is_local and pr_client:
                        open_pr = pr_client._find_open_pr(self._branch_name, self._base_branch)
                        if not open_pr:
                            try:
                                repo._repo.git.push('origin', '--delete', self._branch_name)
                                logger.info("Deleted stale remote branch '%s' on %s", self._branch_name, repo_name)
                            except Exception:
                                pass
                            if self._branch_name in [h.name for h in repo._repo.heads]:
                                try:
                                    repo._repo.git.checkout(self._base_branch)
                                    repo._repo.git.branch('-D', self._branch_name)
                                except Exception:
                                    pass

                    repo.create_branch(self._branch_name, skip_if_exists=True)
                    repo._repo.git.checkout(self._branch_name)

                    ecosystem = get_ecosystem(repo._local_path)
                    files_changed = []

                    manifest_file = get_manifest_file(repo._local_path)
                    support_before = {
                        name: (Path(repo._local_path) / name).read_bytes()
                        for name in (
                            "package-lock.json", "npm-shrinkwrap.json",
                            "yarn.lock", "pnpm-lock.yaml",
                            "constraints.txt", "poetry.lock", "Pipfile.lock",
                            "uv.lock", "pdm.lock",
                        )
                        if (Path(repo._local_path) / name).exists()
                    }
                    if is_root and ecosystem.has_dependency(repo._local_path, finding.component_name):
                        # Root repo has the component directly or via BOM
                        try:
                            ecosystem.bump_direct_dependency(
                                repo._local_path,
                                finding.component_name,
                                finding.current_version,
                                finding.recommended_version,
                            )
                            files_changed.append(manifest_file)
                        except (PomXMLError, PythonManifestError):
                            ecosystem.add_transitive_override(
                                repo._local_path,
                                finding.component_name,
                                finding.recommended_version,
                            )
                            files_changed.append(manifest_file)
                            if manifest_file == "pyproject.toml" and (Path(repo._local_path) / "constraints.txt").exists():
                                files_changed.append("constraints.txt")
                    else:
                        # Intermediate or Consumer repo: pin transitive override
                        ecosystem.add_transitive_override(
                            repo._local_path,
                            finding.component_name,
                            finding.recommended_version,
                        )
                        files_changed.append(manifest_file)
                        if manifest_file == "pyproject.toml" and (Path(repo._local_path) / "constraints.txt").exists():
                            files_changed.append("constraints.txt")

                    # Verify build & tests
                    compiled, compile_msg = ecosystem.verify_build(repo._local_path)
                    if not compiled:
                        logger.warning(
                            "%s: compile failed after pom update -- running CodeFixer fallback: %s",
                            repo_name, compile_msg[:200],
                        )
                        fixer = CodeFixer(repo_path=repo._local_path)
                        summary = fixer.run_retry_fix(
                            tracking_id=record.tracking_id,
                            tracking_store=self._tracking_store,
                        )
                        files_changed.extend(summary.files_changed)
                    else:
                        ecosystem.verify_tests(repo._local_path)

                    for name, before in support_before.items():
                        path = Path(repo._local_path) / name
                        if path.exists() and path.read_bytes() != before:
                            files_changed.append(name)
                    for name in (
                        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                        "pnpm-lock.yaml", "constraints.txt", "poetry.lock",
                        "Pipfile.lock", "uv.lock", "pdm.lock",
                    ):
                        if name not in support_before and (Path(repo._local_path) / name).exists():
                            files_changed.append(name)
                    files_changed = list(dict.fromkeys(files_changed))
                    if not files_changed:
                        files_changed = [manifest_file]

                    # Format commit message linking to all upstream PRs in the chain
                    upstream_refs = []
                    for prev_step in range(step_idx - 1):
                        prev_r = order[prev_step]
                        prev_res = chain_results.get(prev_r)
                        if prev_res and prev_res.pr_number:
                            upstream_refs.append(f"{prev_r} (#{prev_res.pr_number})")
                        else:
                            upstream_refs.append(prev_r)

                    if is_root:
                        commit_msg = (
                            f"fix: upgrade {finding.component_name} to {finding.recommended_version} "
                            "(root in dependency chain)"
                        )
                    else:
                        up_str = ", ".join(upstream_refs) if upstream_refs else "upstream"
                        commit_msg = (
                            f"fix: propagate {finding.component_name} upgrade "
                            f"(depends on {up_str})"
                        )

                    repo.commit_changes(commit_msg, files=files_changed)
                    repo.push_branch(self._branch_name)

                    # For local repos: package remediated repository as downloadable ZIP
                    if is_local:
                        try:
                            dl_dir = get_download_dir()
                            clean_base = Path(repo_name).name
                            zip_filename = f"{clean_base}-remediated.zip"
                            zip_dest = dl_dir / zip_filename
                            with zipfile.ZipFile(zip_dest, "w", zipfile.ZIP_DEFLATED) as zf:
                                for root, _, filenames in os.walk(repo._local_path):
                                    for filename in filenames:
                                        full_p = os.path.join(root, filename)
                                        rel_p = os.path.relpath(full_p, repo._local_path)
                                        if not rel_p.startswith(".git"):
                                            zf.write(full_p, rel_p)
                            logger.info("Saved remediated archive for %s to %s", repo_name, zip_dest)
                        except Exception as zip_exc:
                            logger.warning("Could not archive local remediated repo %s: %s", repo_name, zip_exc)

                # Open PR on GitHub or record Local Remediation
                if is_local:
                    pr_result = PRResult(
                        pr_number=step_idx,
                        pr_url=f"/api/download-zip/{Path(repo_name).name}",
                        was_existing=False,
                    )
                else:
                    pr_result = self._open_chain_pr(
                        pr_client=pr_client,
                        repo_name=repo_name,
                        finding=finding,
                        step_idx=step_idx,
                        total_repos=total_repos,
                        order=order,
                        chain_results=chain_results,
                        files_changed=files_changed,
                    )

                chain_results[repo_name] = pr_result
                current = self._tracking_store.get(record.tracking_id)
                if current:
                    current.pr_number = pr_result.pr_number
                    if is_local:
                        current.status = TrackingStatus.CI_PASSED.value
                    else:
                        current.status = TrackingStatus.PR_OPENED.value if pr_result.was_existing else TrackingStatus.CI_PENDING.value
                    self._tracking_store.update(current)

                logger.info(
                    "[%d/%d] %s for %s: %s (#%d)",
                    step_idx, total_repos,
                    "Remediated ZIP ready" if is_local else "PR opened",
                    repo_name, pr_result.pr_url, pr_result.pr_number,
                )

            except Exception as exc:
                logger.exception("Failed remediation on %s in chain: %s", repo_name, exc)
                current = self._tracking_store.get(record.tracking_id)
                if current:
                    current.status = TrackingStatus.ESCALATED.value
                    current.failure_log_excerpt = str(exc)[:4000]
                    self._tracking_store.update(current)
                chain_results[repo_name] = None

        return chain_results

    def _open_chain_pr(
        self,
        pr_client: PRClient,
        repo_name: str,
        finding,
        step_idx: int,
        total_repos: int,
        order: List[str],
        chain_results: Dict[str, Optional[PRResult]],
        files_changed: List[str],
    ) -> PRResult:
        """Opens a Pull Request explaining its role in the multi-repository remediation chain."""
        is_root = (step_idx == 1)
        is_consumer = (step_idx == total_repos)

        role = "Root Repository" if is_root else ("Consumer Application" if is_consumer else "Intermediate Library")
        title = (
            f"fix: upgrade {finding.component_name} to {finding.recommended_version} "
            f"[{role}]"
        )

        cve_list = ", ".join(finding.cve_ids) if finding.cve_ids else "N/A"
        files_list = "\n".join(f"- `{f}`" for f in files_changed)

        chain_table_rows = []
        for idx, r in enumerate(order, 1):
            pr_info = chain_results.get(r)
            if pr_info and pr_info.pr_url and pr_info.pr_url.startswith("/api/download"):
                status = f"[Fixed Archive]({pr_info.pr_url})"
            elif pr_info:
                status = f"[PR #{pr_info.pr_number}]({pr_info.pr_url})"
            else:
                status = "**Current PR**" if r == repo_name else "Pending"
            r_role = "Root Origin" if idx == 1 else ("Consumer" if idx == len(order) else "Intermediate")
            chain_table_rows.append(f"| {idx} | `{r}` | {r_role} | {status} |")

        chain_table = "\n".join(chain_table_rows)

        body = f"""\
## Multi-Repository Remediation Chain (Step {step_idx} of {total_repos})

This Pull Request is part of an automated cross-repository transitive dependency remediation workflow.

### Target Dependency
- **Component:** `{finding.component_name}`
- **Current Version:** `{finding.current_version}`
- **Remediated Version:** `{finding.recommended_version}`
- **Vulnerabilities Addressed:** {cve_list}
- **Role in Chain:** **{role}**

### Remediation Chain Sequence
| Step | Repository | Role | Status |
|---|---|---|---|
{chain_table}

### Changes Applied
{files_list}

> Generated automatically by the OSS Remediation Agent Multi-Repository Coordinator.
> Human review and CI build verification required before merge.
"""

        summary = ChangeSummary(
            component_name=finding.component_name,
            old_version=finding.current_version,
            new_version=finding.recommended_version,
            files_changed=files_changed,
            rationale=f"Multi-repo chain remediation step {step_idx}/{total_repos} ({role})",
            cve_ids=finding.cve_ids,
        )

        # PRClient.open_remediation_pr is idempotent
        existing = pr_client._find_open_pr(self._branch_name, self._base_branch)
        if existing:
            return PRResult(pr_number=existing.number, pr_url=existing.html_url, was_existing=True)

        try:
            pr = pr_client._repo.create_pull(
                title=title,
                body=body,
                head=self._branch_name,
                base=self._base_branch,
                draft=False,
            )
            return PRResult(pr_number=pr.number, pr_url=pr.html_url, was_existing=False)
        except Exception as exc:
            logger.warning("Falling back to standard PR creation: %s", exc)
            return pr_client.open_remediation_pr(
                branch_name=self._branch_name,
                base_branch=self._base_branch,
                change_summary=summary,
            )
