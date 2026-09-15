"""
FIX-02: Repository operations — clone, branch, commit, push, cleanup.

Uses GitPython for a programmatic API rather than subprocess calls, which makes
the operations testable without a real git binary and avoids PAT leakage in shell history.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import git

logger = logging.getLogger(__name__)


class RepoBranchExistsError(Exception):
    """Raised when the deterministic branch name already exists remotely."""


@dataclass
class DiffReviewResult:
    passed: bool
    message: str = ""
    changed_files: tuple = ()


def _is_version_match(actual: str, expected_cand: str) -> bool:
    if not actual or not expected_cand:
        return False
    a = actual.strip().lstrip("^~><=").strip().lstrip("v")
    e = expected_cand.strip().lstrip("^~><=").strip().lstrip("v")
    if a == e:
        return True
    for suffix in [".RELEASE", ".Final", ".GA", ".jre", ".android"]:
        if a == f"{e}{suffix}" or e == f"{a}{suffix}":
            return True
        if a.rstrip(suffix) == e.rstrip(suffix):
            return True
    if a.startswith(e + ".") or e.startswith(a + "."):
        return True
    return False


def review_dependency_diff(
    repo_path: str | Path,
    component_name: str,
    target_version: str,
    expected_files: list,
    allow_manifest_already_applied: bool = False,
    manifest_file: str = "pom.xml",
) -> DiffReviewResult:
    """Read-only, deterministic review of the working-tree remediation diff."""
    path = Path(repo_path)
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=str(path), capture_output=True, text=True, timeout=30,
        )
        diff = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=str(path), capture_output=True, text=True, timeout=30,
        )
        manifest_diff = subprocess.run(
            ["git", "diff", "HEAD", "--", manifest_file],
            cwd=str(path), capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return DiffReviewResult(False, f"Could not inspect git diff: {exc}")
    if status.returncode != 0 or diff.returncode != 0 or manifest_diff.returncode != 0:
        return DiffReviewResult(
            False,
            "Could not inspect git diff: "
            f"{(status.stderr or diff.stderr or manifest_diff.stderr).strip()[:1000]}",
        )

    changed = set()
    untracked = []
    for line in status.stdout.splitlines():
        if len(line) < 3:
            continue
        name = line[3:]
        if " -> " in name:
            return DiffReviewResult(False, f"Renamed files are not allowed: {name}")
        if line.startswith("??"):
            untracked.append(name)
        else:
            changed.add(name)
    expected_from_status = {str(name).replace("\\", "/") for name in expected_files if name}
    expected_from_status.add(manifest_file)
    changed.update(name for name in diff.stdout.splitlines() if name)
    changed.update(name for name in untracked if name.replace("\\", "/") in expected_from_status)

    filtered_untracked = [
        f for f in untracked
        if not f.replace("\\", "/").startswith("target/")
        and not f.replace("\\", "/").startswith("build/")
        and not f.replace("\\", "/").startswith(".gradle/")
        and "/__pycache__/" not in f.replace("\\", "/")
        and not f.replace("\\", "/").startswith("__pycache__/")
        and not f.replace("\\", "/").startswith(".pytest_cache/")
        and not f.replace("\\", "/").startswith(".venv/")
        and not f.replace("\\", "/").startswith("venv/")
        and f.replace("\\", "/") not in expected_from_status
    ]
    
    if filtered_untracked:
        return DiffReviewResult(
            False, f"Unexpected untracked files in remediation diff: {', '.join(filtered_untracked)}",
            tuple(sorted(changed | set(filtered_untracked))),
        )

    expected = expected_from_status
    changed_normalized = {name.replace("\\", "/") for name in changed}
    # The manifest is already committed on a retry branch, so it need not be
    # present in the working-tree diff; every source edit must be accounted for.
    unexpected = changed_normalized - expected
    missing_source = (expected - {manifest_file}) - changed_normalized
    if unexpected or missing_source:
        details = []
        if unexpected:
            details.append(f"unexpected files: {', '.join(sorted(unexpected))}")
        if missing_source:
            details.append(f"reported files absent from diff: {', '.join(sorted(missing_source))}")
        return DiffReviewResult(False, "Diff review failed — " + "; ".join(details), tuple(sorted(changed_normalized)))
    if manifest_file not in changed_normalized and not allow_manifest_already_applied:
        return DiffReviewResult(
            False,
            f"Diff review failed — {manifest_file} is not part of the working-tree diff.",
            tuple(sorted(changed_normalized)),
        )

    target_candidates = [v.strip() for v in target_version.split(",") if v.strip()] if target_version else []
    manifest_diff_text = manifest_diff.stdout
    for expected_file in expected - {manifest_file}:
        extra_diff = subprocess.run(
            ["git", "diff", "HEAD", "--", expected_file],
            cwd=str(path), capture_output=True, text=True, timeout=30,
        )
        manifest_diff_text += "\n" + extra_diff.stdout
        expected_path = path / expected_file
        if expected_path.exists():
            manifest_diff_text += "\n" + expected_path.read_text(encoding="utf-8")
    target_in_diff = any(
        (cand in manifest_diff_text or any(_is_version_match(word.strip("\"'<>= /+"), cand) for line in manifest_diff_text.splitlines() for word in line.split()))
        for cand in target_candidates
    )
    if manifest_file in changed_normalized and not target_in_diff:
        return DiffReviewResult(
            False,
            f"Diff review failed — {manifest_file} diff does not contain requested version {target_version}.",
            tuple(sorted(changed_normalized)),
        )

    manifest_path = path / manifest_file
    if not manifest_path.exists():
        return DiffReviewResult(False, f"Diff review failed — {manifest_file} is missing.", tuple(sorted(changed_normalized)))
    
    if manifest_file == "pom.xml":
        # XML validation for Maven pom.xml
        try:
            root = ET.parse(str(manifest_path)).getroot()
        except ET.ParseError as exc:
            return DiffReviewResult(False, f"Diff review failed — pom.xml is invalid: {exc}", tuple(sorted(changed_normalized)))
        
        parts = component_name.split(":")
        group_id = parts[0] if len(parts) > 1 else None
        artifact_id = parts[-1]
        def local(tag):
            return tag.rsplit("}", 1)[-1]
        
        properties = {
            local(child.tag): (child.text or "").strip()
            for parent in root.iter()
            if local(parent.tag) == "properties"
            for child in parent
        }
        matches = []
        for dependency in root.iter():
            if local(dependency.tag) != "dependency":
                continue
            values = {local(child.tag): (child.text or "").strip() for child in dependency}
            if values.get("artifactId") != artifact_id:
                continue
            if group_id is not None and values.get("groupId") != group_id:
                continue
            version = values.get("version", "")
            if version.startswith("${") and version.endswith("}"):
                version = properties.get(version[2:-1], version)
            matches.append(version)
        matches_target = any(
            any(_is_version_match(m, cand) for cand in target_candidates)
            for m in matches
        )
        if matches and not matches_target:
            return DiffReviewResult(
                False,
                f"Diff review failed — {component_name} does not resolve to requested version "
                f"{target_version} in pom.xml (found {matches}).",
                tuple(sorted(changed_normalized)),
            )
    elif manifest_file == "package.json":
        # JSON validation for npm package.json
        try:
            import json as _json
            pkg_data = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            return DiffReviewResult(False, f"Diff review failed — package.json is invalid: {exc}", tuple(sorted(changed_normalized)))
        
        # Check that the component appears with the expected version in deps/devDeps/overrides
        all_deps = {}
        for section in ("dependencies", "devDependencies", "optionalDependencies", "overrides"):
            all_deps.update(pkg_data.get(section, {}))
        
        declared_ver = all_deps.get(component_name, "")
        # Strip semver range prefixes for comparison
        clean_ver = declared_ver.lstrip("^~><=" ).strip()
        if declared_ver and target_candidates:
            matches_target = any(_is_version_match(clean_ver, cand) for cand in target_candidates)
            if not matches_target:
                return DiffReviewResult(
                    False,
                    f"Diff review failed — {component_name} does not resolve to requested version "
                    f"{target_version} in package.json (found {declared_ver}).",
                    tuple(sorted(changed_normalized)),
                )
    elif manifest_file in {"pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg"}:
        try:
            if manifest_file == "pyproject.toml":
                import tomllib
                tomllib.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_text = manifest_path.read_text(encoding="utf-8")
            else:
                manifest_text = manifest_path.read_text(encoding="utf-8")
        except (ValueError, OSError) as exc:
            return DiffReviewResult(
                False, f"Diff review failed — {manifest_file} is invalid: {exc}",
                tuple(sorted(changed_normalized)),
            )

        component_pattern = re.compile(
            rf"(^|\W){re.escape(component_name)}(\W|$)", re.IGNORECASE | re.MULTILINE
        )
        if not component_pattern.search(manifest_text):
            return DiffReviewResult(
                False,
                f"Diff review failed — {component_name} is not present in {manifest_file}.",
                tuple(sorted(changed_normalized)),
            )
        clean_candidates = [c.lstrip("v^~<>= ").strip() for c in target_candidates]
        if clean_candidates and not any(c in manifest_text for c in clean_candidates):
            return DiffReviewResult(
                False,
                f"Diff review failed — {manifest_file} does not contain requested version {target_version}.",
                tuple(sorted(changed_normalized)),
            )
    return DiffReviewResult(True, "Diff review passed.", tuple(sorted(changed_normalized)))


class RepoOps:
    """
    Wraps all git operations needed by the Fixer agent.

    Branch naming is deterministic: fix/{component-name}-{short-hash-of-component+version}
    so that re-running the agent for the same vulnerability does not create duplicate branches
    or duplicate PRs. See create_branch() for collision handling behavior.

    Usage as a context manager ensures cleanup() runs even on error:

        with RepoOps() as ops:
            ops.clone(repo_url, github_pat, local_path)
            ops.create_branch("fix/log4j-abc123")
            # ... make changes ...
            ops.commit_changes("fix: upgrade log4j to 2.20.0")
            ops.push_branch("fix/log4j-abc123")
    """

    def __init__(self):
        self._repo: Optional[git.Repo] = None
        self._local_path: Optional[str] = None
        self._repo_url: Optional[str] = None

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False  # Do not suppress exceptions

    # ── Public API ────────────────────────────────────────────────────────────

    def clone_local(self, source_path: str, remote_url: str, github_pat: str) -> str:
        """
        Create a fast local clone from an already-cloned source directory.

        Uses hardlinks where possible (same filesystem) — milliseconds instead of the
        network round-trip of a full GitHub clone. After cloning, re-points origin to
        remote_url (GitHub) so push and remote branch checks work correctly.

        Typical use: clone the repo once with clone(), then call clone_local() once per
        parallel finding so each worker has an isolated working directory without paying
        the GitHub clone cost N times.
        """
        self._local_path = tempfile.mkdtemp(prefix="oss-remediation-")
        self._repo_url = remote_url
        logger.info("Local clone from %s to %s", source_path, self._local_path)
        self._repo = git.Repo.clone_from(source_path, self._local_path)
        # After a local clone, origin points to the source path — re-point to GitHub.
        authenticated_url = self._build_authenticated_url(remote_url, github_pat)
        self._repo.remotes.origin.set_url(authenticated_url)
        self._configure_credential_helper(github_pat, remote_url)
        return self._local_path

    def clone(self, repo_url: str, github_pat: str, local_path: Optional[str] = None) -> str:
        """
        Clone `repo_url` (remote HTTPS GitHub URL or local directory path).
        If `repo_url` is a local directory (e.g. from an uploaded zip):
          - Clones or copies locally and initializes git if not already a git repository.
        If `repo_url` is remote:
          - Uses `github_pat` for HTTPS auth via Git credential helper.
        """
        self._local_path = local_path or tempfile.mkdtemp(prefix="oss-remediation-")
        self._repo_url = repo_url

        # Local directory check (uploaded zip or local filesystem path)
        source_p = Path(repo_url)
        if source_p.is_dir():
            logger.info("Initializing local repo from %s to %s", repo_url, self._local_path)
            if (source_p / ".git").is_dir():
                self._repo = git.Repo.clone_from(str(source_p.resolve()), self._local_path)
            else:
                shutil.copytree(str(source_p.resolve()), self._local_path, dirs_exist_ok=True)
                self._repo = git.Repo.init(self._local_path)
                with self._repo.config_writer() as config:
                    config.set_value("user", "name", "OSS Remediation Agent")
                    config.set_value("user", "email", "agent@remediation.local")
                self._repo.git.add(A=True)
                if not self._repo.heads:
                    self._repo.index.commit("Initial commit from local repository archive")
            logger.info("Local clone complete: %s", self._local_path)
            return self._local_path

        # Build an authenticated URL by injecting credentials as a Git config credential
        # helper override rather than in the URL string itself.
        authenticated_url = self._build_authenticated_url(repo_url, github_pat)

        logger.info("Cloning %s to %s", repo_url, self._local_path)
        self._repo = git.Repo.clone_from(
            authenticated_url,
            self._local_path,
            env={"GIT_TERMINAL_PROMPT": "0"},
        )
        # Store PAT for subsequent pushes via a credential helper in the local config.
        # This avoids re-embedding the PAT at push time.
        self._configure_credential_helper(github_pat, repo_url)

        logger.info("Clone complete: %s", self._local_path)
        return self._local_path

    def create_branch(self, branch_name: str, skip_if_exists: bool = True) -> bool:
        """
        Create and check out `branch_name` off the current default branch.

        If the branch already exists remotely or locally:
          - skip_if_exists=True (default): logs a warning and returns False.
            The caller should interpret False as "PR already in progress, skip this run."
          - skip_if_exists=False: raises RepoBranchExistsError.

        Returns True if the branch was newly created, False if it already existed.
        """
        self._require_repo()

        has_origin = False
        try:
            has_origin = "origin" in [r.name for r in self._repo.remotes]
        except Exception:
            pass

        if has_origin:
            origin = self._repo.remotes.origin
            try:
                origin.fetch()
                remote_branches = [ref.name for ref in origin.refs]
                remote_branch_ref = f"origin/{branch_name}"
                if remote_branch_ref in remote_branches:
                    message = f"Branch '{branch_name}' already exists remotely — PR likely already open."
                    if skip_if_exists:
                        logger.warning(message + " Skipping this remediation run.")
                        return False
                    raise RepoBranchExistsError(message)
            except Exception as exc:
                logger.debug("Could not fetch remote origin: %s", exc)

        # Check local branches
        if branch_name in [h.name for h in self._repo.heads]:
            message = f"Branch '{branch_name}' already exists locally."
            if skip_if_exists:
                logger.warning(message + " Checking out existing branch.")
                self._repo.heads[branch_name].checkout()
                return False
            raise RepoBranchExistsError(message)

        # Create branch off default (HEAD)
        new_branch = self._repo.create_head(branch_name)
        new_branch.checkout()
        logger.info("Created and checked out branch: %s", branch_name)
        return True

    def commit_changes(self, message: str, files: Optional[list] = None) -> str:
        """
        Stage `files` (or all changes if None) and create a commit.

        Returns the commit hexsha.
        """
        self._require_repo()

        if files:
            self._repo.index.add(files)
        else:
            self._repo.git.add(A=True)

        commit = self._repo.index.commit(message)
        logger.info("Committed %s: %s", commit.hexsha[:8], message)
        return commit.hexsha

    def _refresh_credentials_if_needed(self) -> None:
        """
        Refreshes git credentials with a fresh GitHub token before pushing.
        Ensures long-running repairs (2h - 8h) do not fail due to expired tokens.
        """
        if not self._repo_url or not self._local_path:
            return
        try:
            from common.config import get_github_pat, normalize_repo_name
            clean_name = normalize_repo_name(self._repo_url)
            if clean_name and "/" in clean_name:
                fresh_token = get_github_pat(clean_name)
                if fresh_token:
                    self._configure_credential_helper(fresh_token, self._repo_url)
                    logger.debug("Refreshed git credentials for %s before push", clean_name)
        except Exception as exc:
            logger.debug("Pre-push credential refresh skipped: %s", exc)

    def push_branch(self, branch_name: str) -> None:
        """Push `branch_name` to origin if remote exists. Never force-pushes."""
        self._require_repo()
        has_origin = False
        try:
            has_origin = "origin" in [r.name for r in self._repo.remotes]
        except Exception:
            pass

        if has_origin:
            self._refresh_credentials_if_needed()
            origin = self._repo.remotes.origin
            origin.push(refspec=f"{branch_name}:{branch_name}")
            logger.info("Pushed branch %s to origin", branch_name)
        else:
            logger.info("Local repository without remote origin: branch %s committed locally", branch_name)

    def review_dependency_diff(
        self, component_name: str, target_version: str, expected_files: list,
        allow_manifest_already_applied: bool = False,
        manifest_file: str = "pom.xml",
    ) -> DiffReviewResult:
        """Review the current working tree before it can be committed."""
        self._require_repo()
        return review_dependency_diff(
            self._local_path, component_name, target_version, expected_files,
            allow_manifest_already_applied=allow_manifest_already_applied,
            manifest_file=manifest_file,
        )

    def cleanup(self) -> None:
        """Remove the local clone directory. Safe to call multiple times."""
        if self._local_path and os.path.exists(self._local_path):
            shutil.rmtree(self._local_path, ignore_errors=True)
            logger.info("Cleaned up local clone at %s", self._local_path)
            self._local_path = None
            self._repo = None

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def make_branch_name(component_name: str, current_version: str) -> str:
        """
        Produce a deterministic, collision-resistant branch name for a vulnerability fix.
        Format: fix/{sanitized-component}-{8-char-hash}

        The hash is derived from component_name + current_version, so the same vulnerability
        always maps to the same branch name across agent runs, preventing duplicate PRs.
        """
        import hashlib
        key = f"{component_name}@{current_version}"
        short_hash = hashlib.sha1(key.encode()).hexdigest()[:8]
        # Sanitize component name for use in branch name
        safe_name = component_name.replace(":", "-").replace("/", "-").replace(".", "-")
        safe_name = safe_name[:40]  # Keep branch name reasonable
        return f"fix/{safe_name}-{short_hash}"

    # ── Private helpers ───────────────────────────────────────────────────────

    def _require_repo(self):
        if self._repo is None:
            raise RuntimeError("No repository cloned yet. Call clone() first.")

    def _build_authenticated_url(self, repo_url: str, github_pat: str) -> str:
        """
        Inject PAT into the HTTPS URL as `x-access-token:PAT@host/path`.
        This is GitHub's documented machine-account authentication pattern for HTTPS.
        The PAT does NOT appear in the URL returned by `git remote -v` after clone
        because GitPython uses it only during the clone operation.
        """
        parsed = urlparse(repo_url)
        return parsed._replace(
            netloc=f"x-access-token:{github_pat}@{parsed.hostname}"
        ).geturl()

    def _configure_credential_helper(self, github_pat: str, repo_url: str) -> None:
        """
        Store the PAT in the repo's local git config as a credential helper store
        so subsequent pushes authenticate without re-embedding the PAT in remote URLs.
        """
        parsed = urlparse(repo_url)
        host = parsed.hostname
        with self._repo.config_writer() as cw:
            cw.set_value(f'credential "https://{host}"', "helper", "store")
        # Write to the local git credentials store (scoped to this temp directory)
        creds_path = os.path.join(self._local_path, ".git", "credentials")
        with open(creds_path, "w") as f:
            f.write(f"https://x-access-token:{github_pat}@{host}\n")
        with self._repo.config_writer() as cw:
            cw.set_value("credential", "helper", f"store --file {creds_path}")
