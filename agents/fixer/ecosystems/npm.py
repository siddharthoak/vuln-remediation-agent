"""npm/Node.js implementation of PackageEcosystem.

The Node.js counterpart to ecosystems/maven.py. Everything npm/package.json-
specific lives here: dependency-tree resolution (locality via `npm ls`), the
two package.json edit paths (direct-dependency bump, "overrides" for
transitive pinning), and build/test verification (`npm install` + `npm run
build` and `npm test`). CodeFixer and main.py never touch package.json or
shell out to `npm` directly -- they only call through this class via the
PackageEcosystem protocol (ecosystems/base.py).
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ecosystems.base import DependencyLocality, EcosystemError

logger = logging.getLogger(__name__)


class PackageJsonError(Exception):
    """Raised when package.json cannot be parsed, or a targeted dependency isn't found in it."""


def _read_package_json(repo_path: Path) -> dict:
    pj_path = repo_path / "package.json"
    if not pj_path.exists():
        raise PackageJsonError(f"package.json not found at {pj_path}")
    try:
        with open(pj_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise PackageJsonError(f"Could not parse package.json at {pj_path}: {exc}") from exc


def _write_package_json(repo_path: Path, data: dict) -> None:
    pj_path = repo_path / "package.json"
    with open(pj_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _compare_versions(v1: str, v2: str) -> int:
    """Compares two semver strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
    def _to_parts(v: str) -> list:
        clean = v.strip().lstrip("v^~")
        clean = re.sub(r"[-_](alpha|beta|rc|next|canary).*$", "", clean, flags=re.IGNORECASE)
        parts = []
        for seg in re.split(r"[.-]", clean):
            try:
                parts.append((0, int(seg)))
            except ValueError:
                parts.append((1, seg))
        return parts

    p1, p2 = _to_parts(v1), _to_parts(v2)
    for a, b in zip(p1, p2):
        if a < b:
            return -1
        elif a > b:
            return 1
    if len(p1) < len(p2):
        return -1
    elif len(p1) > len(p2):
        return 1
    return 0


def _parse_major(version: str) -> int:
    try:
        return int(version.strip().lstrip("v^~").split(".")[0])
    except (ValueError, IndexError, AttributeError):
        return -1


def _fetch_newer_parent_versions(package_name: str, current_version: str) -> list[str]:
    """Queries the npm registry for newer versions of the parent dependency."""
    import urllib.parse
    import urllib.request
    
    url_pkg = urllib.parse.quote(package_name, safe="")
    url = f"https://registry.npmjs.org/{url_pkg}"
    
    raw_versions = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-remediation-agent"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_versions = list(data.get("versions", {}).keys())
    except Exception as exc:
        logger.debug("npm registry query for %s failed: %s", package_name, exc)
        return []
        
    cur_major = _parse_major(current_version)
    candidates = []
    seen = set()
    for ver in raw_versions:
        if not ver or ver in seen:
            continue
        seen.add(ver)
        if any(kw in ver.lower() for kw in ("alpha", "beta", "rc", "next", "canary")):
            continue
        if cur_major != -1 and _parse_major(ver) != cur_major:
            continue
        if _compare_versions(ver, current_version) > 0:
            candidates.append(ver)
            
    import functools
    candidates.sort(key=functools.cmp_to_key(_compare_versions))
    return candidates


class NpmEcosystem:
    def resolve_locality(self, repo_path: Path, component_name: str) -> DependencyLocality:
        try:
            # If no lockfile exists, npm ls will return an empty tree.
            # Generate one so we can accurately resolve transitive paths.
            repo_path_obj = Path(repo_path)
            if not (repo_path_obj / "node_modules").exists():
                subprocess.run(
                    ["npm", "install", "--ignore-scripts"],
                    cwd=str(repo_path),
                    capture_output=True,
                    timeout=300,
                )

            result = subprocess.run(
                ["npm", "ls", component_name, "--json", "--all"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise EcosystemError(
                "npm not found -- Node must be installed in the container image."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise EcosystemError("npm ls timed out after 120s") from exc

        try:
            tree = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise EcosystemError(
                f"npm ls output could not be parsed as JSON.\n\nSTDOUT:\n{result.stdout[:4000]}"
            )

        def _find_in_deps(deps: dict, target: str, current_depth: int) -> Tuple[bool, Optional[str], Optional[int], Optional[str]]:
            if target in deps:
                return True, None, current_depth, deps[target].get("version")
            
            for dep_name, dep_info in deps.items():
                if "dependencies" in dep_info:
                    f, i_b, d, rv = _find_in_deps(dep_info["dependencies"], target, current_depth + 1)
                    if f:
                        if current_depth == 1:
                            return True, dep_name, d, rv
                        else:
                            return True, i_b, d, rv
            return False, None, None, None

        dependencies = tree.get("dependencies", {})
        found, introduced_by, depth, resolved_version = _find_in_deps(dependencies, component_name, 1)

        if not found:
            return DependencyLocality(found=False, is_transitive=False, depth=-1, raw_tree=result.stdout)
        
        return DependencyLocality(
            found=True,
            is_transitive=(depth > 1),
            depth=depth,
            introduced_by=introduced_by,
            raw_tree=result.stdout,
            resolved_version=resolved_version
        )

    def bump_direct_dependency(
        self, repo_path: Path, component_name: str, current_version: str, target_version: str
    ) -> None:
        data = _read_package_json(repo_path)
        found = False
        
        for dep_type in ("dependencies", "devDependencies", "optionalDependencies"):
            if dep_type in data and component_name in data[dep_type]:
                old_ver = data[dep_type][component_name]
                prefix = ""
                if old_ver.startswith("^") or old_ver.startswith("~"):
                    prefix = old_ver[0]
                data[dep_type][component_name] = f"{prefix}{target_version}"
                found = True
                logger.info("package.json: %s %s -> %s", component_name, old_ver, data[dep_type][component_name])
                break
                
        if not found:
            raise PackageJsonError(f"Dependency {component_name} not found in package.json")
            
        _write_package_json(repo_path, data)

    def add_transitive_override(self, repo_path: Path, component_name: str, target_version: str) -> None:
        data = _read_package_json(repo_path)
        if "overrides" not in data:
            data["overrides"] = {}
        
        old_ver = data["overrides"].get(component_name)
        data["overrides"][component_name] = target_version
        if old_ver:
            logger.info("package.json: overrides %s %s -> %s", component_name, old_ver, target_version)
        else:
            logger.info("package.json: added overrides %s -> %s", component_name, target_version)
            
        _write_package_json(repo_path, data)

    def try_parent_dependency_upgrade(
        self,
        repo_path: Path,
        transitive_component: str,
        target_transitive_version: str,
        parent_component: str,
    ) -> Optional[Tuple[str, str, str]]:
        parent_cur_ver = self.get_declared_dependency_version(repo_path, parent_component)
        if not parent_cur_ver:
            return None
            
        candidates = _fetch_newer_parent_versions(parent_component, parent_cur_ver)
        if not candidates:
            return None
            
        pj_path = repo_path / "package.json"
        original_pj = pj_path.read_text(encoding="utf-8")
        logger.info(
            "Dependency Hygiene: Evaluating %d parent upgrade candidate(s) for %s to resolve %s",
            len(candidates), parent_component, transitive_component,
        )
        
        for cand_ver in candidates[:4]:
            try:
                self.bump_direct_dependency(repo_path, parent_component, parent_cur_ver, cand_ver)
                
                subprocess.run(
                    ["npm", "install", "--ignore-scripts"],
                    cwd=str(repo_path),
                    capture_output=True,
                    timeout=120
                )
                
                loc = self.resolve_locality(repo_path, transitive_component)
                if loc.found and loc.resolved_version and _compare_versions(loc.resolved_version, target_transitive_version) >= 0:
                    compiled, _ = self.verify_build(repo_path)
                    if compiled:
                        tested, _ = self.verify_tests(repo_path)
                        if tested:
                            logger.info(
                                "Dependency Hygiene: Successfully upgraded direct parent %s (%s -> %s) "
                                "which resolved transitive %s to %s!",
                                parent_component, parent_cur_ver, cand_ver, transitive_component, loc.resolved_version,
                            )
                            return (parent_cur_ver, cand_ver, loc.resolved_version)
            except Exception as exc:
                logger.debug("Candidate parent upgrade %s to %s failed verification: %s", parent_component, cand_ver, exc)
            finally:
                pj_path.write_text(original_pj, encoding="utf-8")
                
        return None

    def verify_build(self, repo_path: Path) -> Tuple[bool, str]:
        return install_and_build(repo_path)

    def verify_tests(self, repo_path: Path) -> Tuple[bool, str]:
        return test_repo(repo_path)

    def get_project_coordinates(self, repo_path: Path) -> dict:
        try:
            data = _read_package_json(repo_path)
            name = data.get("name", "")
            version = data.get("version", "")
            return {
                "name": name,
                "version": version,
                "component_name": name,
            }
        except Exception as exc:
            logger.warning("Could not read project coordinates from %s: %s", repo_path / "package.json", exc)
            return {}

    def has_dependency(self, repo_path: Path, component_name: str) -> bool:
        try:
            data = _read_package_json(repo_path)
            for dep_type in ("dependencies", "devDependencies", "optionalDependencies", "overrides"):
                if dep_type in data and component_name in data[dep_type]:
                    return True
            return False
        except Exception:
            return False

    def get_declared_dependency_version(self, repo_path: Path, component_name: str) -> Optional[str]:
        try:
            data = _read_package_json(repo_path)
            for dep_type in ("dependencies", "devDependencies", "optionalDependencies", "overrides"):
                if dep_type in data and component_name in data[dep_type]:
                    return data[dep_type][component_name]
        except Exception:
            pass
        return None


def install_and_build(repo_path: Path, timeout_seconds: int = 300) -> Tuple[bool, str]:
    """Runs `npm install --ignore-scripts` followed by `npm run build`."""
    safe_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS")}
    
    try:
        install_res = subprocess.run(
            ["npm", "install", "--ignore-scripts"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=safe_env,
        )
    except FileNotFoundError:
        return False, "ERROR: npm not found — Node must be installed in the container image."
    except subprocess.TimeoutExpired:
        return False, f"ERROR: npm install timed out after {timeout_seconds} seconds."

    if install_res.returncode != 0:
        output = f"npm install: FAILED (exit code {install_res.returncode})\n\nSTDERR:\n{install_res.stderr[:10_000]}"
        if install_res.stdout.strip():
            output += f"\n\nSTDOUT:\n{install_res.stdout[:5_000]}"
        return False, output

    try:
        data = _read_package_json(repo_path)
        if "scripts" not in data or "build" not in data["scripts"]:
            return True, "npm build: no build script defined -- skipping."
    except Exception:
        return True, "npm build: skipped (could not read package.json)."

    try:
        build_res = subprocess.run(
            ["npm", "run", "build"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=safe_env,
        )
    except subprocess.TimeoutExpired:
        return False, f"ERROR: npm run build timed out after {timeout_seconds} seconds."

    if build_res.returncode == 0:
        return True, "npm run build: SUCCESS — no build errors."

    output = f"npm run build: FAILED (exit code {build_res.returncode})\n\nSTDERR:\n{build_res.stderr[:10_000]}"
    if build_res.stdout.strip():
        output += f"\n\nSTDOUT:\n{build_res.stdout[:5_000]}"
    return False, output


def test_repo(repo_path: Path, timeout_seconds: int = 600) -> Tuple[bool, str]:
    """Runs `npm test`."""
    safe_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS")}
    
    try:
        data = _read_package_json(repo_path)
        if "scripts" not in data or "test" not in data["scripts"]:
            return True, "npm test: no test script defined -- skipping."
    except Exception:
        return True, "npm test: skipped (could not read package.json)."

    try:
        test_res = subprocess.run(
            ["npm", "test"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=safe_env,
        )
    except FileNotFoundError:
        return False, "ERROR: npm not found — Node must be installed in the container image."
    except subprocess.TimeoutExpired:
        return False, f"ERROR: npm test timed out after {timeout_seconds} seconds."

    if test_res.returncode == 0:
        return True, "npm test: SUCCESS — all tests passed."

    output = f"npm test: FAILED (exit code {test_res.returncode})\n\nSTDERR:\n{test_res.stderr[:10_000]}"
    if test_res.stdout.strip():
        output += f"\n\nSTDOUT:\n{test_res.stdout[:5_000]}"
    return False, output
