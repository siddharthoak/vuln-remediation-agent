"""Maven implementation of PackageEcosystem.

The only ecosystem this POC actually supports. Everything Maven/pom.xml-
specific lives here: dependency-tree resolution (locality), the two pom.xml
edit paths (direct-dependency bump, dependencyManagement override), and
build/test verification (`mvn compile` and `mvn -B test -q`). CodeFixer and main.py never touch pom.xml
or shell out to `mvn` directly -- they only call through this class via the
PackageEcosystem protocol (ecosystems/base.py).

Dependency-tree parsing targets the standard maven-dependency-plugin text
format (`+- `/`\\- `/`|  ` indentation), unchanged for years. See the
module-level VERIFICATION STATUS note below -- validated against hand-built
fixture text, not a live `mvn` run (no Maven in this dev environment).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Optional, Tuple

from ecosystems.base import DependencyLocality, EcosystemError

logger = logging.getLogger(__name__)

# VERIFICATION STATUS: resolve_locality's parser has only been validated
# against hand-built fixture text matching the documented tree format, not a
# live `mvn` run. Before relying on this for real fixes, run it against a
# real repo (e.g. vulnerable-java-app with jackson-dataformat-yaml added)
# and confirm it correctly classifies org.yaml:snakeyaml as transitive.

_GAV_RE = re.compile(r"^(?P<groupId>[^:\s]+):(?P<artifactId>[^:\s]+):[^\s:]+(?::[^\s:]+)*(?:\s+.*)?$")
_MARKER_RE = re.compile(r"^((?:\|  |   )*)(\+- |\\- )")


class PomXMLError(Exception):
    """Raised when pom.xml cannot be parsed, or a targeted dependency isn't found in it."""


def _split_ga(component_name: str) -> Tuple[Optional[str], str]:
    """Matches the original _bump_pom_version behavior exactly: group_id is
    None (not defaulted to artifact_id) when component_name has no colon --
    callers that need a real groupId (tree resolution, dependencyManagement,
    which are both keyed on group:artifact) must handle that case themselves.
    """
    parts = component_name.split(":")
    artifact_id = parts[-1]
    group_id = parts[0] if len(parts) > 1 else None
    return group_id, artifact_id


def _pom_namespace_helpers(root) -> tuple:
    """Detects whether a pom.xml uses the default Maven POM namespace and
    returns (ns, tag, subtag, prop_xpath, dep_xpath, ns_uri) so any method
    walking the tree handles both namespaced (<project xmlns="..."/>) and
    bare (<project/>) pom.xml files identically.
    """
    ns_uri = "http://maven.apache.org/POM/4.0.0"
    if root.tag.startswith(f"{{{ns_uri}}}"):
        ns = {"m": ns_uri}
        dep_xpath = ".//m:dependency"
        tag = lambda t: f"m:{t}"  # noqa: E731
        subtag = lambda t: f"{{{ns_uri}}}{t}"  # noqa: E731
        prop_xpath = lambda name: f"./m:properties/m:{name}"  # noqa: E731
    else:
        ns = {}
        dep_xpath = ".//dependency"
        tag = lambda t: t  # noqa: E731
        subtag = lambda t: t  # noqa: E731
        prop_xpath = lambda name: f"./properties/{name}"  # noqa: E731
    return ns, tag, subtag, prop_xpath, dep_xpath, ns_uri


# ── dependency:tree parsing ─────────────────────────────────────────────────

def _strip_info_prefix(line: str) -> str:
    if line.startswith("[INFO] "):
        return line[len("[INFO] "):]
    if line.startswith("[INFO]"):
        return line[len("[INFO]"):].lstrip()
    return line


def _line_depth(line: str) -> Optional[int]:
    match = _MARKER_RE.match(line)
    if match:
        return (len(match.group(1)) // 3) + 1
    if not line.startswith(" ") and _GAV_RE.match(line.strip()):
        return 0
    return None


def _parse_ga(line: str) -> Optional[str]:
    match = _MARKER_RE.match(line)
    content = line[match.end():] if match else line.strip()
    gav = _GAV_RE.match(content)
    return f"{gav.group('groupId')}:{gav.group('artifactId')}" if gav else None


def _parse_version_from_gav_line(line: str) -> Optional[str]:
    match = _MARKER_RE.match(line)
    content = line[match.end():] if match else line.strip()
    clean = re.sub(r"\s+\(.*?\)$", "", content).strip()
    parts = clean.split(":")
    if len(parts) == 4 or len(parts) == 5:
        return parts[3]
    elif len(parts) >= 6:
        return parts[4]
    return None


def _parse_tree(stdout: str, group_id: str, artifact_id: str) -> DependencyLocality:
    target = f"{group_id}:{artifact_id}"
    ancestor_at: Dict[int, str] = {}
    best_match = None

    for raw_line in stdout.splitlines():
        line = _strip_info_prefix(raw_line)
        depth = _line_depth(line)
        if depth is None:
            continue
        ga = _parse_ga(line)
        if ga is None:
            continue
        ancestor_at[depth] = ga

        if ga == target and depth > 0:
            ver = _parse_version_from_gav_line(line)
            if depth == 1:
                return DependencyLocality(found=True, is_transitive=False, depth=depth, raw_tree=stdout, resolved_version=ver)
            if best_match is None:
                best_match = DependencyLocality(
                    found=True,
                    is_transitive=True,
                    depth=depth,
                    introduced_by=ancestor_at.get(1),
                    raw_tree=stdout,
                    resolved_version=ver,
                )

    if best_match is not None:
        return best_match

    return DependencyLocality(found=False, is_transitive=False, depth=-1, raw_tree=stdout)


class MavenEcosystem:
    def resolve_locality(self, repo_path: Path, component_name: str) -> DependencyLocality:
        group_id, artifact_id = _split_ga(component_name)
        if group_id is None:
            raise EcosystemError(
                f"{component_name!r} has no groupId:artifactId form -- "
                "locality resolution needs a real groupId to filter dependency:tree."
            )
        try:
            result = subprocess.run(
                ["mvn", "-B", "dependency:tree", f"-Dincludes={group_id}:{artifact_id}"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise EcosystemError(
                "mvn not found -- Maven must be installed in the container image."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise EcosystemError("mvn dependency:tree timed out after 120s") from exc

        if result.returncode != 0:
            raise EcosystemError(
                f"mvn dependency:tree exited {result.returncode}.\n\nSTDERR:\n{result.stderr[:4000]}"
            )

        return _parse_tree(result.stdout, group_id, artifact_id)

    def bump_direct_dependency(
        self, repo_path: Path, component_name: str, current_version: str, target_version: str
    ) -> None:
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            raise PomXMLError(f"pom.xml not found at {pom_path}")

        try:
            tree = ET.parse(str(pom_path))
        except ET.ParseError as exc:
            raise PomXMLError(f"Could not parse pom.xml at {pom_path}: {exc}") from exc
        root = tree.getroot()
        ns, tag, subtag, prop_xpath, dep_xpath, ns_uri = _pom_namespace_helpers(root)
        ET.register_namespace("", ns_uri)

        group_id, artifact_id = _split_ga(component_name)

        found = False
        for dep in root.findall(dep_xpath, ns):
            aid_el = dep.find(tag("artifactId"), ns)
            gid_el = dep.find(tag("groupId"), ns)
            ver_el = dep.find(tag("version"), ns)
            if aid_el is None:
                continue
            aid_match = aid_el.text == artifact_id
            gid_match = group_id is None or (gid_el is not None and gid_el.text == group_id)
            if not (aid_match and gid_match):
                continue

            if ver_el is None:
                # Version managed by BOM/dependencyManagement — add an explicit override.
                ET.SubElement(dep, subtag("version")).text = target_version
                found = True
                logger.info("pom.xml: %s added explicit version %s (was BOM-managed)", component_name, target_version)
                break

            ver_text = ver_el.text or ""
            if ver_text.startswith("${") and ver_text.endswith("}"):
                prop_name = ver_text[2:-1]
                prop_el = root.find(prop_xpath(prop_name), ns)
                if prop_el is not None:
                    logger.info("pom.xml: property %s %s → %s", prop_name, prop_el.text, target_version)
                    prop_el.text = target_version
                else:
                    logger.info("pom.xml: %s inlining version (property %s not found)", component_name, prop_name)
                    ver_el.text = target_version
                found = True
                break

            if ver_text == current_version:
                ver_el.text = target_version
                found = True
                logger.info("pom.xml: %s %s → %s", component_name, current_version, target_version)
                break

        if not found:
            raise PomXMLError(f"Dependency {component_name}@{current_version} not found in pom.xml.")
        tree.write(str(pom_path), xml_declaration=True, encoding="utf-8")

    def add_transitive_override(self, repo_path: Path, component_name: str, target_version: str) -> None:
        """Add or update a project-level dependencyManagement override."""
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            raise PomXMLError(f"pom.xml not found at {pom_path}")

        try:
            tree = ET.parse(str(pom_path))
        except ET.ParseError as exc:
            raise PomXMLError(f"Could not parse pom.xml at {pom_path}: {exc}") from exc
        root = tree.getroot()
        ns, tag, subtag, _prop_xpath, _dep_xpath, ns_uri = _pom_namespace_helpers(root)
        ET.register_namespace("", ns_uri)

        group_id, artifact_id = _split_ga(component_name)
        if group_id is None:
            raise PomXMLError(
                f"{component_name!r} has no groupId:artifactId form -- "
                "a dependencyManagement override needs a real groupId."
            )

        dm = root.find(tag("dependencyManagement"), ns)
        if dm is None:
            dm = ET.Element(subtag("dependencyManagement"))
            # Keep Maven's conventional top-level model order so generated POMs
            # remain consumable by strict Maven/XML tooling.
            insert_before = {
                "dependencies",
                "repositories",
                "pluginRepositories",
                "build",
                "reporting",
                "profiles",
            }
            insert_at = next(
                (
                    index
                    for index, child in enumerate(root)
                    if child.tag.rsplit("}", 1)[-1] in insert_before
                ),
                len(root),
            )
            root.insert(insert_at, dm)

        dm_deps = dm.find(tag("dependencies"), ns)
        if dm_deps is None:
            dm_deps = ET.SubElement(dm, subtag("dependencies"))

        for dep in dm_deps.findall(tag("dependency"), ns):
            aid_el = dep.find(tag("artifactId"), ns)
            gid_el = dep.find(tag("groupId"), ns)
            if aid_el is not None and aid_el.text == artifact_id and gid_el is not None and gid_el.text == group_id:
                ver_el = dep.find(tag("version"), ns)
                if ver_el is None:
                    ver_el = ET.SubElement(dep, subtag("version"))
                logger.info(
                    "pom.xml: dependencyManagement override %s:%s %s → %s",
                    group_id, artifact_id, ver_el.text, target_version,
                )
                ver_el.text = target_version
                tree.write(str(pom_path), xml_declaration=True, encoding="utf-8")
                return

        dep = ET.SubElement(dm_deps, subtag("dependency"))
        ET.SubElement(dep, subtag("groupId")).text = group_id
        ET.SubElement(dep, subtag("artifactId")).text = artifact_id
        ET.SubElement(dep, subtag("version")).text = target_version
        logger.info(
            "pom.xml: added dependencyManagement override %s:%s → %s",
            group_id, artifact_id, target_version,
        )
        tree.write(str(pom_path), xml_declaration=True, encoding="utf-8")

    def verify_build(self, repo_path: Path) -> Tuple[bool, str]:
        return compile_repo(repo_path)

    def verify_tests(self, repo_path: Path) -> Tuple[bool, str]:
        return test_repo(repo_path)

    def get_project_coordinates(self, repo_path: Path) -> dict:
        """Returns metadata about the project itself (groupId, artifactId, version, component_name)."""
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            return {}
        try:
            tree = ET.parse(str(pom_path))
            root = tree.getroot()
            ns, tag, _, _, _, _ = _pom_namespace_helpers(root)
            gid_el = root.find(tag("groupId"), ns)
            if gid_el is None or not gid_el.text:
                parent_el = root.find(tag("parent"), ns)
                if parent_el is not None:
                    gid_el = parent_el.find(tag("groupId"), ns)
            aid_el = root.find(tag("artifactId"), ns)
            ver_el = root.find(tag("version"), ns)
            if ver_el is None or not ver_el.text:
                parent_el = root.find(tag("parent"), ns)
                if parent_el is not None:
                    ver_el = parent_el.find(tag("version"), ns)

            group_id = gid_el.text.strip() if gid_el is not None and gid_el.text else ""
            artifact_id = aid_el.text.strip() if aid_el is not None and aid_el.text else ""
            version = ver_el.text.strip() if ver_el is not None and ver_el.text else ""
            return {
                "group_id": group_id,
                "artifact_id": artifact_id,
                "version": version,
                "component_name": f"{group_id}:{artifact_id}" if group_id and artifact_id else artifact_id,
            }
        except Exception as exc:
            logger.warning("Could not read project coordinates from %s: %s", pom_path, exc)
            return {}

    def has_dependency(self, repo_path: Path, component_name: str) -> bool:
        """Checks if component_name (groupId:artifactId or artifactId) is declared in pom.xml."""
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            return False
        try:
            tree = ET.parse(str(pom_path))
            root = tree.getroot()
            ns, tag, _, _, dep_xpath, _ = _pom_namespace_helpers(root)
            group_id, artifact_id = _split_ga(component_name)
            for dep in root.findall(dep_xpath, ns):
                aid_el = dep.find(tag("artifactId"), ns)
                gid_el = dep.find(tag("groupId"), ns)
                if aid_el is not None and aid_el.text == artifact_id:
                    if group_id is None or (gid_el is not None and gid_el.text == group_id):
                        return True
            dm = root.find(tag("dependencyManagement"), ns)
            if dm is not None:
                for dep in dm.findall(dep_xpath, ns):
                    aid_el = dep.find(tag("artifactId"), ns)
                    gid_el = dep.find(tag("groupId"), ns)
                    if aid_el is not None and aid_el.text == artifact_id:
                        if group_id is None or (gid_el is not None and gid_el.text == group_id):
                            return True
        except Exception:
            pass
        return False

    def get_declared_dependency_version(self, repo_path: Path, component_name: str) -> Optional[str]:
        """Returns the declared version of component_name directly in pom.xml, resolving ${properties}."""
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            return None
        try:
            tree = ET.parse(str(pom_path))
            root = tree.getroot()
            ns, tag, _, prop_xpath, dep_xpath, _ = _pom_namespace_helpers(root)
            group_id, artifact_id = _split_ga(component_name)
            for dep in root.findall(dep_xpath, ns):
                aid_el = dep.find(tag("artifactId"), ns)
                gid_el = dep.find(tag("groupId"), ns)
                ver_el = dep.find(tag("version"), ns)
                if aid_el is None or ver_el is None or not ver_el.text:
                    continue
                if aid_el.text != artifact_id:
                    continue
                if group_id is not None and gid_el is not None and gid_el.text != group_id:
                    continue
                ver_text = ver_el.text.strip()
                if ver_text.startswith("${") and ver_text.endswith("}"):
                    prop_name = ver_text[2:-1]
                    prop_el = root.find(prop_xpath(prop_name), ns)
                    if prop_el is not None and prop_el.text:
                        return prop_el.text.strip()
                return ver_text
        except Exception as exc:
            logger.debug("Error reading declared dependency version for %s: %s", component_name, exc)
        return None

    def try_parent_dependency_upgrade(
        self,
        repo_path: Path,
        transitive_component: str,
        target_transitive_version: str,
        parent_component: str,
    ) -> Optional[Tuple[str, str, str]]:
        """Dependency Hygiene: Checks if upgrading the direct parent dependency
        resolves the transitive vulnerability cleanly, avoiding unnecessary <dependencyManagement>.
        Returns (parent_current_version, candidate_version, resolved_transitive_version) if successful, else None.
        """
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            return None

        parent_cur_ver = self.get_declared_dependency_version(repo_path, parent_component)
        if not parent_cur_ver:
            return None

        parent_gid, parent_aid = _split_ga(parent_component)
        if not parent_gid or not parent_aid:
            return None

        candidates = _fetch_newer_parent_versions(parent_gid, parent_aid, parent_cur_ver)
        if not candidates:
            return None

        original_pom = pom_path.read_text(encoding="utf-8")
        logger.info(
            "Dependency Hygiene: Evaluating %d parent upgrade candidate(s) for %s to resolve %s",
            len(candidates), parent_component, transitive_component,
        )

        for cand_ver in candidates[:4]:
            succeeded = False
            try:
                self.bump_direct_dependency(repo_path, parent_component, parent_cur_ver, cand_ver)
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
                            succeeded = True
                            return (parent_cur_ver, cand_ver, loc.resolved_version)
            except Exception as exc:
                logger.debug("Candidate parent upgrade %s to %s failed verification: %s", parent_component, cand_ver, exc)
            finally:
                if not succeeded:
                    pom_path.write_text(original_pom, encoding="utf-8")

        return None


def _parse_major(version: str) -> int:
    try:
        return int(version.strip().lstrip("v").split(".")[0])
    except (ValueError, IndexError, AttributeError):
        return -1


def _compare_versions(v1: str, v2: str) -> int:
    """Compares two Maven version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
    qualifier_order = {
        "snapshot": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3,
        "milestone": -2, "m": -2, "rc": -1, "cr": -1,
        "final": 0, "ga": 0, "release": 0,
    }

    def _to_parts(v: str) -> tuple[tuple[int, ...], tuple[int, str]]:
        clean = v.strip().lstrip("v")
        match = re.match(r"^(\d+(?:\.\d+)*)(?:[-_.]?([A-Za-z]+)(\d*)|$)", clean)
        if not match:
            return (0,), (0, "")
        numeric = tuple(int(part) for part in match.group(1).split("."))
        qualifier = match.group(2)
        if not qualifier:
            return numeric, (0, "")
        return numeric, (
            qualifier_order.get(qualifier.lower(), -6),
            qualifier.lower(),
        )

    numeric1, qualifier1 = _to_parts(v1)
    numeric2, qualifier2 = _to_parts(v2)
    max_len = max(len(numeric1), len(numeric2))
    padded1 = numeric1 + (0,) * (max_len - len(numeric1))
    padded2 = numeric2 + (0,) * (max_len - len(numeric2))
    if padded1 != padded2:
        return 1 if padded1 > padded2 else -1
    if qualifier1 != qualifier2:
        return 1 if qualifier1 > qualifier2 else -1
    return 0


def _fetch_newer_parent_versions(group_id: str, artifact_id: str, current_version: str) -> list[str]:
    """Queries Maven Central for newer patch/minor releases of the direct parent dependency.
    Prefers repo1.maven.org Fastly CDN maven-metadata.xml for speed and reliability,
    falling back to Solr search.maven.org if needed.
    """
    import urllib.parse
    import urllib.request
    import xml.etree.ElementTree as ET
    import json

    raw_versions: list[str] = []

    # 1. Primary: Fastly CDN canonical maven-metadata.xml
    g_path = group_id.replace(".", "/")
    cdn_url = f"https://repo1.maven.org/maven2/{g_path}/{artifact_id}/maven-metadata.xml"
    try:
        req = urllib.request.Request(cdn_url, headers={"User-Agent": "vuln-remediation-agent"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            root = ET.fromstring(resp.read())
            raw_versions = [
                el.text.strip()
                for el in root.findall(".//version")
                if el.text and el.text.strip()
            ]
    except Exception as exc:
        logger.debug("repo1.maven.org metadata query for %s:%s failed: %s", group_id, artifact_id, exc)

    # 2. Fallback: Solr search.maven.org
    if not raw_versions:
        solr_url = f"https://search.maven.org/solrsearch/select?q=g:%22{group_id}%22+AND+a:%22{artifact_id}%22&core=gav&rows=40&wt=json"
        try:
            req = urllib.request.Request(solr_url, headers={"User-Agent": "vuln-remediation-agent"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                docs = data.get("response", {}).get("docs", [])
                raw_versions = [d.get("v", "") for d in docs if d.get("v")]
        except Exception as exc:
            logger.debug("search.maven.org lookup for %s:%s failed: %s", group_id, artifact_id, exc)

    if not raw_versions:
        return []

    cur_major = _parse_major(current_version)
    candidates = []
    seen = set()
    for ver in raw_versions:
        if not ver or ver in seen:
            continue
        seen.add(ver)
        if re.search(r"(?i)(?:alpha|beta|milestone|(?:^|[.\-_])(?:a|b|m|rc|cr|snapshot)(?:$|[.\-_]))", ver):
            continue
        if cur_major != -1 and _parse_major(ver) != cur_major:
            continue
        if _compare_versions(ver, current_version) > 0:
            candidates.append(ver)

    import functools
    candidates.sort(key=functools.cmp_to_key(_compare_versions))
    return candidates


def compile_repo(repo_path: Path, timeout_seconds: int = 300) -> Tuple[bool, str]:
    """Runs `mvn compile -q --batch-mode` in repo_path. Returns (success, message).

    Shared by MavenEcosystem.verify_build and engines/adk_vertex.py's compile
    tool -- extracted without changing its output text, since that text is
    part of the prompt contract the model has been tuned against.
    """
    safe_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS")}
    try:
        result = subprocess.run(
            ["mvn", "compile", "-q", "--batch-mode"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=safe_env,
        )
    except FileNotFoundError:
        return False, "ERROR: mvn not found — Maven must be installed in the container image."
    except subprocess.TimeoutExpired:
        return False, f"ERROR: mvn compile timed out after {timeout_seconds} seconds."

    if result.returncode == 0:
        return True, "mvn compile: SUCCESS — no compilation errors."

    output = (
        f"mvn compile: FAILED (exit code {result.returncode})\n\n"
        f"STDERR:\n{result.stderr[:10_000]}"
    )
    if result.stdout.strip():
        output += f"\n\nSTDOUT:\n{result.stdout[:5_000]}"
    return False, output


def test_repo(repo_path: Path, timeout_seconds: int = 600) -> Tuple[bool, str]:
    """Runs the Maven test suite with a bounded timeout."""
    safe_env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS")}
    try:
        result = subprocess.run(
            ["mvn", "-B", "test", "-q"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=safe_env,
        )
    except FileNotFoundError:
        return False, "ERROR: mvn not found — Maven must be installed in the container image."
    except subprocess.TimeoutExpired:
        return False, f"ERROR: mvn test timed out after {timeout_seconds} seconds."

    if result.returncode == 0:
        return True, "mvn test: SUCCESS — all tests passed."

    output = (
        f"mvn test: FAILED (exit code {result.returncode})\n\n"
        f"STDERR:\n{result.stderr[:10_000]}"
    )
    if result.stdout.strip():
        output += f"\n\nSTDOUT:\n{result.stdout[:5_000]}"
    return False, output
