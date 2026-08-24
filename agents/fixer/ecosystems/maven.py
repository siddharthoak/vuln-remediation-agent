"""Maven implementation of PackageEcosystem.

The only ecosystem this POC actually supports. Everything Maven/pom.xml-
specific lives here: dependency-tree resolution (locality), the two pom.xml
edit paths (direct-dependency bump, dependencyManagement override), and
build verification (`mvn compile`). CodeFixer and main.py never touch pom.xml
or shell out to `mvn` directly -- they only call through this class via the
PackageEcosystem protocol (ecosystems/base.py).

Dependency-tree parsing targets the standard maven-dependency-plugin text
format (`+- `/`\\- `/`|  ` indentation), unchanged for years. See the
module-level VERIFICATION STATUS note below -- validated against hand-built
fixture text, not a live `mvn` run (no Maven in this dev environment).
"""

from __future__ import annotations

import logging
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

_GAV_RE = re.compile(r"^(?P<groupId>[^:\s]+):(?P<artifactId>[^:\s]+):\S+$")
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


def _parse_tree(stdout: str, group_id: str, artifact_id: str) -> DependencyLocality:
    target = f"{group_id}:{artifact_id}"
    ancestor_at: Dict[int, str] = {}

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
            if depth == 1:
                return DependencyLocality(found=True, is_transitive=False, depth=depth, raw_tree=stdout)
            return DependencyLocality(
                found=True,
                is_transitive=True,
                depth=depth,
                introduced_by=ancestor_at.get(depth - 1),
                raw_tree=stdout,
            )

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

        tree = ET.parse(str(pom_path))
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
        """POC scope: single-module only. Appends <dependencyManagement> as a
        direct child of <project> if it doesn't already exist -- Maven's
        parser doesn't enforce strict element ordering, so this is valid even
        though it isn't in the IDE-conventional position.
        """
        pom_path = repo_path / "pom.xml"
        if not pom_path.exists():
            raise PomXMLError(f"pom.xml not found at {pom_path}")

        tree = ET.parse(str(pom_path))
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
            dm = ET.SubElement(root, subtag("dependencyManagement"))

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

    def run_tests(self, repo_path: Path) -> Tuple[bool, str]:
        return test_repo(repo_path)


def compile_repo(repo_path: Path, timeout_seconds: int = 300) -> Tuple[bool, str]:
    """Runs `mvn compile -q --batch-mode` in repo_path. Returns (success, message).

    Shared by MavenEcosystem.verify_build and engines/adk_vertex.py's compile
    tool -- extracted without changing its output text, since that text is
    part of the prompt contract the model has been tuned against.
    """
    try:
        result = subprocess.run(
            ["mvn", "compile", "-q", "--batch-mode"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
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
    """Runs `mvn test -q --batch-mode` in repo_path. Returns (success, message).

    Same shape as compile_repo -- longer default timeout since test suites
    run noticeably slower than a compile-only pass. Shared by
    MavenEcosystem.run_tests and engines/adk_vertex.py's run_maven_test
    tool; only ever invoked when RUN_TESTS=1 and the active engine
    advertises supports_tests (see engines/base.py).
    """
    try:
        result = subprocess.run(
            ["mvn", "test", "-q", "--batch-mode"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
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
