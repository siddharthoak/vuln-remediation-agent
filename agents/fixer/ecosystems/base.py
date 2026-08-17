"""PackageEcosystem protocol -- the pluggable dependency-manifest contract.

Maven is the only implementation today (ecosystems/maven.py) -- this repo's
tool prompts, build verification, and manifest handling are all Java/Maven-
specific by design for this POC. The seam exists so a Python (pip/poetry) or
Node (npm/yarn) ecosystem can be added later as a new PackageEcosystem
implementation, without CodeFixer, main.py's locality-resolution loop, or
the classifier's transitive-dependency logic needing to change -- none of
them depend on Maven directly, only on this protocol and on the
ecosystem-agnostic locality fields already on VulnerabilityFinding
(is_transitive / introduced_by / transitive_depth).

component_name is passed through as whatever string form the scanner
reported and the ecosystem's own convention expects -- "groupId:artifactId"
for Maven, a bare package name for npm/pip. Each implementation parses it
however it needs; callers never split it themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, Tuple


class EcosystemError(Exception):
    """Raised when an ecosystem operation itself fails to run (build tool
    missing, timeout, unreadable manifest) -- distinct from "ran fine, this
    dependency isn't in the tree," which is DependencyLocality(found=False).
    """


@dataclass
class DependencyLocality:
    found: bool
    is_transitive: bool
    depth: int  # 0 = the project itself, 1 = direct dependency, 2+ = transitive
    introduced_by: Optional[str] = None  # ecosystem-native name of the direct-dep ancestor
    raw_tree: str = ""


class PackageEcosystem(Protocol):
    """One implementation per language/package-manager."""

    def resolve_locality(self, repo_path: Path, component_name: str) -> DependencyLocality:
        """Is component_name a direct or transitive dependency of the project
        at repo_path, and if transitive, what pulls it in? Raises
        EcosystemError if the resolution tooling itself fails to run.
        """
        ...

    def bump_direct_dependency(
        self, repo_path: Path, component_name: str, current_version: str, target_version: str
    ) -> None:
        """Edits the manifest to move a direct dependency to target_version."""
        ...

    def add_transitive_override(
        self, repo_path: Path, component_name: str, target_version: str
    ) -> None:
        """Pins a transitive dependency's resolved version without adding it
        as a direct dependency (Maven: <dependencyManagement>; npm: package.json
        "overrides"; pip: a constraints file -- each ecosystem's own primitive
        for the same idea).
        """
        ...

    def verify_build(self, repo_path: Path) -> Tuple[bool, str]:
        """Runs the ecosystem's compile/build step. Never raises -- returns
        (success, message) even for infra failures (tool missing, timeout),
        since a failed build here is an expected, handled outcome (triggers
        the FixEngine fallback), not an exceptional one.
        """
        ...
