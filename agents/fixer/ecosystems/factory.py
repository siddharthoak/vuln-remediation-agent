"""Detects which PackageEcosystem a repo uses and returns the matching
implementation.

Detected by manifest presence: pom.xml -> MavenEcosystem, package.json ->
NpmEcosystem. Adding a new ecosystem (e.g. pyproject.toml -> PipEcosystem)
means adding a new elif branch here plus a new ecosystems/<name>.py
implementing the PackageEcosystem protocol -- nothing else in the pipeline
(CodeFixer, main.py's locality loop, the classifier) needs to change.
"""

from __future__ import annotations

from pathlib import Path

from ecosystems.base import PackageEcosystem


def get_ecosystem(repo_path: Path) -> PackageEcosystem:
    repo_path = Path(repo_path)
    if (repo_path / "pom.xml").exists():
        from ecosystems.maven import MavenEcosystem
        return MavenEcosystem()

    if (repo_path / "package.json").exists():
        from ecosystems.npm import NpmEcosystem
        return NpmEcosystem()

    raise ValueError(
        f"No supported package ecosystem detected at {repo_path} "
        "(looked for pom.xml, package.json)."
    )
