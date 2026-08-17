"""Detects which PackageEcosystem a repo uses and returns the matching
implementation.

Maven-only today (POC scope, detected by pom.xml presence). Extending to
Python or Node means adding a new elif branch here (e.g. pyproject.toml ->
PipEcosystem, package.json -> NpmEcosystem) plus a new ecosystems/<name>.py
implementing the PackageEcosystem protocol -- nothing else in the pipeline
(CodeFixer, main.py's locality loop, the classifier) needs to change.
"""

from __future__ import annotations

from pathlib import Path

from ecosystems.base import PackageEcosystem


def get_ecosystem(repo_path: Path) -> PackageEcosystem:
    if (repo_path / "pom.xml").exists():
        from ecosystems.maven import MavenEcosystem
        return MavenEcosystem()

    raise ValueError(
        f"No supported package ecosystem detected at {repo_path} "
        "(looked for pom.xml). Only Maven is supported in this POC."
    )
