"""Detects which PackageEcosystem a repo uses and returns the matching
implementation.

Detected by manifest presence: pom.xml -> MavenEcosystem, package.json ->
NpmEcosystem, and pyproject.toml/requirements.txt -> PythonEcosystem.
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

    if any((repo_path / name).exists() for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg")):
        from ecosystems.python import PythonEcosystem
        return PythonEcosystem()

    raise ValueError(
        f"No supported package ecosystem detected at {repo_path} "
        "(looked for pom.xml, package.json, pyproject.toml, requirements.txt, requirements-dev.txt, Pipfile, setup.cfg)."
    )


def get_manifest_file(repo_path: Path) -> str:
    """Return the primary dependency manifest for diff review and summaries."""
    repo_path = Path(repo_path)
    if (repo_path / "pom.xml").exists():
        return "pom.xml"
    if (repo_path / "package.json").exists():
        return "package.json"
    if (repo_path / "pyproject.toml").exists():
        return "pyproject.toml"
    for name in ("requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg"):
        if (repo_path / name).exists():
            return name
    raise ValueError(f"No supported dependency manifest found at {repo_path}")
