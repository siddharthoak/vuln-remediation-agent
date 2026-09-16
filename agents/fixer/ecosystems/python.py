"""Python package ecosystem support for pip/pyproject projects."""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Optional, Tuple

from ecosystems.base import DependencyLocality, EcosystemError

logger = logging.getLogger(__name__)


class PythonManifestError(Exception):
    """Raised when a Python dependency manifest cannot be updated."""


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_pattern(name: str) -> re.Pattern:
    return re.compile(
        rf"(^\s*[-]?\s*{re.escape(name)}\s*)(==|~=|>=|<=|>|<|!=)?\s*([^\s;,#]+)?",
        re.IGNORECASE,
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PythonManifestError(f"Could not read {path}: {exc}") from exc


def _write(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise PythonManifestError(f"Could not write {path}: {exc}") from exc


class PythonEcosystem:
    @property
    def manifest_file(self) -> str:
        return self._manifest_name(Path(self._repo_path)) if hasattr(self, "_repo_path") else "requirements.txt"

    @staticmethod
    def _manifest_name(repo_path: Path) -> str:
        if (repo_path / "pyproject.toml").exists():
            return "pyproject.toml"
        for name in ("requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg"):
            if (repo_path / name).exists():
                return name
        return "requirements.txt"

    def _set_repo(self, repo_path: Path) -> Path:
        self._repo_path = Path(repo_path)
        return self._repo_path

    @staticmethod
    def _transaction_paths(repo_path: Path) -> list[Path]:
        names = (
            "requirements.txt", "requirements-dev.txt", "pyproject.toml",
            "Pipfile", "setup.cfg", "constraints.txt", "poetry.lock",
            "Pipfile.lock", "uv.lock", "pdm.lock",
        )
        return [repo_path / name for name in names]

    @classmethod
    def _snapshot(cls, repo_path: Path) -> dict[Path, Optional[bytes]]:
        return {
            path: path.read_bytes() if path.exists() else None
            for path in cls._transaction_paths(repo_path)
        }

    @staticmethod
    def _restore(snapshot: dict[Path, Optional[bytes]]) -> None:
        for path, content in snapshot.items():
            if content is None:
                if path.exists():
                    path.unlink()
            else:
                path.write_bytes(content)

    def _atomic_update(self, repo_path: Path, update) -> None:
        snapshot = self._snapshot(repo_path)
        try:
            update()
        except Exception:
            try:
                self._restore(snapshot)
            except OSError as restore_error:
                logger.error("Failed to restore Python dependency files after remediation failure: %s", restore_error)
            raise

    def _environment(self, repo_path: Path) -> Path:
        digest = hashlib.sha256(str(repo_path.resolve()).encode("utf-8")).hexdigest()[:16]
        return Path(tempfile.gettempdir()) / f"vuln-remediation-python-{digest}"

    def _python_executable(self, repo_path: Path) -> Path:
        env = self._environment(repo_path)
        return env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def _ensure_environment(self, repo_path: Path) -> Path:
        env = self._environment(repo_path)
        python = self._python_executable(repo_path)
        if not python.exists():
            venv.EnvBuilder(with_pip=True, clear=False).create(env)
        marker = env / ".dependencies-ready"
        signature_builder = hashlib.sha256()
        for name in (
            self._manifest_name(repo_path), "constraints.txt",
            "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
        ):
            path = repo_path / name
            if path.exists():
                signature_builder.update(name.encode("utf-8"))
                signature_builder.update(path.read_bytes())
        signature = signature_builder.hexdigest()
        marker_matches = marker.exists() and marker.read_text(encoding="utf-8").strip() == signature
        if not marker_matches:
            if env.exists():
                import shutil
                shutil.rmtree(env, ignore_errors=True)
            venv.EnvBuilder(with_pip=True, clear=False).create(env)
            self._run_pip(python, repo_path, ["install", "pipdeptree"])
            if self._manifest_name(repo_path) == "Pipfile":
                requirements = self._pipfile_requirements(repo_path)
                install_args = ["install", *requirements]
                if (repo_path / "constraints.txt").exists():
                    install_args.extend(["-c", "constraints.txt"])
            else:
                install_args = self._install_args(repo_path)
            if install_args:
                self._run_pip(python, repo_path, install_args)
            marker.write_text(signature, encoding="utf-8")
        return python

    @staticmethod
    def _pipfile_requirements(repo_path: Path) -> list[str]:
        try:
            import tomllib
            data = tomllib.loads(_read(repo_path / "Pipfile"))
        except (OSError, ValueError) as exc:
            raise PythonManifestError(f"Could not parse Pipfile: {exc}") from exc
        requirements = []
        for section in ("packages", "dev-packages"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    requirement = name if spec in {"", "*"} else f"{name}{spec}"
                elif isinstance(spec, dict):
                    if "path" in spec or "git" in spec or "file" in spec:
                        raise PythonManifestError(
                            f"Pipfile dependency {name} uses an unsupported local/VCS source."
                        )
                    version = spec.get("version", "")
                    requirement = name if not version or version == "*" else f"{name}{version}"
                else:
                    raise PythonManifestError(f"Unsupported Pipfile specification for {name}.")
                requirements.append(requirement)
        if not requirements:
            raise PythonManifestError("Pipfile has no installable packages.")
        return requirements

    @classmethod
    def _locked_pipfile_requirements(cls, repo_path: Path) -> list[str]:
        lockfile = repo_path / "Pipfile.lock"
        if not lockfile.exists():
            return cls._pipfile_requirements(repo_path)
        try:
            data = json.loads(_read(lockfile))
        except (OSError, ValueError) as exc:
            raise PythonManifestError(f"Could not parse Pipfile.lock: {exc}") from exc
        requirements = []
        for section in ("default", "develop"):
            for name, spec in data.get(section, {}).items():
                version = spec.get("version") if isinstance(spec, dict) else None
                if not version:
                    raise PythonManifestError(
                        f"Pipfile.lock has no pinned version for {name}."
                    )
                requirements.append(f"{name}{version}")
        if not requirements:
            raise PythonManifestError("Pipfile.lock has no installable packages.")
        return requirements

    @staticmethod
    def _install_args(repo_path: Path) -> Optional[list[str]]:
        manifest = PythonEcosystem._manifest_name(repo_path)
        if manifest.startswith("requirements"):
            args = ["install", "-r", manifest]
        elif manifest in {"pyproject.toml", "setup.cfg"}:
            args = ["install", "."]
        else:
            return None
        constraints = repo_path / "constraints.txt"
        if constraints.exists():
            args.extend(["-c", "constraints.txt"])
        return args

    @staticmethod
    def _run_pip(python: Path, repo_path: Path, args: list[str]) -> None:
        result = subprocess.run(
            [str(python), "-m", "pip", "--disable-pip-version-check", *args],
            cwd=str(repo_path), capture_output=True, text=True, timeout=300,
            env=_safe_env(),
        )
        if result.returncode != 0:
            raise EcosystemError(
                f"Python dependency installation failed (exit code {result.returncode}).\n"
                f"{result.stderr[:4000]}"
            )

    @staticmethod
    def _refresh_lockfile(repo_path: Path) -> None:
        commands = []
        if (repo_path / "poetry.lock").exists():
            commands.append(("poetry.lock", ["poetry", "lock"]))
        elif (repo_path / "Pipfile.lock").exists():
            commands.append(("Pipfile.lock", ["pipenv", "lock"]))
        elif (repo_path / "uv.lock").exists():
            commands.append(("uv.lock", ["uv", "lock"]))
        elif (repo_path / "pdm.lock").exists():
            commands.append(("pdm.lock", ["pdm", "lock"]))
        if not commands:
            return
        lockfile, command = commands[0]
        try:
            result = subprocess.run(
                command, cwd=str(repo_path), capture_output=True, text=True, timeout=300,
                env=_safe_env(),
            )
        except FileNotFoundError as exc:
            raise PythonManifestError(
                f"{lockfile} is present but its lock tool ({command[0]}) is not installed."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PythonManifestError(f"{command[0]} lock refresh timed out after 300 seconds.") from exc
        if result.returncode != 0:
            raise PythonManifestError(
                f"{command[0]} failed to refresh {lockfile} (exit code {result.returncode}).\n"
                f"{result.stderr[:4000]}"
            )

    def resolve_locality(self, repo_path: Path, component_name: str) -> DependencyLocality:
        repo_path = self._set_repo(repo_path)
        target = _normalise(component_name)
        try:
            result = subprocess.run(
                [
                    str(self._ensure_environment(repo_path)),
                    "-m",
                    "pipdeptree",
                    "--exclude",
                    "pipdeptree,pip,setuptools,wheel",
                    "--exclude-dependencies",
                    "--json-tree",
                ],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise EcosystemError("Python executable not found.") from exc
        except subprocess.TimeoutExpired as exc:
            raise EcosystemError("pipdeptree dependency resolution timed out after 120s") from exc

        if result.returncode != 0:
            raise EcosystemError(
                "pipdeptree is required to resolve Python dependency locality. "
                "Install it with `python -m pip install pipdeptree`.\n\n"
                f"{result.stderr[:3000]}"
            )
        try:
            tree = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise EcosystemError(f"pipdeptree output could not be parsed as JSON: {exc}") from exc

        # If explicitly declared in any primary manifest, it is a direct dependency
        if self.has_dependency(repo_path, component_name):
            def find_ver(nodes):
                for n in nodes:
                    p = n.get("package") if isinstance(n.get("package"), dict) else n
                    nm = p.get("key") or p.get("package_name") or ""
                    if _normalise(nm) == target:
                        return p.get("installed_version") or p.get("version")
                    cv = find_ver(n.get("dependencies", []))
                    if cv:
                        return cv
                return None

            return DependencyLocality(
                found=True,
                is_transitive=False,
                depth=1,
                introduced_by=None,
                raw_tree=result.stdout,
                resolved_version=find_ver(tree),
            )

        project_coords = self.get_project_coordinates(repo_path)
        norm_proj = _normalise(project_coords.get("name", ""))

        roots = []
        for node in tree:
            pkg = node.get("package") if isinstance(node.get("package"), dict) else node
            name = pkg.get("key") or pkg.get("package_name") or ""
            if norm_proj and _normalise(name) == norm_proj:
                roots.extend(node.get("dependencies", []))
            else:
                roots.append(node)

        if len(tree) == 1 and not roots:
            top = tree[0]
            roots = top.get("dependencies", [])

        def walk(nodes: list, depth: int = 1, direct_parent: Optional[str] = None):
            for node in nodes:
                package = node.get("package") if isinstance(node.get("package"), dict) else node
                name = package.get("key") or package.get("package_name") or ""
                version = package.get("installed_version") or package.get("version")
                current_direct = name if depth == 1 else direct_parent
                if _normalise(name) == target:
                    yield depth, (None if depth == 1 else current_direct), version
                for child in node.get("dependencies", []):
                    yield from walk([child], depth + 1, current_direct)

        matches = list(walk(roots))
        if not matches:
            return DependencyLocality(found=False, is_transitive=False, depth=-1, raw_tree=result.stdout)

        min_depth, parent, version = min(matches, key=lambda item: item[0])
        return DependencyLocality(
            found=True,
            is_transitive=min_depth > 1,
            depth=min_depth,
            introduced_by=parent,
            raw_tree=result.stdout,
            resolved_version=version,
        )

    def bump_direct_dependency(self, repo_path: Path, component_name: str, current_version: str, target_version: str) -> None:
        self._atomic_update(
            Path(repo_path),
            lambda: self._bump_direct_dependency(repo_path, component_name, current_version, target_version),
        )

    def _bump_direct_dependency(self, repo_path: Path, component_name: str, current_version: str, target_version: str) -> None:
        repo_path = self._set_repo(repo_path)
        manifest = repo_path / self._manifest_name(repo_path)
        if not manifest.exists():
            raise PythonManifestError(f"No supported Python manifest found at {repo_path}")
        if manifest.name == "pyproject.toml":
            if self._replace_pyproject_dependency(manifest, component_name, target_version):
                self._refresh_lockfile(repo_path)
                return
            raise PythonManifestError(f"Dependency {component_name} not found in pyproject.toml")
        if manifest.name == "setup.cfg":
            content = _read(manifest)
            section = re.search(r"(\[options\][\s\S]*?)(?=\n\[|\Z)", content, re.IGNORECASE)
            if not section or not re.search(r"(?im)^\s*install_requires\s*=", section.group(1)):
                raise PythonManifestError("setup.cfg has no [options] install_requires section")
            dependency = re.compile(
                rf"(^\s*{re.escape(component_name)})(\[[^\]]+\])?(\s*[<>=!~].*)?$",
                re.IGNORECASE | re.MULTILINE,
            )
            updated, count = dependency.subn(
                rf"\g<1>\g<2>=={target_version}", content, count=1,
            )
            if not count:
                raise PythonManifestError(f"Dependency {component_name} not found in setup.cfg")
            _write(manifest, updated)
            self._refresh_lockfile(repo_path)
            return
        if manifest.name == "Pipfile":
            content = _read(manifest)
            pattern = re.compile(rf"(^\s*{re.escape(component_name)}\s*=\s*)[^\n]+", re.IGNORECASE | re.MULTILINE)
            updated, count = pattern.subn(rf'\g<1>"{target_version}"', content, count=1)
            if not count:
                raise PythonManifestError(f"Dependency {component_name} not found in Pipfile")
            _write(manifest, updated)
            self._refresh_lockfile(repo_path)
            return

        content = _read(manifest)
        pattern = _version_pattern(component_name)
        lines = content.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.lstrip().startswith(("#", "-r", "--")):
                continue
            match = pattern.match(line)
            if match:
                suffix = ""
                if ";" in line:
                    suffix = line[line.index(";"):]
                newline = "\n" if line.endswith("\n") else ""
                lines[index] = f"{component_name}=={target_version}{suffix.rstrip(chr(10))}{newline}"
                _write(manifest, "".join(lines))
                self._refresh_lockfile(repo_path)
                return
        raise PythonManifestError(f"Dependency {component_name} not found in {manifest.name}")

    def _replace_pyproject_dependency(self, path: Path, component_name: str, target_version: str) -> bool:
        content = _read(path)
        escaped = re.escape(component_name)
        array_pattern = re.compile(rf'(["\'])({escaped})([^"\']*)(\1)', re.IGNORECASE)
        def replace_array(match: re.Match) -> str:
            suffix = match.group(3)
            extras = re.match(r"\s*(\[[^\]]+\])", suffix)
            return f"{match.group(1)}{component_name}{extras.group(1) if extras else ''}=={target_version}{match.group(4)}"

        updated, count = array_pattern.subn(replace_array, content, count=1)
        if count:
            _write(path, updated)
            return True

        line_pattern = rf'(^\s*{escaped}\s*=\s*)("[^"]*"|\'[^\']*\')'
        updated, count = re.subn(
            line_pattern, rf'\g<1>"{target_version}"', content,
            count=1, flags=re.IGNORECASE | re.MULTILINE,
        )
        if count:
            _write(path, updated)
            return True
        return False

    def add_transitive_override(self, repo_path: Path, component_name: str, target_version: str) -> None:
        self._atomic_update(
            Path(repo_path),
            lambda: self._add_transitive_override(repo_path, component_name, target_version),
        )

    def _add_transitive_override(self, repo_path: Path, component_name: str, target_version: str) -> None:
        repo_path = self._set_repo(repo_path)
        manifest = repo_path / self._manifest_name(repo_path)
        if manifest.name == "pyproject.toml":
            constraints = manifest.parent / "constraints.txt"
            content = _read(constraints) if constraints.exists() else ""
            lines = content.splitlines()
            updated = False
            for index, line in enumerate(lines):
                if line.split("==", 1)[0].strip().lower() == component_name.lower():
                    lines[index] = f"{component_name}=={target_version}"
                    updated = True
                    break
            if not updated:
                lines.append(f"{component_name}=={target_version}")
            _write(constraints, "\n".join(line for line in lines if line.strip()) + "\n")
            self._refresh_lockfile(repo_path)
            return
        if manifest.name == "Pipfile":
            content = _read(manifest)
            pattern = re.compile(
                rf"(^\s*{re.escape(component_name)}\s*=\s*)[^\n]+",
                re.IGNORECASE | re.MULTILINE,
            )
            updated, count = pattern.subn(rf'\g<1>"{target_version}"', content, count=1)
            if count:
                _write(manifest, updated)
                self._refresh_lockfile(repo_path)
                return
            section = "[packages]\n"
            if section not in content:
                raise PythonManifestError("Pipfile has no [packages] section for a safe override")
            _write(manifest, content.replace(section, section + f'{component_name} = "=={target_version}"\n', 1))
            self._refresh_lockfile(repo_path)
            return
        if manifest.name == "setup.cfg":
            constraints = manifest.parent / "constraints.txt"
            content = _read(constraints) if constraints.exists() else ""
            lines = [
                line for line in content.splitlines()
                if line.strip() and line.split("==", 1)[0].strip().lower() != component_name.lower()
            ]
            lines.append(f"{component_name}=={target_version}")
            _write(constraints, "\n".join(lines) + "\n")
            self._refresh_lockfile(repo_path)
            return

        content = _read(manifest) if manifest.exists() else ""
        pattern = _version_pattern(component_name)
        if pattern.search(content):
            self.bump_direct_dependency(repo_path, component_name, "", target_version)
            return
        suffix = "" if not content or content.endswith("\n") else "\n"
        _write(manifest, content + suffix + f"{component_name}=={target_version}\n")

    def try_parent_dependency_upgrade(self, repo_path: Path, transitive_component: str, target_transitive_version: str, parent_component: str) -> Optional[Tuple[str, str, str]]:
        return None

    def verify_build(self, repo_path: Path) -> Tuple[bool, str]:
        return install_and_build(repo_path)

    def verify_tests(self, repo_path: Path) -> Tuple[bool, str]:
        return test_repo(repo_path)

    def get_project_coordinates(self, repo_path: Path) -> dict:
        manifest = Path(repo_path) / "pyproject.toml"
        if manifest.exists():
            try:
                import tomllib
                data = tomllib.loads(_read(manifest))
                project = data.get("project", {})
                return {"name": project.get("name", ""), "version": project.get("version", ""), "component_name": project.get("name", "")}
            except (OSError, ValueError):
                return {}
        return {}

    def has_dependency(self, repo_path: Path, component_name: str) -> bool:
        repo_path = Path(repo_path)
        for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg"):
            manifest = repo_path / name
            if manifest.exists():
                try:
                    content = _read(manifest)
                    if re.search(rf"(^|\W){re.escape(component_name)}(\W|$)", content, re.IGNORECASE | re.MULTILINE):
                        return True
                except Exception:
                    pass
        return False


def _safe_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in ("GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS")}


def install_and_build(repo_path: Path, timeout_seconds: int = 300) -> Tuple[bool, str]:
    ecosystem = PythonEcosystem()
    try:
        python = ecosystem._ensure_environment(Path(repo_path))
    except (EcosystemError, PythonManifestError, OSError) as exc:
        return False, str(exc)
    except subprocess.TimeoutExpired:
        return False, f"ERROR: Python dependency installation timed out after {timeout_seconds} seconds."
    try:
        for source in repo_path.rglob("*.py"):
            if set(source.parts) & {".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist"}:
                continue
            ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError) as exc:
        return False, f"Python syntax validation: FAILED\n\n{exc}"
    return True, "Python dependencies installed in an isolated environment and syntax validation succeeded."


def test_repo(repo_path: Path, timeout_seconds: int = 600) -> Tuple[bool, str]:
    excluded = {".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist"}
    test_files = [
        path for path in list(Path(repo_path).rglob("test_*.py")) + list(Path(repo_path).rglob("*_test.py"))
        if not (set(path.parts) & excluded)
    ]
    if not test_files:
        return True, "Python tests: no test files found -- skipping."
    try:
        python = PythonEcosystem()._ensure_environment(Path(repo_path))
        probe = subprocess.run([str(python), "-c", "import pytest"], cwd=str(repo_path), capture_output=True, text=True, timeout=30, env=_safe_env())
        command = [str(python), "-m", "pytest", "-q"] if probe.returncode == 0 else [str(python), "-m", "unittest", "discover", "-v"]
        result = subprocess.run(command, cwd=str(repo_path), capture_output=True, text=True, timeout=timeout_seconds, env=_safe_env())
    except (FileNotFoundError, EcosystemError, PythonManifestError, OSError) as exc:
        return False, f"ERROR: Python test environment unavailable: {exc}"
    except subprocess.TimeoutExpired:
        return False, f"Python tests timed out after {timeout_seconds} seconds."
    if result.returncode == 0:
        return True, "Python tests: SUCCESS."
    return False, f"Python tests: FAILED (exit code {result.returncode})\n\nSTDERR:\n{result.stderr[:10000]}"
