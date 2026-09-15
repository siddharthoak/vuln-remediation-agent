import json
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from ecosystems.maven import MavenEcosystem, _compare_versions, _parse_tree
from ecosystems.npm import NpmEcosystem, _compare_versions as compare_npm_versions
from ecosystems.python import PythonEcosystem
from scan_report_client import ScanReportClient


class PythonEcosystemTests(unittest.TestCase):
    def test_requirements_direct_and_transitive_override(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")
            ecosystem = PythonEcosystem()
            ecosystem.bump_direct_dependency(repo, "requests", "2.0", "2.32.4")
            ecosystem.add_transitive_override(repo, "urllib3", "2.5.0")
            self.assertEqual(
                (repo / "requirements.txt").read_text(encoding="utf-8"),
                "requests==2.32.4\nurllib3==2.5.0\n",
            )

    def test_pyproject_extras_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests[socks]>=2.0"]\n',
                encoding="utf-8",
            )
            PythonEcosystem().bump_direct_dependency(repo, "requests", "", "2.32.4")
            self.assertIn("requests[socks]==2.32.4", (repo / "pyproject.toml").read_text(encoding="utf-8"))

    def test_setup_cfg_uses_constraints_for_transitive_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "setup.cfg").write_text(
                "[options]\ninstall_requires=\n    requests>=2.0\n",
                encoding="utf-8",
            )
            ecosystem = PythonEcosystem()
            ecosystem.bump_direct_dependency(repo, "requests", "", "2.32.4")
            ecosystem.add_transitive_override(repo, "urllib3", "2.5.0")
            self.assertIn("requests==2.32.4", (repo / "setup.cfg").read_text(encoding="utf-8"))
            self.assertEqual((repo / "constraints.txt").read_text(encoding="utf-8"), "urllib3==2.5.0\n")

    def test_python_manifest_rolls_back_when_lock_refresh_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            manifest = repo / "requirements.txt"
            original = "requests>=2.0\n"
            manifest.write_text(original, encoding="utf-8")
            ecosystem = PythonEcosystem()
            with patch.object(
                ecosystem,
                "_refresh_lockfile",
                side_effect=RuntimeError("lock refresh failed"),
            ):
                with self.assertRaises(RuntimeError):
                    ecosystem.bump_direct_dependency(repo, "requests", "", "2.32.4")
            self.assertEqual(manifest.read_text(encoding="utf-8"), original)

    def test_pipfile_requirements_are_translated_for_isolated_install(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "Pipfile").write_text(
                '[packages]\nrequests = ">=2.0"\nurllib3 = "*"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                PythonEcosystem._pipfile_requirements(repo),
                ["requests>=2.0", "urllib3"],
            )

    def test_locked_pipfile_uses_pinned_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "Pipfile.lock").write_text(
                '{"default":{"requests":{"version":"==2.32.4"}},'
                '"develop":{"pytest":{"version":"==8.3.3"}}}',
                encoding="utf-8",
            )
            self.assertEqual(
                PythonEcosystem._locked_pipfile_requirements(repo),
                ["requests==2.32.4", "pytest==8.3.3"],
            )

    def test_pipdeptree_depth_and_parent(self):
        tree = json.dumps([{
            "package": {"key": "requests", "version": "2.0"},
            "dependencies": [{
                "package": {"key": "urllib3", "version": "1.26.5"},
                "dependencies": [],
            }],
        }])
        with tempfile.TemporaryDirectory() as directory:
            ecosystem = PythonEcosystem()
            with patch(
                "ecosystems.python.PythonEcosystem._ensure_environment",
                return_value=Path(sys.executable),
            ), patch(
                "ecosystems.python.subprocess.run",
                return_value=CompletedProcess([], 0, tree, ""),
            ):
                locality = ecosystem.resolve_locality(Path(directory), "urllib3")
            self.assertTrue(locality.is_transitive)
            self.assertEqual(locality.depth, 2)
            self.assertEqual(locality.introduced_by, "requests")


class NpmEcosystemTests(unittest.TestCase):
    def test_semver_prerelease_is_lower_than_release(self):
        self.assertLess(compare_npm_versions("2.0.0-rc.1", "2.0.0"), 0)
        self.assertLess(compare_npm_versions("2.0.0-beta.1", "2.0.0-rc.1"), 0)

    def test_locality_parser_handles_nested_dependency(self):
        output = json.dumps({
            "dependencies": {
                "direct": {
                    "version": "1.0.0",
                    "dependencies": {"vulnerable": {"version": "1.0.0"}},
                }
            }
        })
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text('{"dependencies":{"direct":"1.0.0"}}', encoding="utf-8")
            with patch(
                "ecosystems.npm.subprocess.run",
                return_value=CompletedProcess([], 0, output, ""),
            ):
                locality = NpmEcosystem().resolve_locality(repo, "vulnerable")
            self.assertTrue(locality.is_transitive)
            self.assertEqual(locality.introduced_by, "direct")

    def test_package_manager_prefers_pnpm_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text("{}", encoding="utf-8")
            (repo / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
            manager, command = NpmEcosystem._package_manager(repo)
            self.assertEqual(manager, "pnpm")
            self.assertEqual(command[:2], ["pnpm", "install"])

    def test_successful_parent_upgrade_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            package_json = repo / "package.json"
            package_json.write_text(
                '{"dependencies":{"parent":"1.0.0"}}',
                encoding="utf-8",
            )
            ecosystem = NpmEcosystem()
            with patch(
                "ecosystems.npm._fetch_newer_parent_versions",
                return_value=["2.0.0"],
            ), patch.object(
                ecosystem,
                "_run_install",
                return_value=CompletedProcess([], 0, "", ""),
            ), patch.object(
                ecosystem,
                "resolve_locality",
                return_value=type("Locality", (), {
                    "found": True,
                    "resolved_version": "3.0.0",
                })(),
            ), patch.object(ecosystem, "verify_build", return_value=(True, "")), patch.object(
                ecosystem, "verify_tests", return_value=(True, "")
            ):
                result = ecosystem.try_parent_dependency_upgrade(repo, "child", "2.0.0", "parent")
            self.assertEqual(result, ("1.0.0", "2.0.0", "3.0.0"))
            self.assertIn('"parent": "2.0.0"', package_json.read_text(encoding="utf-8"))


class MavenEcosystemTests(unittest.TestCase):
    def test_deep_dependency_uses_direct_ancestor(self):
        output = (
            "[INFO] +- org.example:direct:jar:1.0:compile\n"
            "[INFO] |  +- org.example:middle:jar:1.0:compile\n"
            "[INFO] |  |  \\- org.example:vulnerable:jar:1.0:compile\n"
        )
        locality = _parse_tree(output, "org.example", "vulnerable")
        self.assertEqual(locality.depth, 3)
        self.assertEqual(locality.introduced_by, "org.example:direct")

    def test_maven_qualifier_order(self):
        self.assertLess(_compare_versions("2.0.0-RC1", "2.0.0"), 0)
        self.assertLess(_compare_versions("2.0.0", "2.0.1"), 0)
        self.assertGreater(_compare_versions("2.0.0", "2.0.0-beta1"), 0)

    def test_successful_parent_upgrade_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            pom = repo / "pom.xml"
            pom.write_text(
                "<project><dependencies><dependency>"
                "<groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>1.0.0</version></dependency></dependencies></project>",
                encoding="utf-8",
            )
            ecosystem = MavenEcosystem()
            with patch(
                "ecosystems.maven._fetch_newer_parent_versions",
                return_value=["2.0.0"],
            ), patch.object(
                ecosystem,
                "resolve_locality",
                return_value=type("Locality", (), {
                    "found": True,
                    "resolved_version": "3.0.0",
                })(),
            ), patch.object(ecosystem, "verify_build", return_value=(True, "")), patch.object(
                ecosystem, "verify_tests", return_value=(True, "")
            ):
                result = ecosystem.try_parent_dependency_upgrade(
                    repo, "org.example:child", "2.0.0", "org.example:parent"
                )
            self.assertEqual(result, ("1.0.0", "2.0.0", "3.0.0"))
            self.assertIn("<version>2.0.0</version>", pom.read_text(encoding="utf-8"))


class ScannerTests(unittest.TestCase):
    def test_pypi_purl(self):
        self.assertEqual(
            ScanReportClient._parse_purl("pkg:pypi/urllib3@2.5.0"),
            ("urllib3", "2.5.0"),
        )


if __name__ == "__main__":
    unittest.main()
