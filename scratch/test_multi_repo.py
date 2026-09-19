import unittest
from unittest.mock import MagicMock, patch
import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, "/app/common")

from multi_repo_chain import MultiRepoChainCoordinator, ChainRepoNode
from common.tracking_store import InMemoryTrackingStore
from common.config import normalize_repo_name


class TestMultiRepoChainCoordinator(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryTrackingStore()

    def test_topological_sort_linear_chain(self):
        """
        Repo A (Consumer) -> depends on Repo B (Intermediate) -> depends on Repo C (Root Upstream)
        Expected bottom-up order: [Repo C, Repo B, Repo A]
        """
        coordinator = MultiRepoChainCoordinator(
            repo_chain=["org/repo-a", "org/repo-b", "org/repo-c"],
            github_pat="dummy_pat",
            tracking_store=self.store,
        )

        nodes = {
            "org/repo-a": ChainRepoNode(
                repo_name="org/repo-a",
                github_url="https://github.com/org/repo-a",
                component_name="com.example:repo-a",
                depends_on=["org/repo-b"],
            ),
            "org/repo-b": ChainRepoNode(
                repo_name="org/repo-b",
                github_url="https://github.com/org/repo-b",
                component_name="com.example:repo-b",
                depends_on=["org/repo-c"],
            ),
            "org/repo-c": ChainRepoNode(
                repo_name="org/repo-c",
                github_url="https://github.com/org/repo-c",
                component_name="com.example:repo-c",
                depends_on=[],
            ),
        }

        order = coordinator._topological_sort(nodes)
        self.assertEqual(order, ["org/repo-c", "org/repo-b", "org/repo-a"])

    def test_topological_sort_independent_nodes(self):
        coordinator = MultiRepoChainCoordinator(
            repo_chain=["org/app", "org/lib-1", "org/lib-2"],
            github_pat="dummy_pat",
            tracking_store=self.store,
        )

        nodes = {
            "org/app": ChainRepoNode(repo_name="org/app", github_url="https://github.com/org/app"),
            "org/lib-1": ChainRepoNode(repo_name="org/lib-1", github_url="https://github.com/org/lib-1"),
            "org/lib-2": ChainRepoNode(repo_name="org/lib-2", github_url="https://github.com/org/lib-2"),
        }

        order = coordinator._topological_sort(nodes)
        self.assertEqual(len(order), 3)
        self.assertIn("org/app", order)
        self.assertIn("org/lib-1", order)
        self.assertIn("org/lib-2", order)

    def test_single_repo_chain(self):
        coordinator = MultiRepoChainCoordinator(
            repo_chain=["org/single-repo"],
            github_pat="dummy_pat",
            tracking_store=self.store,
        )
        self.assertEqual(coordinator.resolve_remediation_order(), ["org/single-repo"])

    def test_end_to_end_chain_resolution_with_manifests(self):
        """
        Creates 3 temporary git/maven repos on disk:
        Root (com.example:root-lib:1.0.0)
        Intermediate (com.example:mid-lib:1.0.0) -> depends on com.example:root-lib
        Consumer (com.example:consumer-app:1.0.0) -> depends on com.example:mid-lib
        Verifies that resolve_remediation_order() automatically detects dependencies and orders bottom-up.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            root_dir = temp_path / "root-lib"
            mid_dir = temp_path / "mid-lib"
            consumer_dir = temp_path / "consumer-app"

            for d in (root_dir, mid_dir, consumer_dir):
                d.mkdir()

            (root_dir / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>root-lib</artifactId>
  <version>1.0.0</version>
</project>""")

            (mid_dir / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>mid-lib</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>root-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>""")

            (consumer_dir / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>consumer-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>mid-lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>""")

            coordinator = MultiRepoChainCoordinator(
                repo_chain=[str(consumer_dir), str(mid_dir), str(root_dir)],
                github_pat="dummy_pat",
                tracking_store=self.store,
            )

            # Mock RepoOps.clone to simply point to our temp directories
            def fake_clone(source, pat):
                pass

            with patch("multi_repo_chain.RepoOps") as mock_repo_ops:
                instance = MagicMock()
                mock_repo_ops.return_value.__enter__.return_value = instance

                def fake_enter():
                    return instance
                mock_repo_ops.return_value.__enter__.side_effect = fake_enter

                def side_effect_clone(source_path, pat):
                    instance._local_path = str(source_path)
                instance.clone.side_effect = side_effect_clone

                order = coordinator.resolve_remediation_order()
                self.assertEqual(order, [str(root_dir), str(mid_dir), str(consumer_dir)])

    def test_npm_chain_resolution_with_manifests(self):
        """
        Creates 2 temporary npm repos on disk:
        Package A (consumer) -> depends on Package B (upstream)
        Verifies that resolve_remediation_order() orders them [Package B, Package A].
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            pkg_b = temp_path / "pkg-b"
            pkg_a = temp_path / "pkg-a"

            pkg_b.mkdir()
            pkg_a.mkdir()

            (pkg_b / "package.json").write_text('{"name": "@myorg/pkg-b", "version": "1.0.0"}')
            (pkg_a / "package.json").write_text('{"name": "@myorg/pkg-a", "version": "1.0.0", "dependencies": {"@myorg/pkg-b": "^1.0.0"}}')

            coordinator = MultiRepoChainCoordinator(
                repo_chain=[str(pkg_a), str(pkg_b)],
                github_pat="dummy_pat",
                tracking_store=self.store,
            )

            with patch("multi_repo_chain.RepoOps") as mock_repo_ops:
                instance = MagicMock()
                mock_repo_ops.return_value.__enter__.return_value = instance

                def side_effect_clone(source_path, pat):
                    instance._local_path = str(source_path)
                instance.clone.side_effect = side_effect_clone

                order = coordinator.resolve_remediation_order()
                self.assertEqual(order, [str(pkg_b), str(pkg_a)])


if __name__ == "__main__":
    unittest.main()
