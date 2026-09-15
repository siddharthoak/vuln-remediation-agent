"""
Scan report client — parses OWASP Dependency-Check, Trivy, and Grype JSON reports
into VulnerabilityFinding objects.

Replaces nexus_client.py from nexus-remediation-agent. The NexusIQClient is no
longer used; the vulnerability source is the GitHub Actions scan artifact produced
by security-scan.yml in the target repository.

The output VulnerabilityFinding dataclass is identical to the one in nexus_client.py,
so fixer/main.py requires only an import-name change.
"""

import json
import logging
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ScanReportError(Exception):
    """Raised when no readable report files are found at the configured path."""


@dataclass
class VulnerabilityFinding:
    component_name: str
    current_version: str
    recommended_version: str
    severity: str               # critical | high | medium | low
    cve_ids: list = field(default_factory=list)

    # Populated by dependency_tree.resolve_locality() in main.py before
    # classification, not by any scanner -- scanners report against the
    # resolved graph and don't distinguish direct from transitive.
    is_transitive: bool = False
    introduced_by: Optional[str] = None      # "groupId:artifactId" of the direct-dep ancestor
    transitive_depth: Optional[int] = None   # 1 = direct, 2+ = transitive (see dependency_tree.py)


class ScanReportClient:
    """
    Reads vulnerability findings from scanner JSON reports on the local filesystem.

    Report path is configured via SCAN_REPORT_PATH env var (directory containing
    one or more of: trivy-report.json, grype-report.json, dependency-check-report.json).

    When multiple reports are present, findings are merged and deduplicated by
    (component_name, current_version). The recommended_version is taken from the
    first scanner that provides a fix version (Trivy > Grype > OWASP).
    """

    TRIVY_FILE    = "trivy-report.json"
    GRYPE_FILE    = "grype-report.json"
    # The workflow artifact preserves the directory structure, so the OWASP
    # report lands at <report_dir>/dependency-check-report/dependency-check-report.json
    OWASP_FILE    = "dependency-check-report/dependency-check-report.json"

    def __init__(self, report_dir: Optional[str] = None):
        self._report_dir = Path(report_dir or os.environ["SCAN_REPORT_PATH"])

    # ── Public API ────────────────────────────────────────────────────────────

    def get_vulnerability_report(self, _app_id: str = "") -> list:
        """
        Return a list of VulnerabilityFinding objects merged from all available reports.

        `_app_id` is accepted for API compatibility with the NexusIQClient interface
        but is unused — the report path is fixed at construction time.
        """
        findings: dict = {}  # (component_name, current_version) → VulnerabilityFinding

        trivy_files = list(self._report_dir.rglob(self.TRIVY_FILE))
        grype_files = list(self._report_dir.rglob(self.GRYPE_FILE))
        owasp_files = list(self._report_dir.rglob("dependency-check-report.json"))

        for trivy_path in trivy_files:
            for f in self._parse_trivy(trivy_path):
                key = (f.component_name, f.current_version)
                findings.setdefault(key, f)

        for grype_path in grype_files:
            for f in self._parse_grype(grype_path):
                key = (f.component_name, f.current_version)
                existing = findings.get(key)
                if existing:
                    for cve in f.cve_ids:
                        if cve not in existing.cve_ids:
                            existing.cve_ids.append(cve)
                    existing.severity = self._highest_severity([existing.severity, f.severity])
                    if not f.recommended_version.startswith("UNKNOWN"):
                        if existing.recommended_version.startswith("UNKNOWN") or \
                           self._parse_version_tuple(f.recommended_version) > self._parse_version_tuple(existing.recommended_version):
                            existing.recommended_version = f.recommended_version
                else:
                    findings[key] = f

        for owasp_path in owasp_files:
            for f in self._parse_owasp(owasp_path):
                key = (f.component_name, f.current_version)
                findings.setdefault(key, f)

        if not findings:
            raise ScanReportError(
                f"No readable report files found in {self._report_dir}. "
                f"Expected one or more of: {self.TRIVY_FILE}, {self.GRYPE_FILE}, {self.OWASP_FILE}."
            )

        result = list(findings.values())
        logger.info("Loaded %d unique findings from %s", len(result), self._report_dir)
        return result

    # ── Trivy parser ──────────────────────────────────────────────────────────

    def _parse_trivy(self, path: Path) -> list:
        """
        Trivy JSON format:
          { "Results": [ { "Vulnerabilities": [ {
              "VulnerabilityID": "CVE-...",
              "PkgName": "log4j-core",
              "PkgIdentifier": {"PURL": "pkg:maven/..."},
              "InstalledVersion": "2.14.1",
              "FixedVersion": "2.20.0",
              "Severity": "CRITICAL"
          } ] } ] }
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not parse Trivy report: %s", exc)
            return []

        findings: dict = {}
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                cve_id    = vuln.get("VulnerabilityID", "")
                severity  = vuln.get("Severity", "UNKNOWN").lower()
                installed = vuln.get("InstalledVersion", "unknown")
                fixed_ver_raw = vuln.get("FixedVersion", "")
                fixed_ver = self._select_best_fixed_version(fixed_ver_raw, installed)

                # Resolve component name from PURL or PkgName
                purl = (vuln.get("PkgIdentifier") or {}).get("PURL", "")
                name = self._name_from_purl(purl) or vuln.get("PkgName", "unknown")

                key = (name, installed)
                if key not in findings:
                    findings[key] = VulnerabilityFinding(
                        component_name=name,
                        current_version=installed,
                        recommended_version=fixed_ver or "UNKNOWN — check Trivy FixedVersion",
                        severity=severity,
                        cve_ids=[cve_id] if cve_id else [],
                    )
                else:
                    if cve_id and cve_id not in findings[key].cve_ids:
                        findings[key].cve_ids.append(cve_id)
                    findings[key].severity = self._highest_severity([findings[key].severity, severity])
                    if fixed_ver and not fixed_ver.startswith("UNKNOWN"):
                        cur_rec = findings[key].recommended_version
                        if cur_rec.startswith("UNKNOWN") or self._parse_version_tuple(fixed_ver) > self._parse_version_tuple(cur_rec):
                            findings[key].recommended_version = fixed_ver

        return list(findings.values())

    # ── Grype parser ──────────────────────────────────────────────────────────

    def _parse_grype(self, path: Path) -> list:
        """
        Grype JSON format:
          { "matches": [ {
              "vulnerability": {
                  "id": "CVE-...",
                  "severity": "Critical",
                  "fix": { "versions": ["2.20.0"], "state": "fixed" }
              },
              "artifact": {
                  "name": "log4j-core",
                  "version": "2.14.1",
                  "type": "java-archive",
                  "purl": "pkg:maven/..."
              }
          } ] }
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not parse Grype report: %s", exc)
            return []

        findings: dict = {}
        for match in data.get("matches", []):
            vuln     = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cve_id    = vuln.get("id", "")
            severity  = vuln.get("severity", "UNKNOWN").lower()
            purl      = artifact.get("purl", "")
            name      = self._name_from_purl(purl) or artifact.get("name", "unknown")
            installed = artifact.get("version", "unknown")

            fix_info  = vuln.get("fix", {})
            fix_vers  = fix_info.get("versions", [])
            fixed_ver_raw = ", ".join(fix_vers) if fix_vers else ""
            fixed_ver = self._select_best_fixed_version(fixed_ver_raw, installed) if fixed_ver_raw else "UNKNOWN — check Grype fix.versions"

            key = (name, installed)
            if key not in findings:
                findings[key] = VulnerabilityFinding(
                    component_name=name,
                    current_version=installed,
                    recommended_version=fixed_ver,
                    severity=severity,
                    cve_ids=[cve_id] if cve_id else [],
                )
            else:
                if cve_id and cve_id not in findings[key].cve_ids:
                    findings[key].cve_ids.append(cve_id)
                findings[key].severity = self._highest_severity([findings[key].severity, severity])
                if fixed_ver and not fixed_ver.startswith("UNKNOWN"):
                    cur_rec = findings[key].recommended_version
                    if cur_rec.startswith("UNKNOWN") or self._parse_version_tuple(fixed_ver) > self._parse_version_tuple(cur_rec):
                        findings[key].recommended_version = fixed_ver

        return list(findings.values())

    # ── OWASP Dependency-Check parser ─────────────────────────────────────────

    def _parse_owasp(self, path: Path) -> list:
        """
        OWASP DC JSON format:
          { "dependencies": [ {
              "packages": [{"id": "pkg:maven/...@version"}],
              "vulnerabilities": [{
                  "name": "CVE-...",
                  "severity": "CRITICAL",
                  "cvssv3": {"baseScore": 10.0}
              }]
          } ] }
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not parse OWASP report: %s", exc)
            return []

        findings: dict = {}
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulnerabilities", [])
            if not vulns:
                continue

            packages = dep.get("packages", [])
            purl = packages[0].get("id", "") if packages else ""
            name, installed = self._parse_purl(purl)

            severity = self._highest_severity(
                [v.get("severity", "low") for v in vulns]
            )
            cve_ids = [v["name"] for v in vulns if v.get("name", "").startswith("CVE")]

            key = (name, installed)
            if key not in findings:
                findings[key] = VulnerabilityFinding(
                    component_name=name,
                    current_version=installed,
                    recommended_version="UNKNOWN — check NVD or scanner for safe version",
                    severity=severity,
                    cve_ids=cve_ids,
                )

        return list(findings.values())

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_version_tuple(v: str) -> tuple:
        if not v or v.startswith("UNKNOWN"):
            return (-1,)
        clean = v.strip().lstrip("v")
        for suffix in [".RELEASE", "-RELEASE", ".Final", "-Final", ".GA", "-GA", ".jre", "-jre", ".android", "-android"]:
            if clean.endswith(suffix):
                clean = clean[:-len(suffix)]
        clean = clean.split("-")[0]
        parts = []
        for p in clean.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts) if parts else (0,)

    @classmethod
    def _select_best_fixed_version(cls, fixed_ver_str: str, installed_ver: str) -> str:
        if not fixed_ver_str or fixed_ver_str.startswith("UNKNOWN"):
            return fixed_ver_str
        candidates = [v.strip() for v in fixed_ver_str.split(",") if v.strip()]
        if not candidates:
            return fixed_ver_str
        if len(candidates) == 1:
            return candidates[0]

        inst_tuple = cls._parse_version_tuple(installed_ver)
        # Filter to candidates that are upgrades (>= installed_ver)
        upgrades = [c for c in candidates if cls._parse_version_tuple(c) >= inst_tuple]
        valid_candidates = upgrades if upgrades else candidates

        inst_parts = installed_ver.strip().lstrip("v").split(".")
        # 1. Match same major and minor version if possible
        for cand in valid_candidates:
            cand_parts = cand.strip().lstrip("v").split(".")
            if len(inst_parts) >= 2 and len(cand_parts) >= 2 and inst_parts[0] == cand_parts[0] and inst_parts[1] == cand_parts[1]:
                return cand
        # 2. Match same major version (smallest upgrade on that major)
        same_major = []
        for cand in valid_candidates:
            cand_parts = cand.strip().lstrip("v").split(".")
            if len(inst_parts) >= 1 and len(cand_parts) >= 1 and inst_parts[0] == cand_parts[0]:
                same_major.append(cand)
        if same_major:
            same_major.sort(key=cls._parse_version_tuple)
            return same_major[0]

        valid_candidates.sort(key=cls._parse_version_tuple)
        return valid_candidates[0]



    @staticmethod
    def _name_from_purl(purl: str) -> str:
        """
        Extract package name from a Maven, npm, or PyPI package URL.
        pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
        → org.apache.logging.log4j:log4j-core

        pkg:npm/lodash@4.17.20
        → lodash

        pkg:npm/%40angular/core@12.0.0
        → @angular/core

        pkg:pypi/django@4.2.0
        → django
        """
        if not purl:
            return ""

        if purl.startswith("pkg:maven/"):
            try:
                after_type = purl[len("pkg:maven/"):]
                name_part = after_type.split("@")[0]
                return name_part.replace("/", ":")
            except (IndexError, ValueError):
                return ""

        if purl.startswith("pkg:npm/"):
            try:
                after_type = purl[len("pkg:npm/"):]
                if after_type.startswith("@"):
                    name_part = "@" + after_type[1:].split("@")[0]
                else:
                    name_part = after_type.split("@")[0]
                name_part = name_part.split("?")[0].split("#")[0]
                return urllib.parse.unquote(name_part)
            except (IndexError, ValueError):
                return ""

        if purl.startswith("pkg:pypi/"):
            try:
                after_type = purl[len("pkg:pypi/"):]
                return urllib.parse.unquote(after_type.split("@", 1)[0].split("?", 1)[0].split("#", 1)[0])
            except (IndexError, ValueError):
                return ""

        return ""

    @staticmethod
    def _parse_purl(purl: str):
        """Extract (component_name, version) from a purl."""
        if not purl:
            return "unknown-component", "unknown"
        try:
            if purl.startswith(("pkg:maven/", "pkg:npm/", "pkg:pypi/")):
                name = ScanReportClient._name_from_purl(purl)
                version = purl.rsplit("@", 1)[1].split("?", 1)[0].split("#", 1)[0] if "@" in purl else "unknown"
                return name or "unknown-component", version
            after_type = purl.split("/", 1)[1] if "/" in purl else purl
            name_version = after_type.rsplit("@", 1)
            name = name_version[0].replace("/", ":")
            version = name_version[1] if len(name_version) > 1 else "unknown"
            return name, version
        except (IndexError, ValueError):
            return purl, "unknown"

    @staticmethod
    def _highest_severity(severities: list) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        best = "low"
        for s in severities:
            sev = s.lower()
            if order.get(sev, 0) > order.get(best, 0):
                best = sev
        return best
