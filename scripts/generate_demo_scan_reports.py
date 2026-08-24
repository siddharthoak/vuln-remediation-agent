"""
Generates synthetic trivy-report.json / grype-report.json for demo purposes --
no real scan, no GitHub Actions run needed. Produces the exact minimal shape
agents/fixer/scan_report_client.py's _parse_trivy/_parse_grype expect.

Curated (not random) so a single run of this pipeline demonstrates all three
classifier outcomes a viewer would actually want to see:

  1. log4j-core      2.14.1 -> 2.17.1   bucket 2 (patch/minor, direct automated fix)
  2. commons-collections 3.2.1 -> 4.4    bucket 3 (major bump, real KB playbook
                                          match -- playbooks/commons-collections-3to4.yaml
                                          matches on from_major=3/to_major=4 only,
                                          not exact version strings)
  3. struts2-core     2.3.30 -> 6.3.0.4  bucket 4 (major bump to a complex
                                          framework, no KB entry -> human triage,
                                          not automated -- shows the system knows
                                          when NOT to act)

All three components/versions are real entries in vulnerable-java-app's actual
pom.xml (confirmed against the live repo), so this is a realistic finding set
for that target repo, not arbitrary data.

Usage:
    python3 scripts/generate_demo_scan_reports.py [output_dir]
    (defaults to ./scan-reports, matching SCAN_REPORT_PATH's default)
"""

import json
import sys
from pathlib import Path

DEMO_FINDINGS = [
    {
        "cve": "CVE-2021-44228",
        "group": "org.apache.logging.log4j",
        "artifact": "log4j-core",
        "current": "2.14.1",
        "fixed": "2.17.1",
        "severity": "CRITICAL",
    },
    {
        "cve": "CVE-2015-6420",
        "group": "commons-collections",
        "artifact": "commons-collections",
        "current": "3.2.1",
        "fixed": "4.4",
        "severity": "HIGH",
    },
    {
        "cve": "CVE-2017-5638",
        "group": "org.apache.struts",
        "artifact": "struts2-core",
        "current": "2.3.30",
        "fixed": "6.3.0.4",
        "severity": "CRITICAL",
    },
]


def build_trivy_report() -> dict:
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f["cve"],
                        "PkgName": f["artifact"],
                        "PkgIdentifier": {"PURL": f"pkg:maven/{f['group']}/{f['artifact']}@{f['current']}"},
                        "InstalledVersion": f["current"],
                        "FixedVersion": f["fixed"],
                        "Severity": f["severity"],
                    }
                    for f in DEMO_FINDINGS
                ]
            }
        ]
    }


def build_grype_report() -> dict:
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": f["cve"],
                    "severity": f["severity"].capitalize(),
                    "fix": {"versions": [f["fixed"]], "state": "fixed"},
                },
                "artifact": {
                    "name": f["artifact"],
                    "version": f["current"],
                    "type": "java-archive",
                    "purl": f"pkg:maven/{f['group']}/{f['artifact']}@{f['current']}",
                },
            }
            for f in DEMO_FINDINGS
        ]
    }


def write_demo_reports(out_dir: Path) -> list:
    """Writes trivy-report.json/grype-report.json into out_dir and returns
    the list of CVE ids written -- factored out of main() so fixer-server's
    POST /scan/demo handler can call this directly (no subprocess, no CLI
    round-trip) instead of only being reachable from the command line.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    trivy_path = out_dir / "trivy-report.json"
    grype_path = out_dir / "grype-report.json"

    trivy_path.write_text(json.dumps(build_trivy_report(), indent=2), encoding="utf-8")
    grype_path.write_text(json.dumps(build_grype_report(), indent=2), encoding="utf-8")

    return [f["cve"] for f in DEMO_FINDINGS]


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("scan-reports")
    cves = write_demo_reports(out_dir)
    print(f"Wrote {out_dir / 'trivy-report.json'} and {out_dir / 'grype-report.json'}")
    print(f"{len(cves)} findings: {', '.join(cves)}")


if __name__ == "__main__":
    main()
