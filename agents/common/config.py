"""
Shared Configuration Module for OSS Remediation Agent.

Provides dynamic, process-wide and container-wide access to active target repository
and GitHub Personal Access Token (PAT).

Configuration Sources (in priority order):
1. /data/config.json or ./data/config.json (shared via bind-mount volume across all containers)
2. /config/.env or config/.env
3. Environment variables (GITHUB_REPO_TARGET, GITHUB_PAT)
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

CONFIG_JSON_CANDIDATES = [
    Path("/data/config.json"),
    Path("data/config.json"),
    Path("./data/config.json"),
]

ENV_FILE_CANDIDATES = [
    Path("/config/.env"),
    Path("config/.env"),
    Path("./config/.env"),
    Path("../config/.env"),
    Path("../../config/.env"),
]


def normalize_repo_name(repo_input: str) -> str:
    """
    Extracts 'owner/repo' from URLs, SSH strings, or raw strings.
    Examples:
      - 'https://github.com/Neurealm-Gaurav/Test_repo_1' -> 'Neurealm-Gaurav/Test_repo_1'
      - 'https://github.com/Neurealm-Gaurav/Test_repo_1.git' -> 'Neurealm-Gaurav/Test_repo_1'
      - 'git@github.com:Neurealm-Gaurav/Test_repo_1.git' -> 'Neurealm-Gaurav/Test_repo_1'
      - 'Neurealm-Gaurav/Test_repo_1' -> 'Neurealm-Gaurav/Test_repo_1'
    """
    if not repo_input:
        return ""
    r = repo_input.strip()
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if r.startswith(prefix):
            r = r[len(prefix):]
            break
    if "github.com/" in r:
        r = r.split("github.com/")[-1]
    if r.endswith(".git"):
        r = r[:-4]
    return r.strip("/")


def get_target_repo() -> str:
    """Returns active GITHUB_REPO_TARGET."""
    # 1. Shared data volume
    for p in CONFIG_JSON_CANDIDATES:
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("repo"):
                    return normalize_repo_name(data["repo"])
        except Exception:
            pass

    # 2. config/.env
    for p in ENV_FILE_CANDIDATES:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("GITHUB_REPO_TARGET="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return normalize_repo_name(val)
        except Exception:
            pass

    # 3. os.environ fallback
    return normalize_repo_name(os.environ.get("GITHUB_REPO_TARGET", ""))


def get_github_pat() -> str:
    """Returns active GITHUB_PAT."""
    # 1. Shared data volume
    for p in CONFIG_JSON_CANDIDATES:
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("pat"):
                    return data["pat"].strip()
        except Exception:
            pass

    # 2. config/.env
    for p in ENV_FILE_CANDIDATES:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("GITHUB_PAT="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass

    # 3. os.environ fallback
    return os.environ.get("GITHUB_PAT", "").strip()


def save_config(repo: str, pat: Optional[str] = None) -> Tuple[str, str]:
    """
    Saves repo and pat to data/config.json, updates config/.env, and updates os.environ.
    Returns (clean_repo, clean_pat).
    """
    clean_repo = normalize_repo_name(repo)
    clean_pat = pat.strip() if pat and pat.strip() else get_github_pat()

    # 1. Save to data/config.json (mounted across containers)
    for p in CONFIG_JSON_CANDIDATES:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"repo": clean_repo, "pat": clean_pat}, indent=2), encoding="utf-8")
            break
        except Exception as exc:
            logger.warning("Could not write config to %s: %s", p, exc)

    # 2. Update config/.env if found
    for p in ENV_FILE_CANDIDATES:
        try:
            if p.exists():
                content = p.read_text(encoding="utf-8")
                if re.search(r"^GITHUB_REPO_TARGET=.*$", content, flags=re.MULTILINE):
                    content = re.sub(r"^GITHUB_REPO_TARGET=.*$", f"GITHUB_REPO_TARGET={clean_repo}", content, flags=re.MULTILINE)
                else:
                    content += f"\nGITHUB_REPO_TARGET={clean_repo}"

                if clean_pat:
                    if re.search(r"^GITHUB_PAT=.*$", content, flags=re.MULTILINE):
                        content = re.sub(r"^GITHUB_PAT=.*$", f"GITHUB_PAT={clean_pat}", content, flags=re.MULTILINE)
                    else:
                        content += f"\nGITHUB_PAT={clean_pat}"
                p.write_text(content, encoding="utf-8")
                break
        except Exception as exc:
            logger.warning("Could not update %s: %s", p, exc)

    # 3. In-memory update
    os.environ["GITHUB_REPO_TARGET"] = clean_repo
    if clean_pat:
        os.environ["GITHUB_PAT"] = clean_pat

    logger.info("Configuration updated: repo=%s", clean_repo)
    return clean_repo, clean_pat
