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

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CONFIG_JSON_CANDIDATES = [
    _REPO_ROOT / "data" / "config.json",
    Path("data/config.json"),
    Path("./data/config.json"),
]
if os.name != "nt" and Path("/data").exists():
    CONFIG_JSON_CANDIDATES.insert(0, Path("/data/config.json"))

ENV_FILE_CANDIDATES = [
    _REPO_ROOT / "config" / ".env",
    Path("config/.env"),
    Path("./config/.env"),
    Path("../config/.env"),
    Path("../../config/.env"),
]
if os.name != "nt" and Path("/config").exists():
    ENV_FILE_CANDIDATES.insert(0, Path("/config/.env"))

UPLOAD_DIR_CANDIDATES = [
    _REPO_ROOT / "data" / "uploads",
    Path("data/uploads"),
    Path("./data/uploads"),
]
if os.name != "nt" and Path("/data").exists():
    UPLOAD_DIR_CANDIDATES.insert(0, Path("/data/uploads"))

DOWNLOAD_DIR_CANDIDATES = [
    _REPO_ROOT / "data" / "downloads",
    Path("data/downloads"),
    Path("./data/downloads"),
]
if os.name != "nt" and Path("/data").exists():
    DOWNLOAD_DIR_CANDIDATES.insert(0, Path("/data/downloads"))



def get_upload_dir() -> Path:
    """Returns the writable directory for uploaded repository zip files / directories."""
    for p in UPLOAD_DIR_CANDIDATES:
        try:
            if p.exists() or p.parent.exists():
                p.mkdir(parents=True, exist_ok=True)
                return p
        except Exception:
            pass
    default_dir = Path("./data/uploads")
    default_dir.mkdir(parents=True, exist_ok=True)
    return default_dir


def get_download_dir() -> Path:
    """Returns the writable directory for generated remediated zip files / archives."""
    for p in DOWNLOAD_DIR_CANDIDATES:
        try:
            if p.exists() or p.parent.exists():
                p.mkdir(parents=True, exist_ok=True)
                return p
        except Exception:
            pass
    default_dir = Path("./data/downloads")
    default_dir.mkdir(parents=True, exist_ok=True)
    return default_dir


def resolve_repo_source(repo_name: str) -> Tuple[str, bool]:
    """
    Resolves repository name to either a local filesystem directory or remote GitHub clone URL.
    Returns: (source_path_or_url, is_local)
    """
    if not repo_name:
        return "", False

    # 1. Direct local path or directory
    p = Path(repo_name)
    if p.is_dir():
        return str(p.resolve()), True

    # 2. Uploaded zip directory in data/uploads
    for upload_base in [get_upload_dir(), Path("/data/uploads"), Path("data/uploads"), Path("./data/uploads")]:
        try:
            cand = upload_base / repo_name
            if cand.is_dir():
                return str(cand.resolve()), True
            # Also check if repository name is in short form (e.g. org/repo-a -> repo-a)
            if "/" in repo_name:
                short_name = repo_name.split("/")[-1]
                short_cand = upload_base / short_name
                if short_cand.is_dir():
                    return str(short_cand.resolve()), True
        except Exception:
            pass

    # 3. Remote URL
    if repo_name.startswith("https://") or repo_name.startswith("http://") or repo_name.startswith("git@"):
        return repo_name, False

    return f"https://github.com/{repo_name}.git", False


def normalize_repo_name(repo_input: str) -> str:
    """
    Extracts 'owner/repo' or clean repo name from URLs, SSH strings, zip files, or raw strings.
    Examples:
      - 'https://github.com/org/repo-a' -> 'org/repo-a'
      - 'https://github.com/org/repo-a.git' -> 'org/repo-a'
      - 'repo-a.zip' -> 'repo-a'
      - 'repo-a' -> 'repo-a'
    """
    if not repo_input:
        return ""
    r = repo_input.strip()
    if r.endswith(".zip"):
        r = r[:-4]
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
    """Returns the primary target repo (first in chain if multiple are configured)."""
    # 1. Shared data volume
    for p in CONFIG_JSON_CANDIDATES:
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("repo_chain") and isinstance(data["repo_chain"], list) and data["repo_chain"]:
                    return normalize_repo_name(data["repo_chain"][0])
                if data.get("repo"):
                    raw = str(data["repo"]).strip()
                    if "," in raw or "\n" in raw:
                        first = re.split(r"[,;\n]+", raw)[0]
                        return normalize_repo_name(first)
                    return normalize_repo_name(raw)
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
                            if "," in val or "\n" in val:
                                first = re.split(r"[,;\n]+", val)[0]
                                return normalize_repo_name(first)
                            return normalize_repo_name(val)
        except Exception:
            pass

    # 3. os.environ fallback
    raw_env = os.environ.get("GITHUB_REPO_TARGET", "")
    if "," in raw_env or "\n" in raw_env:
        first = re.split(r"[,;\n]+", raw_env)[0]
        return normalize_repo_name(first)
    return normalize_repo_name(raw_env)


def get_target_repos() -> list:
    """
    Returns the ordered list of target repositories in the dependency chain.
    If multiple repos are configured (e.g. Repo A -> Repo B -> Repo C),
    returns [repo_a, repo_b, repo_c].
    """
    # 1. Shared data volume (config.json)
    for p in CONFIG_JSON_CANDIDATES:
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("repo_chain") and isinstance(data["repo_chain"], list):
                    res = [normalize_repo_name(r) for r in data["repo_chain"] if normalize_repo_name(r)]
                    if res:
                        return res
                if data.get("repos") and isinstance(data["repos"], list):
                    res = [normalize_repo_name(r) for r in data["repos"] if normalize_repo_name(r)]
                    if res:
                        return res
                if data.get("repo"):
                    raw = str(data["repo"]).strip()
                    if "," in raw or "\n" in raw:
                        res = [normalize_repo_name(r) for r in re.split(r"[,;\n]+", raw) if normalize_repo_name(r)]
                        if res:
                            return res
                    norm = normalize_repo_name(raw)
                    if norm:
                        return [norm]
        except Exception:
            pass

    # 2. config/.env
    for p in ENV_FILE_CANDIDATES:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("GITHUB_REPO_CHAIN="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            res = [normalize_repo_name(r) for r in re.split(r"[,;\n]+", val) if normalize_repo_name(r)]
                            if res:
                                return res
        except Exception:
            pass

    # 3. os.environ
    env_chain = (
        os.environ.get("GITHUB_REPO_CHAIN")
        or os.environ.get("DEPENDENCY_CHAIN_REPOS")
        or os.environ.get("GITHUB_REPO_TARGET")
    )
    if env_chain and ("," in env_chain or "\n" in env_chain or ";" in env_chain):
        res = [normalize_repo_name(r) for r in re.split(r"[,;\n]+", env_chain) if normalize_repo_name(r)]
        if res:
            return res
    elif os.environ.get("GITHUB_REPO_CHAIN") or os.environ.get("DEPENDENCY_CHAIN_REPOS"):
        val = os.environ.get("GITHUB_REPO_CHAIN") or os.environ.get("DEPENDENCY_CHAIN_REPOS")
        res = [normalize_repo_name(r) for r in re.split(r"[,;\n]+", val) if normalize_repo_name(r)]
        if res:
            return res

    single = get_target_repo()
    return [single] if single else []


def get_raw_github_pat() -> str:
    """Returns static GITHUB_PAT from config.json, config/.env, or os.environ."""
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


def get_github_pat(repo: Optional[str] = None) -> str:
    """
    Returns active GitHub token.
    If a GitHub App is configured, dynamically derives and refreshes an installation
    token for the given repository (or active target repo).
    Otherwise, returns the static GITHUB_PAT.
    """
    try:
        from common.github_auth import is_github_app_configured, get_installation_access_token
        if is_github_app_configured():
            target_repo = normalize_repo_name(repo) if repo else get_target_repo()
            if target_repo and "/" in target_repo:
                try:
                    return get_installation_access_token(target_repo)
                except Exception as exc:
                    logger.warning("GitHub App token resolution failed for %s: %s; falling back to PAT", target_repo, exc)
    except Exception:
        pass

    return get_raw_github_pat()


def get_github_token(repo: Optional[str] = None) -> str:
    """Explicit alias for get_github_pat(repo)."""
    return get_github_pat(repo=repo)


def get_watcher_sleep_seconds() -> int:
    """Returns the watcher sleep interval in seconds, reading from config/.env first."""
    for p in ENV_FILE_CANDIDATES:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("WATCHER_SLEEP_SECONDS="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val.isdigit():
                            return int(val)
        except Exception:
            pass
    return int(os.environ.get("WATCHER_SLEEP_SECONDS", "60"))



def save_config(repo: str, pat: Optional[str] = None, repo_chain: Optional[list] = None) -> Tuple[str, str]:
    """
    Saves repo and pat to data/config.json, updates config/.env, and updates os.environ.
    Supports single repo and repository chains (e.g. Repo A -> Repo B -> Repo C).
    Returns (clean_repo, clean_pat).
    """
    chain = []
    if repo_chain:
        chain = [normalize_repo_name(r) for r in repo_chain if normalize_repo_name(r)]
    elif repo and ("," in repo or "\n" in repo):
        chain = [normalize_repo_name(r) for r in re.split(r"[,;\n]+", repo) if normalize_repo_name(r)]

    clean_repo = chain[0] if chain else normalize_repo_name(repo)
    clean_pat = pat.strip() if pat and pat.strip() else get_raw_github_pat()

    payload = {"repo": clean_repo, "pat": clean_pat}
    if chain:
        payload["repo_chain"] = chain

    # 1. Save to data/config.json (mounted across containers)
    for p in CONFIG_JSON_CANDIDATES:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
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

                if chain:
                    chain_val = ",".join(chain)
                    if re.search(r"^GITHUB_REPO_CHAIN=.*$", content, flags=re.MULTILINE):
                        content = re.sub(r"^GITHUB_REPO_CHAIN=.*$", f"GITHUB_REPO_CHAIN={chain_val}", content, flags=re.MULTILINE)
                    else:
                        content += f"\nGITHUB_REPO_CHAIN={chain_val}"

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
    if chain:
        os.environ["GITHUB_REPO_CHAIN"] = ",".join(chain)
    if clean_pat:
        os.environ["GITHUB_PAT"] = clean_pat

    logger.info("Configuration updated: repo=%s chain=%s", clean_repo, chain)
    return clean_repo, clean_pat
