"""
agents/common/github_auth.py — Production GitHub App and Dynamic Token Authentication

Provides dynamic, per-repository GitHub token resolution using a GitHub App.
Tokens are short-lived (1 hour), scoped to the specific repository/installation,
and automatically cached and refreshed.

Falls back to static GITHUB_PAT if GitHub App credentials are not provided.
"""

from __future__ import annotations

import os
import re
import time
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# Cache: repo_full_name -> (token, expire_epoch_timestamp)
_INSTALLATION_TOKEN_CACHE: Dict[str, Tuple[str, float]] = {}

# Candidate paths for GitHub App Private Key PEM file
PRIVATE_KEY_CANDIDATES = [
    Path("config/github-app.pem"),
    Path("/config/github-app.pem"),
    Path("./config/github-app.pem"),
    Path("../config/github-app.pem"),
    Path("../../config/github-app.pem"),
    Path("config/app-private-key.pem"),
    Path("/config/app-private-key.pem"),
    Path("config/github-app-private-key.pem"),
]


def get_github_app_id() -> Optional[str]:
    """Returns GITHUB_APP_ID from environment or config."""
    app_id = os.environ.get("GITHUB_APP_ID", "").strip()
    if app_id:
        return app_id

    # Check config/.env files
    env_paths = [
        Path("config/.env"),
        Path("/config/.env"),
        Path("./config/.env"),
        Path("../config/.env"),
        Path("../../config/.env"),
    ]
    for p in env_paths:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("GITHUB_APP_ID="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass
    return None


def get_github_app_private_key() -> Optional[str]:
    """
    Retrieves GitHub App Private Key PEM string.
    Checks GITHUB_APP_PRIVATE_KEY env var, GITHUB_APP_PRIVATE_KEY_PATH env var,
    or candidate PEM files in config/.
    """
    # 1. Direct environment variable (PEM string)
    env_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()
    if env_key:
        if "\\n" in env_key and "\n" not in env_key:
            env_key = env_key.replace("\\n", "\n")
        return env_key

    # 2. Path specified in environment variable
    key_path_env = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if key_path_env:
        p = Path(key_path_env)
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8").strip()
            except Exception as exc:
                logger.error("Failed to read private key from %s: %s", p, exc)

    # 3. Known candidate locations
    for p in PRIVATE_KEY_CANDIDATES:
        try:
            if p.is_file():
                content = p.read_text(encoding="utf-8").strip()
                if "BEGIN" in content and "PRIVATE KEY" in content:
                    return content
        except Exception:
            pass

    return None


def is_github_app_configured() -> bool:
    """Returns True if GitHub App ID and Private Key are both available."""
    return bool(get_github_app_id() and get_github_app_private_key())


def generate_app_jwt(app_id: str, private_key_pem: str) -> str:
    """
    Generates an RS256 JWT valid for 9 minutes for GitHub App authentication.
    Tries PyJWT first, then PyGithub Auth.
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,       # 1 minute leeway for clock skew
        "exp": now + (9 * 60), # 9 minutes validity (GitHub maximum is 10)
        "iss": str(app_id),
    }

    # Attempt PyJWT
    try:
        import jwt
        token = jwt.encode(payload, private_key_pem, algorithm="RS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token
    except ImportError:
        pass

    # Attempt PyGithub internal Auth
    try:
        from github import Auth
        app_auth = Auth.AppAuth(app_id=int(app_id), private_key=private_key_pem)
        return app_auth.token
    except Exception:
        pass

    raise RuntimeError(
        "Cannot generate JWT: neither 'pyjwt[crypto]' nor 'PyGithub>=2.0' is available. "
        "Please ensure PyJWT and cryptography are installed."
    )


def get_installation_access_token(repo_full_name: str) -> str:
    """
    Mints or retrieves a cached installation access token for a given repository.
    Tokens are short-lived (1 hour) and cached for up to 50 minutes.
    """
    from common.config import normalize_repo_name

    clean_repo = normalize_repo_name(repo_full_name)
    if not clean_repo or "/" not in clean_repo:
        raise ValueError(f"Invalid repository full name '{repo_full_name}'. Expected 'owner/repo'.")

    # Check active token cache
    now = time.time()
    cached = _INSTALLATION_TOKEN_CACHE.get(clean_repo)
    if cached:
        token, expires_at = cached
        if (expires_at - now) > 300:
            return token

    app_id = get_github_app_id()
    private_key = get_github_app_private_key()
    if not app_id or not private_key:
        raise RuntimeError("GitHub App is not configured. Missing GITHUB_APP_ID or private key.")

    owner, repo_name = clean_repo.split("/", 1)

    # ── Attempt via PyGithub if available ─────────────────────────────────────
    try:
        from github import Auth, GithubIntegration
        try:
            auth = Auth.AppAuth(app_id=int(app_id), private_key=private_key)
            gi = GithubIntegration(auth=auth)
        except Exception:
            gi = GithubIntegration(int(app_id), private_key)

        installation = gi.get_repo_installation(owner, repo_name)
        access_token_obj = gi.get_access_token(installation.id)
        token_str = access_token_obj.token
        expires_at = (
            access_token_obj.expires_at.timestamp()
            if hasattr(access_token_obj, "expires_at") and access_token_obj.expires_at
            else (now + 3000)
        )

        _INSTALLATION_TOKEN_CACHE[clean_repo] = (token_str, expires_at)
        logger.info("Retrieved and cached GitHub App installation token for %s via PyGithub", clean_repo)
        return token_str
    except Exception as pygh_err:
        logger.debug("PyGithub installation token fetch failed (%s); trying direct REST API...", pygh_err)

    # ── Direct REST API fallback ──────────────────────────────────────────────
    app_jwt = generate_app_jwt(app_id, private_key)
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vuln-remediation-agent",
    }

    # Step 1: Find Installation ID for repo
    find_url = f"https://api.github.com/repos/{clean_repo}/installation"
    req = urllib.request.Request(find_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installation_id = data.get("id")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            org_url = f"https://api.github.com/orgs/{owner}/installation"
            try:
                org_req = urllib.request.Request(org_url, headers=headers)
                with urllib.request.urlopen(org_req, timeout=10) as org_resp:
                    data = json.loads(org_resp.read().decode("utf-8"))
                    installation_id = data.get("id")
            except Exception:
                raise RuntimeError(
                    f"GitHub App (ID {app_id}) is not installed on repository '{clean_repo}' "
                    f"or organization '{owner}'. Please install the App on the repository."
                ) from exc
        else:
            raise RuntimeError(
                f"Failed to lookup GitHub App installation for {clean_repo}: HTTP {exc.code} {exc.reason}"
            ) from exc

    # Step 2: Request Installation Access Token
    token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    token_req = urllib.request.Request(token_url, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(token_req, timeout=10) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
            token = token_data["token"]
            _INSTALLATION_TOKEN_CACHE[clean_repo] = (token, now + 3000)
            logger.info("Retrieved and cached GitHub App installation token for %s via REST API", clean_repo)
            return token
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Failed to mint installation token for {clean_repo}: HTTP {exc.code} - {err_body}") from exc


def get_github_token(repo: Optional[str] = None) -> str:
    """
    Top-level token accessor.
    If GitHub App is configured: dynamically mints/retrieves installation token for `repo`.
    If GitHub App is not configured or repo is local: falls back to static GITHUB_PAT.
    """
    from common.config import get_target_repo, get_github_pat, normalize_repo_name

    target = normalize_repo_name(repo) if repo else get_target_repo()

    if is_github_app_configured() and target and "/" in target:
        try:
            return get_installation_access_token(target)
        except Exception as exc:
            logger.warning(
                "GitHub App token resolution failed for '%s': %s. Falling back to GITHUB_PAT.",
                target, exc
            )

    return get_github_pat()


def get_auth_mode() -> dict:
    """Returns current active authentication mode and status details for observability."""
    from common.config import get_github_pat

    app_id = get_github_app_id()
    has_key = bool(get_github_app_private_key())
    app_configured = bool(app_id and has_key)
    pat = get_github_pat()

    if app_configured:
        return {
            "mode": "github_app",
            "label": "GitHub App",
            "app_id": app_id,
            "configured": True,
            "description": f"GitHub App (App ID: {app_id}) — dynamically mints per-repository tokens.",
        }
    elif pat:
        masked = pat[:4] + "*" * max(0, len(pat) - 8) + pat[-4:] if len(pat) > 8 else "****"
        return {
            "mode": "pat",
            "label": "Personal Access Token (PAT)",
            "app_id": None,
            "configured": True,
            "masked_pat": masked,
            "description": "Static GITHUB_PAT configured (legacy).",
        }
    else:
        return {
            "mode": "none",
            "label": "Unauthenticated",
            "app_id": None,
            "configured": False,
            "description": "No GitHub credentials configured.",
        }
