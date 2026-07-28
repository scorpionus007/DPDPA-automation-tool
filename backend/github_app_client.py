"""GitHub App authentication and installation API helpers."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
from dotenv import load_dotenv
from jose import jwt as jose_jwt

_load_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
load_dotenv(_load_env)

GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "").strip()
GITHUB_APP_PRIVATE_KEY = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()
GITHUB_APP_SLUG = os.environ.get("GITHUB_APP_SLUG", "dpdp-compliance-scanner").strip()
GITHUB_API = "https://api.github.com"


def _normalize_private_key(key: str) -> str:
    if not key:
        return ""
    if "BEGIN" in key and "\\n" in key:
        return key.replace("\\n", "\n")
    return key


def is_github_app_configured() -> bool:
    return bool(GITHUB_APP_ID and _normalize_private_key(GITHUB_APP_PRIVATE_KEY))


def create_app_jwt(ttl_seconds: int = 540) -> str:
    """Create a short-lived JWT for GitHub App authentication."""
    if not is_github_app_configured():
        raise RuntimeError(
            "GitHub App not configured. Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY in .env"
        )
    private_key = _normalize_private_key(GITHUB_APP_PRIVATE_KEY)
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + ttl_seconds,
        "iss": GITHUB_APP_ID,
    }
    return jose_jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(installation_id: str | int) -> str:
    """Exchange app JWT for an installation access token."""
    app_jwt = create_app_jwt()
    url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        resp.raise_for_status()
        return resp.json()["token"]


async def get_installation(installation_id: str | int) -> dict[str, Any]:
    app_jwt = create_app_jwt()
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GITHUB_API}/app/installations/{installation_id}",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def list_installation_repos(
    installation_id: str | int,
    per_page: int = 100,
) -> list[dict[str, Any]]:
    """List all repositories accessible to this installation (paginated)."""
    token = await get_installation_token(installation_id)
    repos: list[dict[str, Any]] = []
    page = 1
    async with httpx.AsyncClient() as client:
        while True:
            resp = await client.get(
                f"{GITHUB_API}/installation/repositories",
                params={"per_page": per_page, "page": page},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("repositories") or []
            repos.extend(batch)
            total_count = data.get("total_count", len(repos))
            if len(repos) >= total_count or not batch:
                break
            page += 1
    return repos


def app_install_url(state: str) -> str:
    return f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new?state={state}"
