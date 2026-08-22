"""Official platform API checkers for high-confidence username detection.

These bypass HTTP probing entirely and hit the platform's own REST API,
giving zero false positives and richer data (bios, creation dates, etc.).
"""

import asyncio
import logging
from dataclasses import dataclass

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

logger = logging.getLogger(__name__)


@dataclass
class OfficialApiResult:
    """Result from an official API check."""
    platform: str
    username: str
    exists: bool
    profile_url: str | None = None
    display_name: str | None = None
    bio: str | None = None
    created_at: str | None = None
    followers: int | None = None
    extra: dict | None = None


async def check_github(
    client: AsyncSession, username: str
) -> OfficialApiResult:
    """Check username via GitHub REST API (no auth required).

    GET /users/{username} → 200 (exists) or 404 (not found).
    Returns rich profile data on success.
    """
    url = f"https://api.github.com/users/{username}"
    try:
        resp = await client.get(
            url,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "CyberMe/0.1",
            },
            impersonate="chrome124",
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return OfficialApiResult(
                platform="GitHub",
                username=username,
                exists=True,
                profile_url=data.get("html_url"),
                display_name=data.get("name"),
                bio=data.get("bio"),
                created_at=data.get("created_at"),
                followers=data.get("followers"),
                extra={
                    "public_repos": data.get("public_repos"),
                    "blog": data.get("blog"),
                    "location": data.get("location"),
                    "email": data.get("email"),
                    "company": data.get("company"),
                },
            )
        return OfficialApiResult(
            platform="GitHub", username=username, exists=False
        )
    except RequestsError as exc:
        logger.debug("GitHub API error for %s: %s", username, exc)
        return OfficialApiResult(
            platform="GitHub", username=username, exists=False
        )


async def check_reddit(
    client: AsyncSession, username: str
) -> OfficialApiResult:
    """Check username via Reddit's public JSON endpoint (no auth required).

    GET /user/{username}/about.json → 200 (exists) or 404 (not found).
    """
    url = f"https://www.reddit.com/user/{username}/about.json"
    try:
        resp = await client.get(
            url,
            headers={
                "User-Agent": "CyberMe/0.1 (+https://github.com/)",
            },
            impersonate="chrome124",
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return OfficialApiResult(
                platform="Reddit",
                username=username,
                exists=True,
                profile_url=f"https://www.reddit.com/user/{username}",
                display_name=data.get("subreddit", {}).get("title"),
                bio=data.get("subreddit", {}).get("public_description"),
                created_at=data.get("created_utc"),
                followers=data.get("followers"),
                extra={
                    "link_karma": data.get("link_karma"),
                    "comment_karma": data.get("comment_karma"),
                    "total_karma": data.get("total_karma"),
                    "verified": data.get("verified"),
                    "has_verified_email": data.get("has_verified_email"),
                    "is_gold": data.get("is_gold"),
                    "icon_img": data.get("icon_img"),
                },
            )
        return OfficialApiResult(
            platform="Reddit", username=username, exists=False
        )
    except RequestsError as exc:
        logger.debug("Reddit API error for %s: %s", username, exc)
        return OfficialApiResult(
            platform="Reddit", username=username, exists=False
        )


async def check_gitlab(
    client: AsyncSession, username: str
) -> OfficialApiResult:
    """Check username via GitLab API (no auth required for public profiles).

    GET /users?username={username} → list (non-empty = exists).
    """
    url = f"https://gitlab.com/api/v4/users?username={username}"
    try:
        resp = await client.get(
            url,
            headers={"User-Agent": "CyberMe/0.1"},
            impersonate="chrome124",
            timeout=10.0,
        )
        if resp.status_code == 200:
            users = resp.json()
            if users:
                u = users[0]
                return OfficialApiResult(
                    platform="GitLab",
                    username=username,
                    exists=True,
                    profile_url=u.get("web_url"),
                    display_name=u.get("name"),
                    bio=u.get("bio"),
                    created_at=u.get("created_at"),
                    followers=u.get("followers"),
                    extra={
                        "public_repos": u.get("projects_count"),
                        "location": u.get("location"),
                        "website": u.get("website_url"),
                    },
                )
        return OfficialApiResult(
            platform="GitLab", username=username, exists=False
        )
    except RequestsError as exc:
        logger.debug("GitLab API error for %s: %s", username, exc)
        return OfficialApiResult(
            platform="GitLab", username=username, exists=False
        )


# Registry of all official API checkers
OFFICIAL_API_CHECKERS = {
    "GitHub": check_github,
    "Reddit": check_reddit,
    "GitLab": check_gitlab,
}


async def run_official_api_checks(
    username: str,
) -> dict[str, OfficialApiResult]:
    """Run all official API checks concurrently.

    Returns dict keyed by platform name.
    """
    async with AsyncSession(impersonate="chrome124") as client:
        tasks = {
            name: checker(client, username)
            for name, checker in OFFICIAL_API_CHECKERS.items()
        }
        results = {}
        for name, coro in tasks.items():
            results[name] = await coro
        return results
