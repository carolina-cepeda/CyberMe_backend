"""WhatsMyName + Maigret combined target list."""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app import config

logger = logging.getLogger(__name__)

CORE_CATEGORIES = {
    "social",
    "tech",
    "coding",
    "business",
    "news",
    "blog",
    "video",
    "political",
}


@dataclass
class Target:
    platform_name: str
    probe_url_template: str
    exists_status_code: int
    exists_marker: str
    miss_status_code: int | None
    miss_marker: str
    category: str
    is_core: bool
    protection: tuple[str, ...] = field(default_factory=tuple)
    known_accounts: list[str] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_protected(self) -> bool:
        return bool(self.protection)


def _parse_target(site: dict[str, Any]) -> Target | None:
    template = site.get("uri_check")
    platform_name = site.get("name")
    exists_status = site.get("e_code", site.get("valid_status"))
    if (
        not isinstance(template, str)
        or "{account}" not in template
        or not isinstance(platform_name, str)
        or not isinstance(exists_status, int)
    ):
        return None

    category = (site.get("cat") or site.get("category") or "general").strip().lower()
    return Target(
        platform_name=platform_name,
        probe_url_template=template,
        exists_status_code=exists_status,
        exists_marker=site.get("e_string") or "",
        miss_status_code=site.get("m_code"),
        miss_marker=site.get("m_string") or "",
        category=category,
        is_core=category in CORE_CATEGORIES,
        protection=tuple(site.get("protection") or []),
        known_accounts=list(site.get("known") or []),
        request_headers=dict(site.get("request_headers") or {}),
    )


def _load_cached() -> list[dict[str, Any]] | None:
    path = config.TARGETS_CACHE
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > config.TARGETS_MAX_AGE_SECONDS:
        return None
    with path.open() as fh:
        return json.load(fh).get("sites", [])


def _save_cache(sites: list[dict[str, Any]]) -> None:
    with config.TARGETS_CACHE.open("w") as fh:
        json.dump({"sites": sites}, fh)


async def fetch_targets(
    force: bool = False, include_protected: bool | None = None
) -> list[Target]:
    if include_protected is None:
        include_protected = not config.SKIP_PROTECTED_SITES

    sites = None if force else _load_cached()
    if sites is None:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(config.DEFAULT_TARGETS_URL)
            resp.raise_for_status()
            payload = resp.json()
            sites = payload.get("sites", [])
            _save_cache(sites)

    targets: list[Target] = []
    for site in sites:
        target = _parse_target(site)
        if target is None:
            continue
        if target.is_protected and not include_protected:
            continue
        targets.append(target)
    return targets


async def fetch_all_targets(
    force: bool = False,
    include_protected: bool | None = None,
    include_maigret: bool = True,
    maigret_max: int = 200,
) -> list[Target]:
    """Fetch and merge targets from WhatsMyName + Maigret.

    WhatsMyName targets are loaded first (higher priority). Maigret targets
    fill gaps — sites not already covered by WhatsMyName.
    """
    wmn_targets = await fetch_targets(force=force, include_protected=include_protected)
    all_targets = list(wmn_targets)

    if include_maigret:
        try:
            from app.osint.maigret_adapter import load_maigret_targets

            wmn_names = {t.platform_name for t in wmn_targets}
            maigret_targets = load_maigret_targets(
                existing_names=wmn_names, max_sites=maigret_max
            )
            all_targets.extend(maigret_targets)
            logger.info(
                "Target merge: %d WhatsMyName + %d Maigret = %d total",
                len(wmn_targets),
                len(maigret_targets),
                len(all_targets),
            )
        except Exception as exc:
            logger.warning("Failed to load Maigret targets: %s", exc)

    return all_targets
