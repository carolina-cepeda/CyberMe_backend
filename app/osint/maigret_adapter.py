"""Adapter to convert Maigret site database entries into our Target format.

Maigret ships 3200+ sites with its own detection model. This module converts
the relevant subset into our Target dataclass so they can be probed by our
existing checker (with curl_cffi TLS impersonation).
"""

import json
import logging
from pathlib import Path

from app.osint.targets import Target

logger = logging.getLogger(__name__)

# Path to Maigret's bundled data.json
_MAIGRET_DATA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / ".venv"
    / "lib"
    / "python3.12"
    / "site-packages"
    / "maigret"
    / "resources"
    / "data.json"
)

# Tag → category mapping (Maigret tags to our category names)
_TAG_TO_CATEGORY = {
    "social": "social",
    "tech": "tech",
    "coding": "coding",
    "business": "business",
    "news": "news",
    "blog": "blog",
    "video": "video",
    "gaming": "gaming",
    "music": "music",
    "photo": "photo",
    "forum": "forum",
    "discussion": "forum",
    "education": "education",
    "shopping": "shopping",
    "finance": "finance",
    "travel": "travel",
    "sport": "sport",
    "health": "health",
    "dating": "dating",
    "politics": "political",
    "messaging": "messaging",
    "streaming": "streaming",
    "networking": "social",
    "creative": "creative",
    "crypto": "crypto",
    "dev": "coding",
    "military": "government",
    "government": "government",
    "wiki": "wiki",
    "research": "research",
    "writing": "blog",
    "apps": "tech",
    "sharing": "social",
    "ru": "regional",
    "cn": "regional",
    "de": "regional",
    "jp": "regional",
    "br": "regional",
    "tr": "regional",
    "iran": "regional",
    "language": "regional",
}


def _pick_category(tags: list[str]) -> str:
    """Map Maigret tags to a single category string."""
    for tag in tags:
        if tag in _TAG_TO_CATEGORY:
            return _TAG_TO_CATEGORY[tag]
    return "general"


def _convert_site(name: str, site: dict) -> Target | None:
    """Convert a single Maigret site dict to our Target dataclass."""
    # Determine probe URL
    probe_url = site.get("urlProbe") or site.get("url") or ""
    if not probe_url or "{username}" not in probe_url:
        return None

    # Convert placeholder: Maigret uses {username}, we use {account}
    probe_url = probe_url.replace("{username}", "{account}")

    # Detection markers
    presense = site.get("presenseStrs") or []
    absence = site.get("absenceStrs") or []
    exists_marker = presense[0] if presense else ""
    miss_marker = absence[0] if absence else ""

    # Skip sites without any presence marker — our classifier needs it
    # to distinguish real profiles from soft-404s (200-for-everything pages).
    if not exists_marker:
        return None

    # Determine status codes based on checkType
    check_type = site.get("checkType", "message")
    if check_type == "status_code":
        exists_status_code = 200
        miss_status_code = None
    else:
        # message, response_url, none → rely on content markers
        exists_status_code = 200
        miss_status_code = None

    # Category from tags
    tags = site.get("tags") or []
    category = _pick_category(tags)

    # Custom headers
    headers = site.get("headers") or {}

    # Protection: Maigret doesn't have this field, but some sites need login
    protection = ()
    if not probe_url:
        protection = ("login_walled",)

    return Target(
        platform_name=name,
        probe_url_template=probe_url,
        exists_status_code=exists_status_code,
        exists_marker=exists_marker,
        miss_status_code=miss_status_code,
        miss_marker=miss_marker,
        category=category,
        is_core=category in {
            "social", "tech", "coding", "business",
            "news", "blog", "video", "political",
        },
        protection=protection,
        known_accounts=[],
        request_headers=headers,
    )


def load_maigret_targets(
    existing_names: set[str] | None = None,
    max_sites: int = 500,
) -> list[Target]:
    """Load Maigret sites and convert to our Target format.

    Args:
        existing_names: Set of platform names already loaded from WhatsMyName.
            Duplicates are skipped to avoid probing the same site twice.
        max_sites: Maximum number of Maigret sites to return (sorted by
            Alexa rank when available).

    Returns:
        List of Target objects ready for our checker.
    """
    if not _MAIGRET_DATA_PATH.exists():
        logger.warning("Maigret data.json not found at %s", _MAIGRET_DATA_PATH)
        return []

    with _MAIGRET_DATA_PATH.open() as fh:
        data = json.load(fh)

    sites = data.get("sites", {})
    existing_names = existing_names or set()

    # Filter to sites that have a probeable URL
    candidates = []
    for name, site_data in sites.items():
        if name in existing_names:
            continue
        probe_url = site_data.get("urlProbe") or site_data.get("url") or ""
        if "{username}" not in probe_url:
            continue
        target = _convert_site(name, site_data)
        if target is not None:
            candidates.append(target)

    # Sort by alexaRank (lower = more popular) and take top N
    def _alexa_rank(t: Target) -> int:
        # Extract alexaRank from original data
        original = sites.get(t.platform_name, {})
        return original.get("alexaRank", 999999)

    candidates.sort(key=_alexa_rank)
    result = candidates[:max_sites]

    logger.info(
        "Loaded %d Maigret targets (skipped %d already in WhatsMyName)",
        len(result),
        len(existing_names),
    )
    return result
