"""Async username probe across the WhatsMyName target list.

Detection combines first-hop/final HTTP status with the WhatsMyName content
markers (exists_marker / miss_marker) to cut false positives from soft-404
pages that return a 200 status. Deterministic bot-blocks (403) are reported
as a distinct `blocked` verdict.
"""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

from app import config
from app.osint.targets import Target

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    DETECTED = "detected"
    NOT_FOUND = "not_found"
    BLOCKED = "blocked"
    UNREACHABLE = "unreachable"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ProbeResult:
    target: Target
    requested_url: str
    observed_status_code: int | None
    verdict: Verdict
    exists_marker_matched: bool
    miss_marker_matched: bool
    verdict_reason: str | None = None

    @property
    def detected(self) -> bool:
        return self.verdict is Verdict.DETECTED

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCKED

    @property
    def unreachable(self) -> bool:
        return self.verdict is Verdict.UNREACHABLE

    @property
    def inconclusive(self) -> bool:
        return self.verdict is Verdict.INCONCLUSIVE


def _build_url(target: Target, username: str) -> str:
    return target.probe_url_template.replace("{account}", username).replace("{}", username)


def classify_response(
    first_hop_status: int | None,
    final_status: int | None,
    observed_body: str | None,
    target: Target,
    require_exists_marker: bool = config.REQUIRE_EXISTS_MARKER,
) -> tuple[Verdict, bool, bool, str | None]:
    """Classify a probe response using statuses + content markers.

    A status matches `exists_status_code` if either the first hop or the
    final response matches (redirect-aware). Returns
    (verdict, exists_marker_matched, miss_marker_matched, reason).
    """
    body = observed_body or ""
    exists_marker_matched = bool(target.exists_marker) and target.exists_marker in body
    miss_marker_matched = bool(target.miss_marker) and target.miss_marker in body

    def _result(verdict: Verdict, reason: str | None = None):
        return verdict, exists_marker_matched, miss_marker_matched, reason

    if first_hop_status is None:
        return _result(Verdict.INCONCLUSIVE, "request_error")
    if target.is_protected:
        return _result(Verdict.INCONCLUSIVE, "protected")
    if miss_marker_matched:
        return _result(Verdict.NOT_FOUND, "miss_marker")

    exists_status_match = (
        first_hop_status == target.exists_status_code
        or final_status == target.exists_status_code
    )
    miss_status_match = (
        target.miss_status_code is not None
        and (
            first_hop_status == target.miss_status_code
            or final_status == target.miss_status_code
        )
    )

    if miss_status_match and not exists_status_match:
        return _result(Verdict.NOT_FOUND, "miss_status")
    marker_missing = (
        exists_status_match
        and require_exists_marker
        and target.exists_marker
        and not exists_marker_matched
    )
    if marker_missing:
        return _result(Verdict.INCONCLUSIVE, "exists_marker_absent")
    if exists_status_match:
        return _result(Verdict.DETECTED)
    if final_status in (404, 410) and target.exists_status_code not in (404, 410):
        return _result(Verdict.NOT_FOUND, "not_found_status")
    if first_hop_status in (403,) or final_status in (403,):
        return _result(Verdict.BLOCKED, "bot_blocked")
    return _result(Verdict.INCONCLUSIVE, "unexpected_status")


async def _probe_one(
    client: AsyncSession, target: Target, username: str
) -> ProbeResult:
    url = _build_url(target, username)
    last_error: Exception | None = None

    for attempt in range(1 + config.DEFAULT_PROBE_RETRIES):
        try:
            response = await client.get(
                url,
                headers=target.request_headers or None,
                impersonate="chrome124",
                allow_redirects=True,
            )
            final_status = response.status_code
            first_hop_status = (
                response.history[0].status_code if response.history else final_status
            )

            if (
                attempt < config.DEFAULT_PROBE_RETRIES
                and final_status in config.PROBE_RETRY_STATUS_CODES
            ):
                await asyncio.sleep(config.PROBE_RETRY_DELAY)
                continue

            verdict, exists_matched, miss_matched, reason = classify_response(
                first_hop_status, final_status, response.text, target
            )
            return ProbeResult(
                target=target,
                requested_url=url,
                observed_status_code=first_hop_status,
                verdict=verdict,
                exists_marker_matched=exists_matched,
                miss_marker_matched=miss_matched,
                verdict_reason=reason,
            )
        except RequestsError as exc:
            last_error = exc
            logger.debug("probe failed for %s: %s", target.platform_name, exc)
            if attempt < config.DEFAULT_PROBE_RETRIES:
                await asyncio.sleep(config.PROBE_RETRY_DELAY)

    return ProbeResult(
        target=target,
        requested_url=url,
        observed_status_code=None,
        verdict=Verdict.UNREACHABLE,
        exists_marker_matched=False,
        miss_marker_matched=False,
        verdict_reason=f"request_error: {last_error!r}",
    )


async def check_username(
    username: str,
    targets: list[Target],
    concurrency: int = config.DEFAULT_CONCURRENCY,
    timeout: float = config.DEFAULT_TIMEOUT,
) -> list[ProbeResult]:
    """Probe one slug across all targets. Results keep input order."""
    semaphore = asyncio.Semaphore(concurrency)
    host_locks: dict[str, asyncio.Semaphore] = {}

    def host_semaphore(hostname: str) -> asyncio.Semaphore:
        lock = host_locks.get(hostname)
        if lock is None:
            lock = asyncio.Semaphore(config.MAX_PER_HOST_CONCURRENCY)
            host_locks[hostname] = lock
        return lock

    async def limited(target: Target) -> ProbeResult:
        hostname = urlsplit(_build_url(target, username)).netloc
        async with semaphore:
            async with host_semaphore(hostname):
                return await _probe_one(client, target, username)

    async with AsyncSession(
        timeout=timeout,
        headers={"User-Agent": "CiberMe/0.1 (+https://github.com/)"},
    ) as client:
        return await asyncio.gather(*(limited(t) for t in targets))
