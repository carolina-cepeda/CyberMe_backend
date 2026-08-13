"""Async username probe across the WhatsMyName target list.

Detection combines the first-hop HTTP status with the WhatsMyName content
markers (exists_marker / miss_marker) to cut false positives from soft-404
pages that return a 200 status.
"""

import asyncio
import logging
import secrets
from dataclasses import dataclass
from enum import Enum

import httpx

from app import config
from app.osint.targets import Target

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    DETECTED = "detected"
    NOT_FOUND = "not_found"
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
    def inconclusive(self) -> bool:
        return self.verdict is Verdict.INCONCLUSIVE

    @property
    def is_request_error(self) -> bool:
        return bool(self.verdict_reason and self.verdict_reason.startswith("request_error"))


# TODO(remove): temporary control username for FPR estimation diagnostics.
def generate_control_username() -> str:
    return "cbm_" + secrets.token_hex(8)


def _build_url(target: Target, username: str) -> str:
    return target.probe_url_template.replace("{account}", username).replace("{}", username)


def _first_hop_status_code(response: httpx.Response) -> int:
    if response.history:
        return response.history[0].status_code
    return response.status_code


def classify_response(
    observed_status_code: int | None,
    observed_body: str | None,
    target: Target,
    require_exists_marker: bool = config.REQUIRE_EXISTS_MARKER,
) -> tuple[Verdict, bool, bool, str | None]:
    """Classify a probe response using status + content markers.

    Returns (verdict, exists_marker_matched, miss_marker_matched, reason).
    """
    body = observed_body or ""
    exists_marker_matched = bool(target.exists_marker) and target.exists_marker in body
    miss_marker_matched = bool(target.miss_marker) and target.miss_marker in body

    if observed_status_code is None:
        return Verdict.INCONCLUSIVE, exists_marker_matched, miss_marker_matched, "request_error"
    if target.is_protected:
        return Verdict.INCONCLUSIVE, exists_marker_matched, miss_marker_matched, "protected"
    if miss_marker_matched:
        return Verdict.NOT_FOUND, exists_marker_matched, miss_marker_matched, "miss_marker"
    if (
        target.miss_status_code is not None
        and observed_status_code == target.miss_status_code
    ):
        return Verdict.NOT_FOUND, exists_marker_matched, miss_marker_matched, "miss_status"
    if observed_status_code != target.exists_status_code:
        return Verdict.INCONCLUSIVE, exists_marker_matched, miss_marker_matched, "unexpected_status"
    if require_exists_marker and target.exists_marker and not exists_marker_matched:
        return Verdict.INCONCLUSIVE, exists_marker_matched, miss_marker_matched, "exists_marker_absent"
    return Verdict.DETECTED, exists_marker_matched, miss_marker_matched, None


async def _probe_one(
    client: httpx.AsyncClient, target: Target, username: str
) -> ProbeResult:
    url = _build_url(target, username)
    last_error: Exception | None = None

    for attempt in range(1 + config.DEFAULT_PROBE_RETRIES):
        try:
            response = await client.get(url, headers=target.request_headers or None)
            status_code = _first_hop_status_code(response)
            verdict, exists_matched, miss_matched, reason = classify_response(
                status_code, response.text, target
            )
            return ProbeResult(
                target=target,
                requested_url=url,
                observed_status_code=status_code,
                verdict=verdict,
                exists_marker_matched=exists_matched,
                miss_marker_matched=miss_matched,
                verdict_reason=reason,
            )
        except httpx.HTTPError as exc:
            last_error = exc
            logger.debug("probe failed for %s: %s", target.platform_name, exc)
            if attempt < config.DEFAULT_PROBE_RETRIES:
                await asyncio.sleep(config.PROBE_RETRY_DELAY)

    return ProbeResult(
        target=target,
        requested_url=url,
        observed_status_code=None,
        verdict=Verdict.INCONCLUSIVE,
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

    async def limited(target: Target) -> ProbeResult:
        async with semaphore:
            return await _probe_one(client, target, username)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "CiberMe/0.1 (+https://github.com/)"},
    ) as client:
        return await asyncio.gather(*(limited(t) for t in targets))
