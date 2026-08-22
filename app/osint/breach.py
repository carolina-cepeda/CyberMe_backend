"""HIBP Pwned Passwords breach checker using k-anonymity.

The password never leaves the device in plaintext. We only send the
first 5 characters of its SHA-1 hash to the API and check if the
remaining suffix appears in the response.
"""

import hashlib
import logging
from dataclasses import dataclass

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import RequestsError

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"


@dataclass
class BreachCheckResult:
    """Result of a Pwned Passwords check."""
    breached: bool
    count: int  # How many times this password appeared in breaches
    prefix: str
    suffix: str
    error: bool = False  # True when HIBP API was unreachable or returned an error


async def check_password_breach(
    client: AsyncSession,
    password: str,
) -> BreachCheckResult:
    """Check if a password has been seen in known data breaches.

    Uses the Pwned Passwords k-anonymity API:
    1. SHA-1 hash the password
    2. Send only the first 5 hex chars (prefix) to the API
    3. Compare our suffix against the returned list

    The actual password (or even its full hash) never leaves the client.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # NOSONAR – HIBP k-anonymity requires SHA-1
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = _HIBP_URL.format(prefix=prefix)
    try:
        resp = await client.get(
            url,
            headers={"User-Agent": "CiberMe/0.1"},
            impersonate="chrome124",
            timeout=10.0,
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    return BreachCheckResult(
                        breached=True,
                        count=int(parts[1]),
                        prefix=prefix,
                        suffix=suffix,
                    )
            return BreachCheckResult(
                breached=False, count=0, prefix=prefix, suffix=suffix
            )
        logging.warning("HIBP API returned status %d", resp.status_code)
        return BreachCheckResult(
            breached=False, count=0, prefix=prefix, suffix=suffix, error=True
        )
    except RequestsError as exc:
        logging.exception("HIBP API error")
        return BreachCheckResult(
            breached=False, count=0, prefix=prefix, suffix=suffix, error=True
        )
