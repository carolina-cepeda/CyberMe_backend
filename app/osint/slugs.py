"""Full-name to slug variants for name-based scans.

"John Doe" -> ["johndoe", "john.doe", "john_doe", "john-doe"]
The first entry is the primary slug; the rest are fallback variants.
"""

import re
import unicodedata


def _ascii_fold(name: str) -> str:
    nfkd = unicodedata.normalize("NFKD", name)
    ascii_text = nfkd.encode("ascii", "ignore").decode("ascii")
    ascii_text = re.sub(r"[^a-zA-Z0-9 ]", "", ascii_text)
    return ascii_text.strip().lower()


def build_variants(name: str, max_fallbacks: int | None = None) -> list[str]:
    """Return [primary_slug, *fallback_variants] for a name, URL-safe.

    Single words yield only themselves; multi-word names get separator
    variants ('.', '_', '-') as fallbacks. If max_fallbacks is set, the
    returned list is capped at 1 + max_fallbacks entries.
    """
    folded = _ascii_fold(name)
    words = [w for w in re.split(r"\s+", folded) if w]
    if not words:
        return []

    variants = ["".join(words)]
    if len(words) > 1:
        for separator in (".", "_", "-"):
            variants.append(separator.join(words))

    if max_fallbacks is not None:
        variants = variants[: 1 + max_fallbacks]
    return variants
