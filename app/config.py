from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
DB_PATH = BASE_DIR / "ciberme.db"

DEFAULT_TARGETS_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
TARGETS_CACHE = BASE_DIR / "wmn-data.json"
TARGETS_MAX_AGE_SECONDS = 86400

DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 12.0

SKIP_PROTECTED_SITES = True
REQUIRE_EXISTS_MARKER = True
DEFAULT_PROBE_RETRIES = 1
PROBE_RETRY_DELAY = 1.0

MAX_NAME_FALLBACK_VARIANTS = 1


def load_env() -> None:
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        import os

        os.environ.setdefault(key.strip(), value.strip())


def get_setting(key: str, default: str = "") -> str:
    import os

    return os.environ.get(key, default)
