# CiberMe Glossary

Maps the raw WhatsMyName JSON field names and the app's variables to the descriptive names used in the code, so every term is self-explanatory.

Short memory aid: **`e` = exists**, **`m` = miss**.

## WhatsMyName source fields → code names

| Raw JSON field | Code name | Meaning |
| :--- | :--- | :--- |
| `name` | `platform_name` | Display name of the website/platform |
| `uri_check` | `probe_url_template` | URL template containing the `{account}` placeholder that gets probed |
| `e_code` | `exists_status_code` | HTTP status returned when the account **EXISTS** |
| `m_code` | `miss_status_code` | HTTP status returned when the account does **NOT** exist |
| `e_string` | `exists_marker` | Unique string found in the page HTML when the account **EXISTS** |
| `m_string` | `miss_marker` | Unique string found when the account does **NOT** exist (the soft-404 page). **`m_string` = "miss string"** |
| `cat` | `category` | Platform category (social, tech, gaming, …) |
| `known` | `known_accounts` | Sample known usernames maintained by the WhatsMyName project |
| `protection` | `protection` | Anti-bot measures (cloudflare, captcha, …); protected sites are skipped |
| `valid_status` (legacy) | `exists_status_code` | Old name for `e_code` |

## Detection verdicts

| Verdict | Meaning |
| :--- | :--- |
| `detected` | Strong positive: status matches `exists_status_code` (first hop OR final, redirect-aware) AND `exists_marker` is present (and `miss_marker` is absent) |
| `not_found` | Status matches `miss_status_code`, or `miss_marker` present (soft-404 page returned a 200), or a `404/410` fallback |
| `blocked` | Deterministic bot-block (persistent `403`), e.g. Cloudflare challenge — account presence unknown |
| `unreachable` | Network-level failure (TLS reset / DNS / timeout), e.g. domains filtered by the local network — account presence unknown |
| `inconclusive` | Cannot decide: unexpected status, `exists_marker` absent, protected site |

## Scan metrics

| Term | Meaning |
| :--- | :--- |
| `probed` | Number of platforms that received a request |
| `matches` | Number of platforms with verdict = `detected` |
| `fpr` / `false_positive_rate` | Share of control-scan probes falsely detected (probed with a random near-nonexistent username) |
| `core` / `secondary` | Account tier used by the scoring engine (−30 / −15 points) |
| `blocked` | Count of platforms that returned a deterministic bot-block (403) |
| `unreachable` | Count of platforms that failed at the network level (TLS reset, DNS, timeout) |
| `slug` | URL-safe normalization of the input (`"John Doe"` → `johndoe`) |
| `variant` | One of several slug forms for the same name (`johndoe`, `john.doe`, `john-doe`) |
| `probe_url_template`→`requested_url` | The `{account}` placeholder replaced by the probed slug |
| `observed_status_code` | First-hop HTTP status of the response (before any redirects) |
| `first-hop status` | Status of the first response in a redirect chain; used for status matching |
| `verdict_reason` | Machine-readable explanation of the verdict (`miss_marker`, `unexpected_status`, `request_error`, …) |
