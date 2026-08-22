<p align="center">
  <h1 align="center">CyberMe</h1>
  <p align="center">
    <strong>Your digital footprint, your shield. A free OSINT tool that helps anyone measure and improve their online privacy.</strong>
  </p>
</p>

<p align="center">
  <a href="https://sonarcloud.io/summary/new_code?id=carolina-cepeda_CyberMe_backend"><img src="https://sonarcloud.io/api/project_badges/measure?project=carolina-cepeda_CyberMe_backend&metric=alert_status&token=0df78ff41b6929d8b0b0f496e13873b1d5e52550" alt="Quality Gate"></a>&nbsp;
  <a href="https://sonarcloud.io/summary/new_code?id=carolina-cepeda_CyberMe_backend"><img src="https://sonarcloud.io/api/project_badges/measure?project=carolina-cepeda_CyberMe_backend&metric=bugs&token=0df78ff41b6929d8b0b0f496e13873b1d5e52550" alt="Bugs"></a>&nbsp;
  <a href="https://sonarcloud.io/summary/new_code?id=carolina-cepeda_CyberMe_backend"><img src="https://sonarcloud.io/api/project_badges/measure?project=carolina-cepeda_CyberMe_backend&metric=code_smells&token=0df78ff41b6929d8b0b0f496e13873b1d5e52550" alt="Code Smells"></a>&nbsp;
  <a href="https://sonarcloud.io/summary/new_code?id=carolina-cepeda_CyberMe_backend"><img src="https://sonarcloud.io/api/project_badges/measure?project=carolina-cepeda_CyberMe_backend&metric=coverage&token=0df78ff41b6929d8b0b0f496e13873b1d5e52550" alt="Coverage"></a>&nbsp;
  <a href="https://sonarcloud.io/summary/new_code?id=carolina-cepeda_CyberMe_backend"><img src="https://sonarcloud.io/api/project_badges/measure?project=carolina-cepeda_CyberMe_backend&metric=duplicated_lines_density&token=0df78ff41b6929d8b0b0f496e13873b1d5e52550" alt="Duplicated Lines"></a>
</p>

---

## What is CyberMe?

**CyberMe** is an OSINT (Open Source Intelligence) tool built to bring digital security to everyone. You don't need to be a cybersecurity expert: enter a username and CyberMe scans **800+ platforms** to find where that person has registered accounts, checks whether their password has appeared in known data breaches, and calculates a **Privacy Health Score** -- a gamified rating (300-850) that measures how exposed your digital footprint is.

**The mission:** make online privacy understandable and actionable for everyone, regardless of technical skill.

---

## How it works?

```
                    +-----------------------------------+
                    |   User enters a username          |
                    +----------------+------------------+
                                     |
                    +----------------v------------------+
                    |  OSINT Engine (837+ platforms)     |
                    |  * WhatsMyName (600+)              |
                    |  * Maigret (~200 extra)            |
                    |  * Official APIs (GitHub,          |
                    |    Reddit, GitLab)                 |
                    +----------------+------------------+
                                     |
              +----------------------+----------------------+
              |                      |                       |
    +---------v----------+ +--------v--------+ +-----------v-----------+
    | Detected accounts  | | Breach check     | | Score calculator      |
    | (core/secondary)   | | (HIBP k-anon)   | | (300-850 points)      |
    +---------+----------+ +--------+--------+ +-----------+-----------+
              |                      |                       |
              +----------------------+----------------------+
                                     |
                    +----------------v------------------+
                    |     Results + Actions              |
                    |  * View privacy score              |
                    |  * Reclaim points by deleting      |
                    |    accounts (/api/verify)          |
                    +-----------------------------------+
```

### Smart detection

CyberMe doesn't just check if a URL returns 200. It combines **HTTP status codes** with **content markers** (unique strings present when an account exists vs. when it doesn't) to cut false positives from pages that return 200 for everyone:

| Verdict | Meaning |
|---------|---------|
| `detected` | Account found (status + marker match) |
| `not_found` | Account doesn't exist (miss marker or 404) |
| `blocked` | Bot protection (Cloudflare, CAPTCHA) |
| `unreachable` | Network error (DNS, timeout, TLS) |
| `inconclusive` | Could not determine |

### Privacy Health Score

| Factor | Deduction |
|--------|-----------|
| Core account (social, tech, coding) | -30 per account |
| Secondary account (forums, gaming) | -15 per account |
| Password in breaches (HIBP) | -150 |
| Reclamation (account deleted) | +30 or +15 |
| **Base score** | **850** (minimum: 300) |

---

## Project structure

```
backend/
+-- app/
|   +-- main.py              # FastAPI app, CORS, rate limiting
|   +-- config.py            # Configuration and environment variables
|   +-- routers/
|   |   +-- scan.py          # POST /api/scan -- full OSINT scan
|   |   +-- breach.py        # POST /api/breach, GET /api/score, POST /api/verify
|   +-- osint/
|   |   +-- checker.py       # Async probe engine with curl_cffi
|   |   +-- targets.py       # Target fetching (WhatsMyName + Maigret)
|   |   +-- maigret_adapter.py # Maigret -> internal format converter
|   |   +-- official_apis.py # GitHub, Reddit, GitLab (official APIs)
|   |   +-- breach.py        # HIBP Pwned Passwords (k-anonymity)
|   |   +-- score.py         # Privacy Health Score calculator
|   |   +-- slugs.py         # Name variant generation
|   |   +-- control.py       # Temporary FPR diagnostics
|   +-- db/
|       +-- database.py      # SQLite persistence layer
+-- docs/
|   +-- GLOSSARY.md          # Terminology and field mapping
+-- .github/workflows/
|   +-- sonarcloud.yml       # CI: automated quality analysis
+-- sonar-project.properties # SonarCloud configuration
+-- requirements.txt         # Python dependencies
+-- README.md                # This file
```

---

## Database

CyberMe uses **SQLite** stored at `backend/ciberme.db`. The persistence layer (`app/db/database.py`) manages five tables:

```
users ------+-- scans ---------- scan_results
            |
            +-- breaches
            |
            +-- scores
```

| Table | Purpose |
|-------|---------|
| `users` | Scanned users (unique username) |
| `scans` | Scan metadata (status, timestamps) |
| `scan_results` | Per-platform results (verdict, URL, markers) |
| `breaches` | HIBP verification results |
| `scores` | Privacy Health Score history |

Initialization is automatic: on server start, `init_db()` creates tables if they don't exist.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Full OSINT scan of a username |
| `POST` | `/api/breach` | Check password against breaches (HIBP k-anonymity) |
| `GET` | `/api/score/{username}` | Get Privacy Health Score |
| `POST` | `/api/verify` | Re-verify a platform after deleting an account |

### Example: full scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe"}'
```

### Example: breach check

```bash
curl -X POST http://localhost:8000/api/breach \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe", "password": "my_password"}'
```

> **Note:** The password never leaves in plaintext. Only the first 5 characters of its SHA-1 hash are sent to the HIBP API (k-anonymity).

---

## Tech stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI (Python 3.12) |
| Database | SQLite |
| HTTP probing | curl_cffi (Chrome 124 TLS fingerprinting) |
| Site lists | WhatsMyName + Maigret |
| Official APIs | GitHub, Reddit, GitLab |
| Breach check | HIBP Pwned Passwords (k-anonymity) |
| Rate limiting | slowapi |
| CI/CD | GitHub Actions + SonarCloud |

---

## Quick Start

### Requirements
- Python 3.12+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/carolina-cepeda/carolina-cepeda_CyberMe_backend.git
cd carolina-cepeda_CyberMe_backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The server will be available at `http://localhost:8000/docs` (Swagger UI).

### Environment variables (optional)

Create a `.env` file in `backend/`:

```env
# CORS (for the frontend)
CORS_ORIGINS=http://localhost:5173

# Gemini API (phase 4 - privacy tips)
GEMINI_API_KEY=
```

---


<p align="center">
  <strong>Built to make digital security accessible for everyone.</strong>
</p>
