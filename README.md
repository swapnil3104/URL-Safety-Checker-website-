URL Safety Checker (Flask)

This web app evaluates a URL's safety using heuristics and optional external checks (Google Safe Browsing, VirusTotal).

Quick Start (Windows PowerShell)

```powershell
# 1) Create and activate venv
python -m venv .venv
. .venv\Scripts\Activate.ps1

# 2) Install dependencies
pip install -r requirements.txt

# 3) (Optional) Configure API keys
Copy-Item .env.example .env
# Edit .env and set GOOGLE_SAFE_BROWSING_API_KEY / VIRUSTOTAL_API_KEY if you have them

# 4) Run the app
python app.py
# Open http://127.0.0.1:5000
```

Environment Variables

- FLASK_DEBUG (default false)
- HOST (default 127.0.0.1)
- PORT (default 5000)
- ENABLE_EXTERNAL_CHECKS (default true)
- EXTERNAL_REQUEST_TIMEOUT_SECONDS (default 6)
- GOOGLE_SAFE_BROWSING_API_KEY (optional)
- VIRUSTOTAL_API_KEY (optional)

Notes

- Heuristics give a fast estimate; treat results as guidance, not proof.
- With API keys, external providers can flag malicious URLs to raise the risk.
- No URLs are stored; processing is in-memory only.

