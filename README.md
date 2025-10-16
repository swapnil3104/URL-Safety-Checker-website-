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
- No URLs are stored; processing is in-memory only

UI of website 
<img width="1858" height="887" alt="Screenshot 2025-10-16 143430" src="https://github.com/user-attachments/assets/2265d47a-f7b2-48c4-9645-6535c05573ea" />

Output of Website 
<img width="1289" height="870" alt="Screenshot 2025-10-16 143854" src="https://github.com/user-attachments/assets/0d15eb26-bb8b-4591-91d9-f0683ecc9ac6" 

<img width="1318" height="872" alt="Screenshot 2025-10-16 144231" src="https://github.com/user-attachments/assets/18ea3a2b-f850-46c6-b433-c60584546699" />

<img width="1302" height="871" alt="Screenshot 2025-10-16 144424" src="https://github.com/user-attachments/assets/12ff026d-dfa8-4eac-b8a5-b307d55f6e00" />

<img width="1289" height="867" alt="Screenshot 2025-10-16 144806" src="https://github.com/user-attachments/assets/71b1bcd1-8d1a-4530-b576-4103fc2ea80c" />









