# AI-Assisted Lab Port Scanner

A lightweight Flask web application that runs a safe TCP scan against an approved lab host and uses Claude AI to explain the results.

> **Lab targets only.** Scanning systems without explicit authorisation is illegal.  
> The only permitted target is `scanme.nmap.org` — the official Nmap test host.

---

## What it does

| Step | Detail |
|------|--------|
| **Scan** | Calls `nmap -sT -sV --top-ports 100 -T4 --open` against the approved host |
| **Parse** | Extracts open ports, protocols, services, and version banners from nmap XML |
| **Analyse** | Sends findings to Claude Haiku, which explains each service and gives an overall assessment |
| **Display** | Renders results in a terminal-style web UI with a copyable raw-JSON panel |

---

## Requirements

- Python 3.11+
- [nmap](https://nmap.org/download.html) installed and on `PATH`
- An Anthropic API key *(optional — AI analysis is skipped without one)*

---

## How to run

```bash
# 1. Clone
git clone https://github.com/<you>/lab-scanner.git
cd lab-scanner

# 2. Create a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment (optional for AI analysis)
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 5. Run
python app.py
```

Open **http://localhost:5000** in your browser.  
Select the approved target, click **SCAN**, and wait ~15-30 s for results.

---

## Project structure

```
lab-scanner/
├── app.py               # Flask backend + nmap runner + Claude integration
├── templates/
│   └── index.html       # Terminal-style single-page UI
├── requirements.txt
├── .env.example
└── README.md
```

---

## Safety notes

- Only targets in `APPROVED_TARGETS` (hardcoded in `app.py`) are accepted; all others return HTTP 403.
- Nmap flags are fixed — no user-supplied arguments reach the shell.
- Target is passed as a positional nmap argument, never interpolated into a shell string.
- `subprocess.run` is called with a list (no `shell=True`), preventing injection.

---

## Extending approved targets

To add another host you control (e.g. a private lab VM), edit `APPROVED_TARGETS` in `app.py`:

```python
APPROVED_TARGETS = {
    "scanme.nmap.org": "Nmap official public test host",
    "192.168.56.101":  "My local Metasploitable VM",
}
```

Only do this for hosts you own or have written permission to scan.
