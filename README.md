## Phishing / Spam Risk Dashboard (SRS + Design implementation)

This project implements the web application described in `phishing_detector.srs.txt` and `📗 SYSTEM DESIGN DOCUMENT.txt`:

- Connect a mailbox (IMAP app password)
- Fetch last \(N\) emails
- Analyze sender/content/URLs/attachments in-memory
- Compute per-email risk score + risk factors
- Store **only derived metrics** (no raw bodies stored)
- Show dashboard charts + results list + exposure settings

### Tech

- **Backend**: FastAPI (Python)
- **DB**: SQLite (default; easy to swap)
- **Frontend**: Static single-page UI (Tailwind + Chart.js) served by the backend

---

## Run locally (Windows)

### 1) Backend setup

From the project root:

```powershell
cd "c:\Users\hp\OneDrive\Desktop\phy ms\backend"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If you hit Windows “Access is denied” while creating a venv or installing packages (common with Desktop/OneDrive “protected folders”), create the venv in a non-protected location instead, e.g.:

```powershell
py -m venv "$env:LOCALAPPDATA\venvs\mailbox-risk"
& "$env:LOCALAPPDATA\venvs\mailbox-risk\Scripts\Activate.ps1"
pip install -r "c:\Users\hp\OneDrive\Desktop\phy ms\backend\requirements.txt"
```

### 2) Set encryption key (required)

The backend encrypts stored mailbox credentials using Fernet. You have **two options**:

#### Option A: Use a `.env` file (recommended - persists across sessions)

1. Generate a key:
```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

2. Copy `backend/.env.example` to `backend/.env`:
```powershell
cd backend
Copy-Item .env.example .env
```

3. Edit `backend/.env` and paste your generated key:
```text
APP_ENCRYPTION_KEY=your-generated-key-here
```

#### Option B: Set in PowerShell (temporary - only for current session)

```powershell
$env:APP_ENCRYPTION_KEY="PASTE_THE_KEY_HERE"
```

**Note**: Option A is recommended because the key persists. Option B requires setting it every time you open a new terminal.

### 3) Start the server

```powershell
$env:PYTHONDONTWRITEBYTECODE=1
python -m uvicorn app:app --reload --port 8000
```

Open the UI:

- `http://127.0.0.1:8000/`

API docs:

- `http://127.0.0.1:8000/docs`

---

## IMAP notes

- **Gmail**: IMAP must be enabled; use an **App Password** (requires 2FA).
- **Outlook/Office365**: IMAP support depends on tenant settings; also prefer app passwords where available.

This implementation focuses on the SRS requirement “OAuth OR IMAP app password” and provides the IMAP app-password flow. The API shape keeps room for adding OAuth later without changing the dashboard.

## Data storage note

By default the SQLite database is stored in **`%LOCALAPPDATA%\mailbox_risk\app.db`** to avoid writing inside protected folders. You can override this with:

```powershell
$env:DB_URL="sqlite:///C:/path/to/app.db"
```

