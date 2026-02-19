# 📧 Mail Phishing Simulator

A simple phishing/spam risk analyzer that connects to a mailbox using IMAP, scans recent emails, calculates a risk score (0–100), and displays results on a dashboard.

⚠️ **Currently supports Gmail only.**

---

## 🚀 Features

- Connect Gmail using IMAP + App Password
- Scan last N emails from INBOX
- Analyze:
  - Sender domain & reply-to mismatch
  - Suspicious URLs (IP links, shorteners, risky TLDs)
  - Risky attachments
  - Phishing keywords
  - Lightweight ML signal
- Generate:
  - Risk Score (0–100)
  - Risk Level (Low / Medium / High / Critical)
  - Risk Factors list
- Stores only derived metrics (no raw email bodies saved)
- Dashboard with charts + per-email results

---

## ⚠️ Gmail Setup (Required)

Google does NOT allow normal password login for IMAP.  
You must enable IMAP + 2FA and generate an App Password.

### 1) Enable IMAP
1. Open Gmail  
2. Settings → See all settings  
3. Forwarding and POP/IMAP  
4. Enable **IMAP**  
5. Save changes  

### 2) Enable 2-Step Verification
1. Go to: https://myaccount.google.com/security  
2. Turn ON **2-Step Verification**

### 3) Generate App Password
1. Go to: https://myaccount.google.com/apppasswords  
2. Select:
   - App: Mail  
   - Device: Windows Computer (or Other)  
3. Click Generate  
4. Copy the 16-character password and use it in the app  

---

## 🛠 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/mail-phishing-simulator.git
cd mail-phishing-simulator/backend
```

---

## 2. Create Virtual Environment

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Set Encryption Key (Required)

Generate a key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Create a file: `backend/.env`

```env
APP_ENCRYPTION_KEY=PASTE_YOUR_GENERATED_KEY_HERE
```

---

## 5. Run the Server

```bash
python -m uvicorn app:app --reload --port 8000
```

Open in browser:

```
http://127.0.0.1:8000/
```

API Documentation:

```
http://127.0.0.1:8000/docs
```

---

## 🧪 Tech Stack

| Backend                        | Frontend | Email Protocol     |
|--------------------------------|----------|--------------------|
| Python 3.x                     | HTML5    | IMAP (Gmail)       |
| FastAPI                        | CSS3     | SSL/TLS (Port 993) |
| SQLAlchemy                     | Chart.js |                    |
| SQLite                         |          |                    |
| Cryptography (Fernet Encryption)|         |                    |
| python-dotenv                  |          |                    |
| scikit-learn (Mini ML model)   |          |                    |

---

## 📁 Project Structure

```
mail-phishing-simulator/
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── .env                # (Not pushed to GitHub)
│   └── app.db              # Auto-created SQLite DB
│
├── frontend/
│   └── index.html
│
├── .gitignore
├── README.md
```

---

## 🟥 Risk Levels

| Score    | Level    |
|----------|----------|
| 0–24     | Low      |
| 25–49    | Medium   |
| 50–74    | High     |
| 75–100   | Critical |

---

## 🔒 Data Storage

**Stored:**
- Risk score
- Risk level
- Timestamp
- Sender domain
- Risk factors

**Not Stored:**
- Raw email bodies
- Full attachments

---

## 📌 Notes

- Gmail IMAP: `imap.gmail.com`
- Port: `993`
- SSL: Enabled

---

## ⚠️ Disclaimer

This project is for educational and cybersecurity learning purposes only.
