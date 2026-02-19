from __future__ import annotations

import base64
import email
import hashlib
import imaplib
import json
import os
import re
import secrets
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from dateutil import parser as date_parser
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
except Exception:  # pragma: no cover
    TfidfVectorizer = None  # type: ignore
    LogisticRegression = None  # type: ignore


APP_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = APP_ROOT.parent / "frontend"

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_file = APP_ROOT / ".env"
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass  # python-dotenv not installed, skip


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required env var {name}. "
            f"Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return value


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_email_date(value: Optional[str]) -> datetime:
    if not value:
        return _utcnow()
    try:
        dt = date_parser.parse(value)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return _utcnow()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_mailbox_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    settings: Mapped["UserSettings"] = relationship(back_populates="user", uselist=False)


class UserSettings(Base):
    __tablename__ = "user_settings"

    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), primary_key=True)
    scan_limit: Mapped[int] = mapped_column(Integer, default=50)
    risk_threshold: Mapped[int] = mapped_column(Integer, default=60)
    scan_frequency_minutes: Mapped[int] = mapped_column(Integer, default=60)

    user: Mapped[User] = relationship(back_populates="settings")


class EmailRiskMetric(Base):
    __tablename__ = "email_risk_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), index=True)
    msg_hash: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    factors_json: Mapped[str] = mapped_column(Text)
    sender_domain: Mapped[str] = mapped_column(String(255), default="")


def _default_db_url() -> str:
    # Avoid writing to protected folders (e.g., Desktop/OneDrive) by default.
    base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
    db_dir = Path(base) / "mailbox_risk"
    db_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(db_dir / 'app.db').as_posix()}"


DB_URL = os.getenv("DB_URL") or _default_db_url()
engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db() -> Session:
    with Session(engine) as session:
        yield session


def get_fernet() -> Fernet:
    key = _require_env("APP_ENCRYPTION_KEY").encode("utf-8")
    try:
        return Fernet(key)
    except Exception as e:
        raise RuntimeError("Invalid APP_ENCRYPTION_KEY; must be a Fernet key.") from e


def encrypt_json(data: dict[str, Any]) -> str:
    f = get_fernet()
    token = f.encrypt(json.dumps(data).encode("utf-8"))
    return token.decode("utf-8")


def decrypt_json(token: str) -> dict[str, Any]:
    f = get_fernet()
    try:
        raw = f.decrypt(token.encode("utf-8"))
    except InvalidToken as e:
        raise RuntimeError("Encrypted mailbox data could not be decrypted.") from e
    return json.loads(raw.decode("utf-8"))


def _new_api_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")


def _risk_level(score: int) -> str:
    if score < 25:
        return "Low"
    if score < 50:
        return "Medium"
    if score < 75:
        return "High"
    return "Critical"


URL_RE = re.compile(r"(https?://[^\s<>()\"']+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[\w\.\-+%]+@[\w\.\-]+\.[A-Za-z]{2,}")

SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".work", ".ru", ".su"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
PHISH_PHRASES = [
    "verify your account",
    "update your account",
    "security alert",
    "unusual activity",
    "suspend",
    "locked",
    "urgent",
    "act now",
    "confirm your password",
    "reset your password",
    "payment failed",
    "invoice attached",
    "click below",
    "log in",
    "login",
    "credentials",
]
BRAND_DOMAINS = [
    "paypal.com",
    "microsoft.com",
    "office.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "amazon.com",
    "icloud.com",
]
RISKY_ATTACHMENT_EXTS = {".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".zip", ".rar", ".7z", ".iso"}


def _extract_sender_domain(from_header: str) -> str:
    matches = EMAIL_RE.findall(from_header or "")
    if not matches:
        return ""
    addr = matches[0].lower()
    return addr.split("@")[-1]


def _extract_urls(text: str) -> list[str]:
    return [m.group(1).rstrip(").,;") for m in URL_RE.finditer(text or "")]


def _get_body_text(msg: Message) -> str:
    # Prefer text/plain; fall back to stripping HTML tags lightly.
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            if ctype == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        return payload.decode(charset, errors="replace")
                    except Exception:
                        return payload.decode("utf-8", errors="replace")
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            if ctype == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        html = payload.decode(charset, errors="replace")
                    except Exception:
                        html = payload.decode("utf-8", errors="replace")
                    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
                    html = re.sub(r"(?s)<[^>]+>", " ", html)
                    return re.sub(r"\s+", " ", html).strip()
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except Exception:
                return payload.decode("utf-8", errors="replace")
    return ""


def _extract_attachment_names(msg: Message) -> list[str]:
    names: list[str] = []
    if not msg.is_multipart():
        return names
    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        if "attachment" not in disp:
            continue
        filename = part.get_filename()
        if filename:
            names.append(filename)
    return names


def _domain_from_url(url: str) -> str:
    m = re.match(r"^https?://([^/]+)/?", url, flags=re.IGNORECASE)
    if not m:
        return ""
    host = m.group(1).split("@")[-1]
    host = host.split(":")[0].lower()
    return host


def _is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def analyze_urls(urls: list[str], factors: list[str]) -> float:
    if not urls:
        return 0.0
    score = 0.0
    for u in urls:
        host = _domain_from_url(u)
        if not host:
            continue
        if _is_ip_host(host):
            score += 0.35
            factors.append("url:ip-host")
        if host.startswith("xn--"):
            score += 0.25
            factors.append("url:punycode")
        if host.count(".") >= 4:
            score += 0.15
            factors.append("url:many-subdomains")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 0.25
            factors.append("url:suspicious-tld")
        if host in SHORTENERS:
            score += 0.20
            factors.append("url:shortener")
    return min(1.0, score)


def analyze_content(subject: str, body: str, factors: list[str]) -> float:
    text = f"{subject}\n{body}".lower()
    score = 0.0
    for phrase in PHISH_PHRASES:
        if phrase in text:
            score += 0.08
            factors.append(f"content:{phrase[:24].replace(' ', '-')}")
    if len(_extract_urls(text)) >= 3:
        score += 0.15
        factors.append("content:many-links")
    if re.search(r"\b(one\s*time\s*password|otp|2fa)\b", text):
        score += 0.12
        factors.append("content:otp-lure")
    if re.search(r"\b(bank|gift\s*card|wire|crypto)\b", text):
        score += 0.10
        factors.append("content:payment-lure")
    return min(1.0, score)


def analyze_sender(from_header: str, reply_to: Optional[str], factors: list[str]) -> float:
    score = 0.0
    sender_domain = _extract_sender_domain(from_header or "")
    reply_domain = _extract_sender_domain(reply_to or "") if reply_to else ""
    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 0.35
        factors.append("sender:reply-to-mismatch")

    if sender_domain:
        # Very light typosquat detector vs common brands
        for brand in BRAND_DOMAINS:
            if sender_domain == brand:
                continue
            # same TLD and close-ish similarity is suspicious
            if sender_domain.split(".")[-1] == brand.split(".")[-1]:
                import difflib

                if difflib.SequenceMatcher(a=sender_domain, b=brand).ratio() >= 0.86:
                    score += 0.25
                    factors.append("sender:brand-similarity")
                    break

    if "noreply" in (from_header or "").lower() and sender_domain and sender_domain not in BRAND_DOMAINS:
        score += 0.10
        factors.append("sender:noreply-nonbrand")

    return min(1.0, score)


def analyze_attachments(names: list[str], factors: list[str]) -> float:
    if not names:
        return 0.0
    score = 0.0
    for n in names:
        ext = ("." + n.split(".")[-1]).lower() if "." in n else ""
        if ext in RISKY_ATTACHMENT_EXTS:
            score += 0.30
            factors.append(f"attachment:risky{ext}")
    return min(1.0, score)


@dataclass
class MiniML:
    vectorizer: Any
    model: Any

    def prob(self, text: str) -> float:
        if not text.strip():
            return 0.0
        X = self.vectorizer.transform([text])
        proba = self.model.predict_proba(X)[0][1]
        return float(max(0.0, min(1.0, proba)))


def build_mini_ml() -> Optional[MiniML]:
    if TfidfVectorizer is None or LogisticRegression is None:
        return None
    # Tiny built-in dataset (placeholder). Replace with a real trained model later.
    phishing = [
        "verify your account now",
        "urgent security alert click link to login",
        "your password expires reset password immediately",
        "invoice attached open urgently",
        "unusual activity confirm credentials",
        "payment failed update billing information",
    ]
    safe = [
        "meeting agenda for tomorrow",
        "family photos attached",
        "your order has shipped",
        "newsletter weekly update",
        "project status report",
        "lunch plans next week",
    ]
    y = [1] * len(phishing) + [0] * len(safe)
    X_text = phishing + safe

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=5000)
    X = vec.fit_transform(X_text)
    clf = LogisticRegression(max_iter=200)
    clf.fit(X, y)
    return MiniML(vectorizer=vec, model=clf)


mini_ml: Optional[MiniML] = None


class ConnectImapRequest(BaseModel):
    provider: str = Field(default="gmail", description="gmail|outlook|custom")
    email: str
    username: Optional[str] = None
    app_password: str
    imap_host: Optional[str] = None
    imap_port: Optional[int] = None
    use_ssl: Optional[bool] = True


class ConnectResponse(BaseModel):
    user_id: str
    api_key: str


class ScanRequest(BaseModel):
    limit: Optional[int] = Field(default=None, ge=1, le=200)


class ScanResponse(BaseModel):
    scanned: int
    stored: int


class MetricOut(BaseModel):
    timestamp: datetime
    msg_hash: str
    risk_score: int
    risk_level: str
    factors: list[str]
    sender_domain: str = ""


class ResultsResponse(BaseModel):
    items: list[MetricOut]


class DashboardResponse(BaseModel):
    distribution: dict[str, int]
    trend: list[dict[str, Any]]
    top_factors: list[dict[str, Any]]
    flagged_count: int
    total_count: int


class SettingsIn(BaseModel):
    scan_limit: int = Field(ge=1, le=200, default=50)
    risk_threshold: int = Field(ge=0, le=100, default=60)
    scan_frequency_minutes: int = Field(ge=5, le=10080, default=60)


class SettingsOut(SettingsIn):
    pass


def get_user(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    db: Session = Depends(get_db),
) -> User:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-Api-Key.")
    api_hash = _sha256_hex(x_api_key)
    user = db.scalar(select(User).where(User.api_key_hash == api_hash))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return user


app = FastAPI(title="Mailbox Phishing Risk API", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    global mini_ml
    init_db()
    mini_ml = build_mini_ml()


@app.get("/")
def ui_index() -> FileResponse:
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=500, detail="Frontend not found.")
    return FileResponse(index)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "time": _utcnow().isoformat()}


@app.post("/api/connect/imap", response_model=ConnectResponse)
def connect_imap(req: ConnectImapRequest, db: Session = Depends(get_db)) -> ConnectResponse:
    provider = (req.provider or "custom").lower()
    if provider not in {"gmail", "outlook", "custom"}:
        raise HTTPException(status_code=400, detail="provider must be gmail|outlook|custom")

    if provider == "gmail":
        host, port, use_ssl = "imap.gmail.com", 993, True
    elif provider == "outlook":
        host, port, use_ssl = "imap-mail.outlook.com", 993, True
    else:
        host = req.imap_host or ""
        port = int(req.imap_port or 993)
        use_ssl = bool(req.use_ssl)
        if not host:
            raise HTTPException(status_code=400, detail="imap_host is required for custom provider")

    username = req.username or req.email
    user_id = _sha256_hex(req.email.lower())[:32]
    api_key = _new_api_key()
    mailbox = {
        "type": "imap",
        "provider": provider,
        "email": req.email,
        "username": username,
        "app_password": req.app_password,
        "host": host,
        "port": port,
        "use_ssl": use_ssl,
    }
    
    print("DEBUG username:", repr(mailbox.get("username")))
    pw_raw = str(mailbox.get("app_password") or "")
    print("DEBUG pw_raw_len:", len(pw_raw))
    pw_norm = pw_raw.replace(" ", "").strip()
    print("DEBUG pw_norm_len:", len(pw_norm))


    try:
        pw = str(mailbox.get("app_password") or "")
        print("DEBUG IMAP provider:", mailbox.get("provider"))
        print("DEBUG IMAP host/port/ssl:", mailbox.get("host"), mailbox.get("port"), mailbox.get("use_ssl"))
        print("DEBUG IMAP username repr:", repr(mailbox.get("username")))
        print("DEBUG IMAP password length:", len(pw))
        print("DEBUG IMAP password preview:", repr((pw[:4] + "..." + pw[-4:]) if len(pw) >= 8 else pw))
    except Exception:
        pass


    try:
        test_client = _imap_login(mailbox)
        try:
            test_client.select("INBOX")  # light check
        finally:
            try:
                test_client.logout()
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"IMAP credential check failed: {type(e).__name__}: {e}",
        ) from e

    existing = db.scalar(select(User).where(User.id == user_id))

    if existing:
        # Update creds + rotate API key
        existing.api_key_hash = _sha256_hex(api_key)
        existing.encrypted_mailbox_json = encrypt_json(mailbox)
        # Keep created_at as-is (or update if you prefer)
        user = existing

        # Ensure settings exist
        if not user.settings:
            user.settings = UserSettings(
                user_id=user_id, scan_limit=50, risk_threshold=60, scan_frequency_minutes=60
            )
    else:
        user = User(
            id=user_id,
            api_key_hash=_sha256_hex(api_key),
            encrypted_mailbox_json=encrypt_json(mailbox),
            created_at=_utcnow(),
        )
        user.settings = UserSettings(user_id=user_id, scan_limit=50, risk_threshold=60, scan_frequency_minutes=60)
        db.add(user)

    db.commit()
    return ConnectResponse(user_id=user_id, api_key=api_key)



def _imap_login(mailbox: dict[str, Any]) -> imaplib.IMAP4:
    host = mailbox["host"]
    port = int(mailbox.get("port") or 993)
    use_ssl = bool(mailbox.get("use_ssl", True))

    username = str(mailbox.get("username") or "").strip()

    # Normalize app password safely (remove spaces + trim newlines)
    password_raw = str(mailbox.get("app_password") or "")
    password = password_raw.replace(" ", "").strip()

    if not username or not password:
        raise ValueError("Missing IMAP username/password.")

    client: imaplib.IMAP4
    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port)
    else:
        client = imaplib.IMAP4(host, port)

    client.login(username, password)
    return client


def _safe_msg_hash(msg: Message) -> str:
    msg_id = (msg.get("Message-ID") or "").strip()
    date = (msg.get("Date") or "").strip()
    from_h = (msg.get("From") or "").strip()
    subj = (msg.get("Subject") or "").strip()
    seed = "|".join([msg_id, date, from_h, subj])
    return _sha256_hex(seed or secrets.token_hex(16))


def _analyze_email(msg: Message) -> tuple[int, str, list[str], str]:
    factors: list[str] = []
    subject = (msg.get("Subject") or "")[:500]
    from_h = msg.get("From") or ""
    reply_to = msg.get("Reply-To")
    sender_domain = _extract_sender_domain(from_h)

    body = _get_body_text(msg)
    urls = _extract_urls(body)
    attachments = _extract_attachment_names(msg)

    url_r = analyze_urls(urls, factors)
    content_r = analyze_content(subject, body, factors)
    sender_r = analyze_sender(from_h, reply_to, factors)
    attach_r = analyze_attachments(attachments, factors)

    text_for_ml = f"{subject}\n{body}"
    ml_p = mini_ml.prob(text_for_ml) if mini_ml else 0.0
    if ml_p >= 0.75:
        factors.append("ml:high-probability")
    elif ml_p >= 0.5:
        factors.append("ml:medium-probability")

    # Weighted formula from design doc; normalize to 0..100
    blended = (
        0.35 * ml_p
        + 0.25 * url_r
        + 0.20 * sender_r
        + 0.15 * content_r
        + 0.05 * attach_r
    )
    score = int(round(100 * max(0.0, min(1.0, blended))))
    level = _risk_level(score)
    return score, level, sorted(set(factors)), sender_domain


@app.post("/api/scan", response_model=ScanResponse)
def scan_mailbox(req: ScanRequest, user: User = Depends(get_user), db: Session = Depends(get_db)) -> ScanResponse:
    mailbox = decrypt_json(user.encrypted_mailbox_json)

    settings = db.scalar(select(UserSettings).where(UserSettings.user_id == user.id))
    scan_limit = int(req.limit or (settings.scan_limit if settings else 50))
    scan_limit = max(1, min(200, scan_limit))

    scanned = 0
    stored = 0

    try:
        client = _imap_login(mailbox)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"IMAP login failed: {type(e).__name__}:{e}") from e

    try:
        client.select("INBOX")
        typ, data = client.search(None, "ALL")
        if typ != "OK" or not data or not data[0]:
            return ScanResponse(scanned=0, stored=0)
        ids = data[0].split()
        ids = ids[-scan_limit:]

        for msg_id in reversed(ids):
            scanned += 1
            try:
                typ2, msg_data = client.fetch(msg_id, "(RFC822)")
                if typ2 != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1]
                if not raw:
                    continue
                msg = email.message_from_bytes(raw)

                msg_hash = _safe_msg_hash(msg)
                ts = _parse_email_date(msg.get("Date"))
                score, level, factors, sender_domain = _analyze_email(msg)

                metric = EmailRiskMetric(
                    user_id=user.id,
                    msg_hash=msg_hash,
                    timestamp=ts,
                    risk_score=score,
                    risk_level=level,
                    factors_json=json.dumps(factors),
                    sender_domain=sender_domain or "",
                )
                db.add(metric)
                stored += 1
            except Exception:
                # Partial scan allowed (SRS reliability)
                continue

        db.commit()
        return ScanResponse(scanned=scanned, stored=stored)
    finally:
        try:
            client.logout()
        except Exception:
            pass


@app.get("/api/results", response_model=ResultsResponse)
def get_results(
    limit: int = 100,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
) -> ResultsResponse:
    limit = max(1, min(500, int(limit)))
    rows = db.execute(
        select(EmailRiskMetric)
        .where(EmailRiskMetric.user_id == user.id)
        .order_by(EmailRiskMetric.timestamp.desc())
        .limit(limit)
    ).scalars()

    items: list[MetricOut] = []
    for r in rows:
        try:
            factors = json.loads(r.factors_json)
        except Exception:
            factors = []
        items.append(
            MetricOut(
                timestamp=r.timestamp,
                msg_hash=r.msg_hash,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                factors=factors,
                sender_domain=r.sender_domain or "",
            )
        )
    return ResultsResponse(items=items)


@app.get("/api/settings", response_model=SettingsOut)
def get_settings(user: User = Depends(get_user), db: Session = Depends(get_db)) -> SettingsOut:
    s = db.scalar(select(UserSettings).where(UserSettings.user_id == user.id))
    if not s:
        s = UserSettings(user_id=user.id, scan_limit=50, risk_threshold=60, scan_frequency_minutes=60)
        db.add(s)
        db.commit()
    return SettingsOut(scan_limit=s.scan_limit, risk_threshold=s.risk_threshold, scan_frequency_minutes=s.scan_frequency_minutes)


@app.post("/api/settings", response_model=SettingsOut)
def update_settings(body: SettingsIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> SettingsOut:
    s = db.scalar(select(UserSettings).where(UserSettings.user_id == user.id))
    if not s:
        s = UserSettings(user_id=user.id)
        db.add(s)
    s.scan_limit = body.scan_limit
    s.risk_threshold = body.risk_threshold
    s.scan_frequency_minutes = body.scan_frequency_minutes
    db.commit()
    return SettingsOut(scan_limit=s.scan_limit, risk_threshold=s.risk_threshold, scan_frequency_minutes=s.scan_frequency_minutes)


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(user: User = Depends(get_user), db: Session = Depends(get_db)) -> DashboardResponse:
    s = db.scalar(select(UserSettings).where(UserSettings.user_id == user.id))
    threshold = int(s.risk_threshold if s else 60)

    rows = db.execute(
        select(EmailRiskMetric)
        .where(EmailRiskMetric.user_id == user.id)
        .order_by(EmailRiskMetric.timestamp.desc())
        .limit(2000)
    ).scalars().all()

    dist = Counter([r.risk_level for r in rows])
    flagged_count = sum(1 for r in rows if r.risk_score >= threshold)

    # Trend grouped by day
    by_day: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        day = r.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d")
        by_day[day].append(int(r.risk_score))

    trend = []
    for day in sorted(by_day.keys())[-30:]:
        scores = by_day[day]
        trend.append({"day": day, "count": len(scores), "avg_risk": round(sum(scores) / max(1, len(scores)), 2)})

    factor_counts: Counter[str] = Counter()
    for r in rows:
        try:
            factors = json.loads(r.factors_json)
        except Exception:
            factors = []
        factor_counts.update([str(f) for f in factors])

    top_factors = [{"factor": f, "count": c} for f, c in factor_counts.most_common(10)]

    distribution = {k: int(dist.get(k, 0)) for k in ["Low", "Medium", "High", "Critical"]}
    return DashboardResponse(
        distribution=distribution,
        trend=trend,
        top_factors=top_factors,
        flagged_count=int(flagged_count),
        total_count=int(len(rows)),
    )


@app.exception_handler(RuntimeError)
def runtime_error_handler(_req, exc: RuntimeError):
    return JSONResponse(status_code=500, content={"detail": str(exc)})

