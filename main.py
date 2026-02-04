import os
import re
import asyncio
from typing import Dict, Any, List, Optional, Union

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

APP = FastAPI(title="Agentic HoneyPot API", version="1.0.0")

API_KEY = os.getenv("HONEYPOT_API_KEY", "")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_LOCK = asyncio.Lock()

# ---------------- Models ----------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]  # guideline says epoch ms; accept both

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class HoneyPotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None

class HoneyPotResponse(BaseModel):
    status: str
    reply: str

# ---------------- Regex ----------------
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
PHONE_REGEX = re.compile(r"\b(\+91[\s-]?)?[6-9]\d{9}\b")
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)

# Bank accounts: safer extraction using context words
# e.g. "account number 12345678901", "a/c: 1234567890"
BANK_CTX_REGEX = re.compile(
    r"(?:account(?:\s*number)?|acct|a/c|ac(?:\s*no)?|acc(?:\s*no)?)\s*[:\-]?\s*(\d{9,18})",
    re.IGNORECASE
)

KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp",
    "upi", "refund", "click", "bank", "kyc", "account",
    "freeze", "limited", "penalty", "immediately", "compromised"
]

# ---------------- GUVI tester detection ----------------
def is_guvi_tester_payload(body: Any) -> bool:
    # Endpoint Tester sends apiUrl/apiKey/hackathonId/authToken/etc.
    return isinstance(body, dict) and any(
        k in body for k in ["apiUrl", "apiKey", "hackathonId", "requestedFrom", "authToken", "originUrl"]
    )

# ---------------- Detection ----------------
def is_scam(text: str) -> bool:
    score = 0
    t = text.lower()

    if URL_REGEX.search(text):
        score += 3
    if UPI_REGEX.search(text):
        score += 3
    if PHONE_REGEX.search(text):
        score += 1
    if "otp" in t:
        score += 3

    # Contextual bank account mention boosts score
    if BANK_CTX_REGEX.search(text):
        score += 2

    for k in KEYWORDS:
        if k in t:
            score += 1

    return score >= 5

# ---------------- Intelligence extraction ----------------
def extract_intel(text: str) -> Dict[str, List[str]]:
    upis = set(UPI_REGEX.findall(text))
    links = set(URL_REGEX.findall(text))
    phones = set(PHONE_REGEX.findall(text))
    # PHONE_REGEX with group returns tuples sometimes; normalize
    normalized_phones = set()
    for p in phones:
        if isinstance(p, tuple):
            # group behavior: first group might be "+91" etc; rebuild by re-finditer to be safe
            pass
    normalized_phones = set(m.group(0) for m in PHONE_REGEX.finditer(text))

    bank_accounts = set(m.group(1) for m in BANK_CTX_REGEX.finditer(text))
    ifsc = set(IFSC_REGEX.findall(text))

    return {
        "bankAccounts": list(bank_accounts),
        "upiIds": list(upis),
        "phishingLinks": list(links),
        "phoneNumbers": list(normalized_phones),
        "ifscCodes": list(ifsc),
    }

# ---------------- Agent logic ----------------
def next_agent_reply(session: Dict[str, Any], last_msg: str) -> str:
    t = last_msg.lower()
    intel = session["intel"]
    asked = session["asked"]
    expect = session["expecting"]  # what we are trying to get next (upi/link/phone/bank/ref)

    def ask_once(key: str, text: str) -> Optional[str]:
        if key in asked:
            return None
        asked.add(key)
        return text

    # ----- safety (never share OTP / never pay) -----
    if "otp" in t:
        session["expecting"] = "support_ref"
        return (
            ask_once(
                "otp_refuse",
                "I can’t share OTP. Please provide an official bank support number or a complaint/ticket reference."
            )
            or "Please share the official support number or complaint/ticket reference."
        )

    # If scammer pushes payment/transfer
    if any(x in t for x in ["pay", "transfer", "payment", "debit", "send rs", "send ₹", "freeze", "frozen"]):
        session["expecting"] = "beneficiary"
        return (
            ask_once(
                "beneficiary",
                "Before I proceed, what beneficiary/merchant name shows on the payment request? Also share the exact reason message."
            )
            or "What beneficiary/merchant name shows on the payment request?"
        )

    # ---------- Self-correction: if we expected something and didn’t get it ----------
    # If we asked for UPI earlier but still none found after a couple turns, re-ask differently.
    if expect == "upi" and not intel["upiIds"]:
        session["miss_counts"]["upi"] += 1
        if session["miss_counts"]["upi"] == 1:
            return "I’m not seeing the UPI handle. Please send it exactly like name@bank (no spaces)."
        if session["miss_counts"]["upi"] >= 2:
            # switch tactic to link/phone
            session["expecting"] = "phone"
            return "Okay. If you can’t share UPI, which number should I call back to confirm this request?"

    if expect == "link" and not intel["phishingLinks"]:
        session["miss_counts"]["link"] += 1
        if session["miss_counts"]["link"] == 1:
            return "Please paste the full link exactly as received (including https://)."
        if session["miss_counts"]["link"] >= 2:
            session["expecting"] = "phone"
            return "I didn’t receive the link. Share your official helpline number so I can confirm."

    if expect == "phone" and not intel["phoneNumbers"]:
        session["miss_counts"]["phone"] += 1
        if session["miss_counts"]["phone"] == 1:
            return "Which number should I call to confirm this? Please share the helpline/contact number."
        if session["miss_counts"]["phone"] >= 2:
            session["expecting"] = "upi"
            return "Okay, then share the UPI handle you want me to use (like name@bank)."

    # ---------- Stage-based flow ----------
    stage = session["stage"]

    # Stage 1: triage
    if stage == "triage":
        q = ask_once("bank_name", "Which bank is this and which department? (KYC/Compliance/UPI/NetBanking)")
        if q:
            session["expecting"] = "bank"
            return q
        q = ask_once("reason", "What’s the exact reason for blocking—KYC pending, suspicious activity, or something else?")
        if q:
            session["expecting"] = "reason"
            return q
        q = ask_once("ref_id", "Do you have an official reference/ticket number for this case?")
        if q:
            session["expecting"] = "support_ref"
            return q
        session["stage"] = "collect_intel"
        stage = "collect_intel"

    # Stage 2: collect intel (actively request missing items)
    if stage == "collect_intel":
        # Prefer collecting link first if none
        if not intel["phishingLinks"]:
            session["expecting"] = "link"
            q = ask_once("ask_link", "Please share the official verification link you received (paste the full URL).")
            if q:
                return q

        if not intel["upiIds"]:
            session["expecting"] = "upi"
            q = ask_once("ask_upi", "What’s the UPI ID / handle you want me to use? Please send it exactly (like name@bank).")
            if q:
                return q

        if not intel["phoneNumbers"]:
            session["expecting"] = "phone"
            q = ask_once("ask_phone", "Which number should I call back to confirm this request? Please share the contact number.")
            if q:
                return q

        # Ask for bank acct only if they mention bank transfer or if IFSC present
        if not intel["bankAccounts"]:
            session["expecting"] = "bank"
            q = ask_once("ask_bank", "If it’s not UPI, share the account number and IFSC (for verification).")
            if q:
                return q

        session["stage"] = "stall"
        stage = "stall"

    # Stage 3: stall and extend (believable + non-repetitive)
    if stage == "stall":
        for key, text in [
            ("time_window", "By what time exactly will it be blocked? I’m currently not near my banking app."),
            ("message_copy", "Can you forward the exact SMS/email text you received from the bank (word to word)?"),
            ("branch_city", "Which branch/city is handling this? My account is from a different city."),
            ("confirm_again", "Just confirming—share the UPI/link again so I can verify before I do anything."),
        ]:
            q = ask_once(key, text)
            if q:
                return q

        return "Okay, share the link/UPI/contact details again so I can complete the verification."

    return "Can you share the official reference number and the exact steps again?"

# ---------------- Finalization & Callback ----------------
def should_finalize(session: Dict[str, Any]) -> bool:
    intel = session["intel"]

    categories = 0
    if intel["upiIds"]:
        categories += 1
    if intel["phishingLinks"]:
        categories += 1
    if intel["phoneNumbers"]:
        categories += 1
    if intel["bankAccounts"] or intel["ifscCodes"]:
        categories += 1

    # finalize after deep engagement OR enough intel
    if session["total_messages"] >= 18:
        return True
    if categories >= 2 and session["total_messages"] >= 10:
        return True
    return False

def send_callback(session_id: str, session: Dict[str, Any]) -> None:
    if session.get("callback_sent"):
        return

    intel = session["intel"]
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["total_messages"],
        "extractedIntelligence": {
            "bankAccounts": intel["bankAccounts"],
            "upiIds": intel["upiIds"],
            "phishingLinks": intel["phishingLinks"],
            "phoneNumbers": intel["phoneNumbers"],
            "suspiciousKeywords": session["keywords"],
        },
        "agentNotes": session.get(
            "notes",
            "Scammer used urgency/verification tactics. Agent engaged to extract UPI/link/phone/bank details."
        ),
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        session["callback_sent"] = True
    except Exception:
        # don't crash
        pass

# ---------------- Routes ----------------
@APP.get("/")
def root():
    return {"status": "ok", "message": "Agentic HoneyPot API is live"}

@APP.get("/health")
def health():
    return {"status": "ok"}

@APP.get("/honeypot", response_model=HoneyPotResponse)
async def honeypot_get(x_api_key: str = Header(default="")):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server misconfigured: API key missing")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

@APP.post("/honeypot", response_model=HoneyPotResponse)
async def honeypot(request: Request, x_api_key: str = Header(default="")):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server misconfigured: API key missing")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Robust JSON parsing (GUVI tester may send different shape)
    try:
        body = await request.json()
    except Exception:
        body = None

    # GUVI Endpoint Tester compatibility
    if is_guvi_tester_payload(body):
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    # If body isn't real honeypot payload, don't fail
    if not isinstance(body, dict) or "sessionId" not in body or "message" not in body:
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    try:
        req = HoneyPotRequest(**body)
    except ValidationError:
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    async with SESSION_LOCK:
        session = SESSIONS.setdefault(req.sessionId, {
            "scam": False,
            "intel": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "ifscCodes": []},
            "keywords": [],
            "callback_sent": False,
            "stage": "triage",
            "asked": set(),
            "total_messages": 0,  # counts both sides
            "notes": "",
            "expecting": None,
            "miss_counts": {"upi": 0, "link": 0, "phone": 0},
        })

        # count incoming
        session["total_messages"] += 1

        # extract intel
        intel = extract_intel(req.message.text)
        for k, v in intel.items():
            if k in session["intel"]:
                session["intel"][k] = list(set(session["intel"][k] + v))

        # keywords
        msg_lower = req.message.text.lower()
        for kw in KEYWORDS:
            if kw in msg_lower:
                session["keywords"].append(kw)
        session["keywords"] = list(set(session["keywords"]))

        # detect scam
        if not session["scam"] and is_scam(req.message.text):
            session["scam"] = True
            session["notes"] = "Scam intent detected; agent engaged to extract intelligence."

        # if not scam, stay neutral (don’t expose)
        if not session["scam"]:
            session["total_messages"] += 1
            return HoneyPotResponse(status="success", reply="Can you explain what you need?")

        # agent reply
        reply = next_agent_reply(session, req.message.text)
        session["total_messages"] += 1

        # callback when done
        if should_finalize(session):
            send_callback(req.sessionId, session)

        # IMPORTANT: match guideline response format (status + reply only)
        return HoneyPotResponse(status="success", reply=reply)
