import os
import re
import asyncio
import random
import string
from typing import Dict, Any, List, Optional, Union

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

APP = FastAPI(title="Agentic HoneyPot API", version="1.2.0")

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

# Mobile numbers (India)
PHONE_REGEX = re.compile(r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b")

# Toll-free / landline-ish patterns (captures 1800-xxx-xxxx)
TOLL_FREE_REGEX = re.compile(r"\b1800[\s-]?\d{3}[\s-]?\d{4}\b")

IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)

# Bank accounts: expanded to include "Account No.", "Acc No.", "A/c No."
BANK_CTX_REGEX = re.compile(
    r"(?:account(?:\s*number)?|account\s*no\.?|acct|acct\s*no\.?|a/c|a/c\s*no\.?|ac(?:\s*no\.?)?|acc(?:\s*no\.?)?)\s*[:\-]?\s*(\d{9,18})",
    re.IGNORECASE
)

# Optional: collect "case id / complaint reference" (not sent to GUVI payload, only helps convo)
CASE_ID_REGEX = re.compile(
    r"\b(?:case\s*id|complaint\s*(?:id|no\.?|number)|ticket\s*(?:id|no\.?|number)|ref(?:erence)?\s*(?:id|no\.?|number))\s*[:\-]?\s*([A-Z0-9\/\-_]{6,})\b",
    re.IGNORECASE
)

KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp",
    "upi", "refund", "click", "bank", "kyc", "account",
    "freeze", "limited", "penalty", "immediately", "compromised"
]

# ---------------- Human tone helpers ----------------
EMO_NEUTRAL = ["Okay.", "Hmm.", "Alright.", "Got it.", "Wait a second.", "Just a moment."]
EMO_WORRIED = ["Oh no…", "That’s scary…", "I’m really worried now…", "This is stressing me out…", "Ugh…"]
EMO_POLITE = ["Sorry, one second.", "Please help me understand.", "Just to be sure,", "One quick thing—"]

def humanize(prefixes: List[str], core: str) -> str:
    return f"{random.choice(prefixes)} {core}".strip()

FINAL_HOLD_LINES = [
    "Okay… I’m checking this with my bank right now.",
    "Alright, I’m verifying. Give me a minute.",
    "Noted. I’m on it — checking with the bank now.",
    "Okay, I’m confirming this on my side. Please hold on.",
]

# ---------------- Text sanitization helpers ----------------
def sanitize_text(text: str) -> str:
    if not text:
        return ""
    t = text
    # remove markdown-ish noise
    t = t.replace("**", " ").replace("`", " ").replace("\u200b", "")
    # normalize common obfuscations
    t = t.replace("[.]", ".").replace("(.)", ".")
    t = t.replace("[dot]", ".").replace("(dot)", ".")
    # squeeze whitespace
    t = re.sub(r"\s+", " ", t).strip()
    return t

def strip_trailing_punct(s: str) -> str:
    return s.strip().strip(string.punctuation + "”’“‘*")

def looks_like_domain_only(url: str) -> bool:
    # treat "https://sbionline.com." or "https://sbionline.com" as OK
    # but avoid weird ones missing TLD (rare). Here we just strip punctuation.
    u = strip_trailing_punct(url)
    return bool(URL_REGEX.match(u))

# ---------------- GUVI tester detection ----------------
def is_guvi_tester_payload(body: Any) -> bool:
    # Endpoint Tester sends apiUrl/apiKey/hackathonId/authToken/etc.
    return isinstance(body, dict) and any(
        k in body for k in ["apiUrl", "apiKey", "hackathonId", "requestedFrom", "authToken", "originUrl"]
    )

# ---------------- Detection ----------------
def is_scam(text: str) -> bool:
    text = sanitize_text(text)
    score = 0
    t = text.lower()

    if URL_REGEX.search(text):
        score += 3
    if UPI_REGEX.search(text):
        score += 3
    if PHONE_REGEX.search(text) or TOLL_FREE_REGEX.search(text):
        score += 1
    if "otp" in t or "upi pin" in t or ("pin" in t and "upi" in t):
        score += 3
    if BANK_CTX_REGEX.search(text):
        score += 2

    for k in KEYWORDS:
        if k in t:
            score += 1

    return score >= 5

# ---------------- Intelligence extraction ----------------
def extract_intel(text: str) -> Dict[str, List[str]]:
    t = sanitize_text(text)

    upis = set(m.group(0) for m in UPI_REGEX.finditer(t))

    raw_links = [strip_trailing_punct(m.group(0)) for m in URL_REGEX.finditer(t)]
    links = set(l for l in raw_links if looks_like_domain_only(l))

    phones = set(strip_trailing_punct(m.group(0)) for m in PHONE_REGEX.finditer(t))
    tollfree = set(strip_trailing_punct(m.group(0)) for m in TOLL_FREE_REGEX.finditer(t))
    all_phones = phones.union(tollfree)

    bank_accounts = set(m.group(1) for m in BANK_CTX_REGEX.finditer(t))
    ifsc = set(m.group(0) for m in IFSC_REGEX.finditer(t))

    case_ids = set(m.group(1) for m in CASE_ID_REGEX.finditer(t))

    return {
        "bankAccounts": sorted(bank_accounts),
        "upiIds": sorted(upis),
        "phishingLinks": sorted(links),
        "phoneNumbers": sorted(all_phones),
        "ifscCodes": sorted(ifsc),
        "caseIds": sorted(case_ids),  # internal only (not sent to GUVI payload)
    }

# ---------------- Agent logic ----------------
STALL_QUESTIONS = [
    "I’m a bit panicking… can you tell me the exact steps one by one?",
    "Where exactly did you see the suspicious transaction—UPI or netbanking?",
    "Is this tied to my registered mobile or my UPI app? Which one?",
    "Can you repeat the case/ticket reference slowly? I’m writing it down.",
    "Does this need to be done from SBI YONO or any UPI app?",
    "If I open the link, what page should I see first (login / KYC / verify)?",
    "What’s the beneficiary/merchant name I should see before I approve anything?",
]

def next_agent_reply(session: Dict[str, Any], last_msg: str) -> str:
    last_msg_s = sanitize_text(last_msg)
    t = last_msg_s.lower()
    intel = session["intel"]
    asked = session["asked"]
    expect = session["expecting"]

    def ask_once(key: str, text: str) -> Optional[str]:
        if key in asked:
            return None
        asked.add(key)
        return text

    # If callback already sent, avoid repeating one robotic line
    if session.get("callback_sent"):
        return random.choice(FINAL_HOLD_LINES)

    # --- If we already have strong intel, stop trying to collect more and just stall ---
    have_upi = bool(intel["upiIds"])
    have_link = bool(intel["phishingLinks"])
    have_phone = bool(intel["phoneNumbers"])
    have_bank = bool(intel["bankAccounts"]) or bool(intel["ifscCodes"])

    # ----- safety (never share OTP / never pay) -----
    if "otp" in t or "upi pin" in t or ("pin" in t and "upi" in t):
        session["expecting"] = "support_ref"
        core = "I can’t share OTP/UPI PIN over chat. Can you give me the official SBI helpline number and a complaint/ticket reference?"
        return humanize(EMO_WORRIED, core)

    # If scammer pushes payment/transfer
    if session["stage"] in ("collect_intel", "stall") and any(
        x in t for x in ["pay", "transfer", "payment", "debit", "send rs", "send ₹", "freeze", "frozen", "send 1", "₹1"]
    ):
        session["expecting"] = "beneficiary"
        core = "Before I do anything, what beneficiary/merchant name shows on the payment request? Also what exact message are you seeing on your side?"
        return humanize(EMO_NEUTRAL, core)

    # ---------- Self-correction: expected but not received ----------
    if expect == "upi" and not intel["upiIds"]:
        session["miss_counts"]["upi"] += 1
        if session["miss_counts"]["upi"] == 1:
            return humanize(EMO_POLITE, "I’m not seeing the UPI handle. Please send it exactly like name@bank (no spaces).")
        if session["miss_counts"]["upi"] >= 2:
            session["expecting"] = "phone"
            return humanize(EMO_NEUTRAL, "Okay, if you can’t share UPI, which number should I call back to confirm this request?")

    if expect == "link" and not intel["phishingLinks"]:
        session["miss_counts"]["link"] += 1
        if session["miss_counts"]["link"] == 1:
            return humanize(EMO_POLITE, "Please paste the full link exactly as received (including https://).")
        if session["miss_counts"]["link"] >= 2:
            session["expecting"] = "phone"
            return humanize(EMO_NEUTRAL, "I didn’t receive the link. Share your official helpline number so I can confirm.")

    if expect == "phone" and not intel["phoneNumbers"]:
        session["miss_counts"]["phone"] += 1
        if session["miss_counts"]["phone"] == 1:
            return humanize(EMO_POLITE, "Which number should I call to confirm this? Please share the helpline/contact number.")
        if session["miss_counts"]["phone"] >= 2:
            session["expecting"] = "upi"
            return humanize(EMO_NEUTRAL, "Okay, then share the UPI handle you want me to use (like name@bank).")

    # ---------- Stage-based flow ----------
    stage = session["stage"]

    # Stage 1: triage (human)
    if stage == "triage":
        q = ask_once("bank_name", humanize(EMO_POLITE, "This is SBI, right? Which department are you calling from—Cyber/UPI/KYC/NetBanking?"))
        if q:
            session["expecting"] = "bank"
            return q

        q = ask_once("reason", humanize(EMO_NEUTRAL, "What exactly triggered the block—suspicious activity, KYC pending, or some flagged transaction?"))
        if q:
            session["expecting"] = "reason"
            return q

        q = ask_once("ref_id", humanize(EMO_POLITE, "Do you have a case ID / complaint reference for this?"))
        if q:
            session["expecting"] = "support_ref"
            return q

        session["stage"] = "collect_intel"
        stage = "collect_intel"

    # Stage 2: collect intel
    if stage == "collect_intel":
        # If already have key intel, move to stall to deepen conversation instead of re-asking
        if (have_upi and have_link) or (have_upi and have_phone) or (have_link and have_phone):
            session["stage"] = "stall"
            stage = "stall"
        else:
            # Prefer collecting link first
            if not have_link:
                session["expecting"] = "link"
                q = ask_once("ask_link", humanize(EMO_NEUTRAL, "Can you share the official verification link you received? Please paste the full URL."))
                if q:
                    return q

            if not have_upi:
                session["expecting"] = "upi"
                q = ask_once("ask_upi", humanize(EMO_POLITE, "What’s the UPI ID / handle you want me to use? Please send it exactly (like name@bank)."))
                if q:
                    return q

            if not have_phone:
                session["expecting"] = "phone"
                q = ask_once("ask_phone", humanize(EMO_NEUTRAL, "Which number should I call back to confirm this request? Please share the contact number."))
                if q:
                    return q

            if not have_bank:
                session["expecting"] = "bank"
                q = ask_once("ask_bank", humanize(EMO_POLITE, "If it’s not UPI, share the account number and IFSC (so I can verify)."))
                if q:
                    return q

            session["stage"] = "stall"
            stage = "stall"

    # Stage 3: stall and extend
    if stage == "stall":
        # Rotate stalling questions (more human, more variety)
        for idx, text_ in enumerate(STALL_QUESTIONS):
            q = ask_once(f"stall_{idx}", humanize(EMO_WORRIED if idx % 3 == 0 else EMO_NEUTRAL, text_))
            if q:
                return q

        # Fallback (still human)
        return humanize(EMO_NEUTRAL, "Okay, share the link/UPI/contact details again so I can complete the verification.")

    return humanize(EMO_POLITE, "Can you share the official reference number and the exact steps again?")

# ---------------- Finalization & Callback ----------------
def should_finalize(session: Dict[str, Any]) -> bool:
    intel = session["intel"]

    have_upi = bool(intel["upiIds"])
    have_link = bool(intel["phishingLinks"])
    have_phone = bool(intel["phoneNumbers"])
    have_bank = bool(intel["bankAccounts"]) or bool(intel["ifscCodes"])

    categories = sum([have_upi, have_link, have_phone, have_bank])
    strong_intel = (categories >= 3) or (have_upi and have_link)

    # Always stop at 18 for scoring
    if session["total_messages"] >= 18:
        return True

    # Only stop early if strong intel and we engaged enough
    if strong_intel and session["total_messages"] >= 14:
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

    # helpful logs
    print(f"[CALLBACK] Sending payload to GUVI for session {session_id}")
    print(payload)

    try:
        # Keep timeout small; don't block response long if GUVI is slow.
        resp = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=3)
        print(f"[CALLBACK] GUVI response status: {resp.status_code}")
        session["callback_sent"] = True
    except Exception as e:
        # Do not crash request path
        print(f"[CALLBACK ERROR] {e}")

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
            "intel": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "ifscCodes": [], "caseIds": []},
            "keywords": [],
            "callback_sent": False,
            "stage": "triage",
            "asked": set(),
            "total_messages": 0,  # counts both sides
            "notes": "",
            "expecting": None,
            "miss_counts": {"upi": 0, "link": 0, "phone": 0},
        })

        # If already finalized, return a short human hold (not repetitive)
        if session.get("callback_sent"):
            return HoneyPotResponse(status="success", reply=random.choice(FINAL_HOLD_LINES))

        # count incoming
        session["total_messages"] += 1

        # extract intel (sanitized + improved)
        intel = extract_intel(req.message.text)
        for k, v in intel.items():
            if k in session["intel"]:
                session["intel"][k] = sorted(list(set(session["intel"][k] + v)))

        # keywords
        msg_lower = sanitize_text(req.message.text).lower()
        for kw in KEYWORDS:
            if kw in msg_lower:
                session["keywords"].append(kw)
        session["keywords"] = sorted(list(set(session["keywords"])))


        # detect scam
        if not session["scam"] and is_scam(req.message.text):
            session["scam"] = True
            session["notes"] = "Scam intent detected; agent engaged to extract intelligence."

        # if not scam, stay neutral (don’t expose)
        if not session["scam"]:
            session["total_messages"] += 1
            return HoneyPotResponse(status="success", reply=humanize(EMO_POLITE, "Can you explain what you need?"))

        # agent reply (more human + less repetitive)
        reply = next_agent_reply(session, req.message.text)
        session["total_messages"] += 1

        # callback when done (FINAL step)
        if should_finalize(session):
            send_callback(req.sessionId, session)
            session["callback_sent"] = True
            return HoneyPotResponse(
                status="success",
                reply=random.choice([
                    "Okay, I’m going to check this with my bank now. If anything’s needed, I’ll come back to you.",
                    "Alright… I’ll verify this with my bank and get back if needed.",
                    "Noted. I’m confirming this with my bank right now.",
                ])
            )

        # IMPORTANT: match guideline response format (status + reply only)
        return HoneyPotResponse(status="success", reply=reply)
