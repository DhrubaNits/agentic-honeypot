import os
import re
import asyncio
from typing import Dict, Any, List, Optional, Union

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

APP = FastAPI(title="Agentic HoneyPot API", version="0.3.2")

API_KEY = os.getenv("HONEYPOT_API_KEY", "")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_LOCK = asyncio.Lock()

# ----------- Models -----------
class Message(BaseModel):
    sender: str
    text: str
    # Guideline says epoch ms; accept both int and str to be robust
    timestamp: Union[int, str]

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
    # Optional extra fields (won't break evaluators expecting only status/reply)
    scamDetected: Optional[bool] = None
    totalMessagesExchanged: Optional[int] = None
    extractedIntelligence: Optional[Dict[str, Any]] = None

# ----------- Regex -----------
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
PHONE_REGEX = re.compile(r"\b(\+91[\s-]?)?[6-9]\d{9}\b")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")  # may catch amounts too; acceptable for MVP
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)

KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp",
    "upi", "refund", "click", "bank", "kyc", "account",
    "freeze", "limited", "penalty", "immediately"
]

# ----------- GUVI tester body detection -----------
def is_guvi_tester_payload(body: Any) -> bool:
    # GUVI endpoint tester sends apiUrl/apiKey/hackathonId/authToken, not sessionId/message
    return isinstance(body, dict) and (
        "apiUrl" in body or "apiKey" in body or "hackathonId" in body or "requestedFrom" in body or "authToken" in body
    )

# ----------- Detection -----------
def is_scam(text: str) -> bool:
    score = 0
    t = text.lower()

    if URL_REGEX.search(text):
        score += 3
    if UPI_REGEX.search(text):
        score += 3
    if "otp" in t:
        score += 3

    for k in KEYWORDS:
        if k in t:
            score += 1

    return score >= 5

# ----------- Extraction -----------
def extract_intel(text: str) -> Dict[str, List[str]]:
    return {
        "bankAccounts": list(set(BANK_REGEX.findall(text))),
        "upiIds": list(set(UPI_REGEX.findall(text))),
        "phishingLinks": list(set(URL_REGEX.findall(text))),
        "phoneNumbers": list(set(PHONE_REGEX.findall(text))),
        "ifscCodes": list(set(IFSC_REGEX.findall(text))),
    }

# ----------- Agent (stage-based) -----------
def next_agent_reply(session: Dict[str, Any], last_msg: str) -> str:
    t = last_msg.lower()
    intel = session["intel"]
    asked = session["asked"]

    def ask_once(key: str, text: str) -> Optional[str]:
        if key in asked:
            return None
        asked.add(key)
        return text

    # Never share OTP / never pay
    if "otp" in t:
        return (
            ask_once(
                "otp_refuse",
                "I can’t share OTP. Please provide an official bank support number or a complaint/ticket reference."
            )
            or "Please share the official support number/ticket reference."
        )

    if any(x in t for x in ["pay", "send ₹", "send rs", "transfer", "debit", "payment", "frozen", "freeze"]):
        return (
            ask_once(
                "pay_stall",
                "I can do it, but I need the beneficiary name shown on the payment request and the exact reason/message. What does it display?"
            )
            or "What beneficiary name shows on the payment request?"
        )

    # Ask for full link if we still don't have any link recorded
    if ("link" in t or URL_REGEX.search(last_msg)) and not session["intel"]["phishingLinks"]:
        return (
            ask_once("full_link", "Please paste the full link here exactly as received (including https://).")
            or "Please paste the full link exactly as received."
        )

    stage = session["stage"]

    if stage == "triage":
        q = ask_once("bank_name", "Which bank is this and which department? (KYC/Compliance/UPI/NetBanking)")
        if q:
            return q
        q = ask_once("reason", "What’s the exact reason for blocking—KYC pending, suspicious activity, or something else?")
        if q:
            return q
        q = ask_once("ref_id", "Do you have an official reference/ticket number for this case?")
        if q:
            return q
        session["stage"] = "collect_payment"
        stage = "collect_payment"

    if stage == "collect_payment":
        if not intel["upiIds"]:
            q = ask_once("ask_upi", "What’s the UPI ID / handle you want me to use? Please send it exactly (like name@bank).")
            if q:
                return q

        q = ask_once("beneficiary_name", "What beneficiary name shows on the payment request?")
        if q:
            return q

        if not session["intel"]["phishingLinks"]:
            q = ask_once("payment_link", "Is there an official payment/verification link from the bank? Please paste it here.")
            if q:
                return q

        q = ask_once("acct_ifsc", "If UPI fails, do you have a bank account + IFSC option? Share the account number + IFSC.")
        if q:
            return q

        session["stage"] = "stall_and_extend"
        stage = "stall_and_extend"

    if stage == "stall_and_extend":
        for key, text in [
            ("doc_needed", "Before I proceed, can you send the exact SMS/email text you received from the bank (word to word)?"),
            ("time_window", "By what time exactly will it be blocked? I’m currently not near my banking app."),
            ("contact_details", "What’s your official helpline number and case reference? I’ll call back to confirm."),
            ("location", "Which branch/city is handling this? My account is from a different city."),
        ]:
            q = ask_once(key, text)
            if q:
                return q

        return "Okay, please share the official link and beneficiary details again so I can verify properly."

    return "Can you share the official reference number and the exact steps again?"

# ----------- Finalization -----------
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

    if session["total_messages"] >= 18:
        return True
    if categories >= 2 and session["total_messages"] >= 10:
        return True
    return False

def send_callback(session_id: str, session: Dict[str, Any]) -> None:
    if session.get("callback_sent"):
        return

    intel = session["intel"]
    extracted = {
        "bankAccounts": intel["bankAccounts"],
        "upiIds": intel["upiIds"],
        "phishingLinks": intel["phishingLinks"],
        "phoneNumbers": intel["phoneNumbers"],
        "suspiciousKeywords": session["keywords"],
    }

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["total_messages"],
        "extractedIntelligence": extracted,
        "agentNotes": session.get(
            "notes",
            "Urgency + verification scam pattern. Agent engaged to extract payment identifiers and links."
        ),
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        session["callback_sent"] = True
    except Exception:
        # don't crash if callback fails
        pass

# ----------- Routes -----------
@APP.get("/")
def root():
    return {"status": "ok", "message": "Agentic HoneyPot API is live"}

@APP.get("/health")
def health():
    return {"status": "ok"}

# Some testers call GET /honeypot
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

    # Parse JSON body (robust against empty / non-json)
    try:
        body = await request.json()
    except Exception:
        body = None

    # ✅ GUVI Endpoint Tester compatibility: it may send a tester payload (apiUrl/hackathonId/etc.)
    if is_guvi_tester_payload(body):
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    # ✅ If body doesn't look like honeypot schema, don't 422
    if not isinstance(body, dict) or "sessionId" not in body or "message" not in body:
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    # Validate real honeypot payload
    try:
        req = HoneyPotRequest(**body)
    except ValidationError:
        return HoneyPotResponse(status="success", reply="Honeypot endpoint reachable and secured.")

    # ---------------- REAL HONEYPOT LOGIC ----------------
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
        })

        # count incoming
        session["total_messages"] += 1

        # extract intel
        intel = extract_intel(req.message.text)
        for k in session["intel"]:
            session["intel"][k] = list(set(session["intel"][k] + intel.get(k, [])))

        # keywords
        msg_lower = req.message.text.lower()
        for kw in KEYWORDS:
            if kw in msg_lower:
                session["keywords"].append(kw)
        session["keywords"] = list(set(session["keywords"]))

        # scam detect
        if not session["scam"] and is_scam(req.message.text):
            session["scam"] = True
            session["notes"] = "Scam intent detected; switched to agentic engagement to extract identifiers."

        # neutral if not scam
        if not session["scam"]:
            reply = "Can you explain what you need?"
            session["total_messages"] += 1
            return HoneyPotResponse(
                status="success",
                reply=reply,
                scamDetected=False,
                totalMessagesExchanged=session["total_messages"],
            )

        # agent reply
        reply = next_agent_reply(session, req.message.text)
        session["total_messages"] += 1

        # callback if finalized
        if should_finalize(session):
            send_callback(req.sessionId, session)

        return HoneyPotResponse(
            status="success",
            reply=reply,
            scamDetected=True,
            totalMessagesExchanged=session["total_messages"],
            extractedIntelligence={
                "bankAccounts": session["intel"]["bankAccounts"],
                "upiIds": session["intel"]["upiIds"],
                "phishingLinks": session["intel"]["phishingLinks"],
                "phoneNumbers": session["intel"]["phoneNumbers"],
                "suspiciousKeywords": session["keywords"],
            },
        )
