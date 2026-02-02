import os
import re
import asyncio
from typing import Dict, Any, List, Optional

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP = FastAPI(title="Agentic HoneyPot API")

API_KEY = os.getenv("HONEYPOT_API_KEY", "")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_LOCK = asyncio.Lock()

# ----------- Models -----------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

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

# ----------- Regex -----------
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
PHONE_REGEX = re.compile(r"\b(\+91[\s-]?)?[6-9]\d{9}\b")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")

KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp",
    "upi", "refund", "click", "bank", "kyc"
]

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

def extract_intel(text: str) -> Dict[str, List[str]]:
    return {
        "bankAccounts": list(set(BANK_REGEX.findall(text))),
        "upiIds": list(set(UPI_REGEX.findall(text))),
        "phishingLinks": list(set(URL_REGEX.findall(text))),
        "phoneNumbers": list(set(PHONE_REGEX.findall(text))),
    }

def agent_reply(turns: int, last_msg: str) -> str:
    t = last_msg.lower()

    if "upi" in t:
        return "Okay, can you share the exact UPI handle or payment page link?"
    if "link" in t or "click" in t:
        return "Please send the full link here so I can open it."
    if "otp" in t:
        return "I’m not sure about OTP. Can you share official support details?"

    if turns < 4:
        return "Why is my account being blocked? Which bank is this?"
    if turns < 10:
        return "What are the steps to resolve this today?"
    return "Before proceeding, please share the official link and beneficiary details."

def should_finalize(session: Dict[str, Any]) -> bool:
    intel = session["intel"]
    if session["turns"] >= 18:
        return True
    if any(intel[k] for k in intel) and session["turns"] >= 6:
        return True
    return False

def send_callback(session_id: str, session: Dict[str, Any]) -> None:
    if session.get("callback_sent"):
        return

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session["turns"],
        "extractedIntelligence": {
            **session["intel"],
            "suspiciousKeywords": session["keywords"],
        },
        "agentNotes": "Urgency and verification scam pattern detected",
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        session["callback_sent"] = True
    except Exception:
        # Do not crash API if callback fails
        pass

@APP.get("/health")
def health():
    return {"status": "ok"}

@APP.post("/honeypot", response_model=HoneyPotResponse)
async def honeypot(req: HoneyPotRequest, x_api_key: str = Header(default="")):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server misconfigured: API key missing")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    async with SESSION_LOCK:
        session = SESSIONS.setdefault(req.sessionId, {
            "turns": 0,
            "scam": False,
            "intel": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": []},
            "keywords": [],
            "callback_sent": False,
        })

        session["turns"] += 1

        # Extract intelligence from latest message
        intel = extract_intel(req.message.text)
        for k in session["intel"]:
            session["intel"][k] = list(set(session["intel"][k] + intel[k]))

        # Track suspicious keywords
        t = req.message.text.lower()
        for kw in KEYWORDS:
            if kw in t:
                session["keywords"].append(kw)
        session["keywords"] = list(set(session["keywords"]))

        # Detect scam
        if not session["scam"] and is_scam(req.message.text):
            session["scam"] = True

        reply = agent_reply(session["turns"], req.message.text)

        # Count agent reply as another exchanged message (for scoring)
        session["turns"] += 1

        # Final callback if done
        if session["scam"] and should_finalize(session):
            send_callback(req.sessionId, session)

    return HoneyPotResponse(status="success", reply=reply)
