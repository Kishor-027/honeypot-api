from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict
import re
import time

app = FastAPI(
    title="Honeypot Scam Detection API",
    description="Detects scam messages and extracts suspicious data",
    version="1.1"
)

API_KEY = "test123"

# ---------------- Models ----------------

class Message(BaseModel):
    sender: str = "unknown"
    text: str = ""
    timestamp: str = ""

class RequestBody(BaseModel):
    message: Optional[Message] = None
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Dict] = {}

# ---------------- Utils ----------------

SCAM_KEYWORDS = [
    "blocked", "verify", "urgent", "suspend",
    "upi", "account", "click", "link", "refund", "otp"
]

def is_scam(text: str) -> bool:
    text = text.lower()
    return any(keyword in text for keyword in SCAM_KEYWORDS)

def extract_upi(text: str):
    return re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text)

def extract_accounts(text: str):
    return re.findall(r"\b\d{9,18}\b", text)

def extract_links(text: str):
    return re.findall(r"https?://\S+", text)

# ---------------- Routes ----------------

@app.get("/")
def root():
    return {
        "message": "Honeypot API is running",
        "status": "OK"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

# 👇 IMPORTANT: Handle GET / HEAD (GUVI checks this)
@app.get("/api/honeypot")
@app.head("/api/honeypot")
def honeypot_ping():
    return {
        "status": "ready",
        "message": "Honeypot endpoint reachable"
    }

# 👇 MAIN POST ENDPOINT
@app.post("/api/honeypot")
async def honeypot(
    request: Request,
    data: Optional[RequestBody] = None,
    x_api_key: Optional[str] = Header(None)
):
    # API key check
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key missing")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

    start_time = time.time()

    text = ""
    if data and data.message and data.message.text:
        text = data.message.text

    scam_detected = is_scam(text)
    upi_ids = extract_upi(text)
    bank_accounts = extract_accounts(text)
    links = extract_links(text)

    duration = round(time.time() - start_time, 3)

    return {
        "status": "success",
        "scamDetected": scam_detected,
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": len(data.conversationHistory) + 1 if data else 1
        },
        "extractedIntelligence": {
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phishingLinks": links
        },
        "agentNotes": (
            "Urgency-based scam language detected"
            if scam_detected else
            "No major scam indicators found"
        )
    }
# ---------------- Run Server ----------------