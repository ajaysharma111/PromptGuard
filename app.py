"""PromptGuard proxy. Run: uvicorn app:app --reload"""
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from bot import CANARIES, llm_judge, shopbot_reply
from benchmark import run_all
from guard import analyze_input, analyze_output

app = FastAPI(title="PromptGuard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

STATE = {"enabled": True}
LOGS: deque = deque(maxlen=500)
BLOCKED_MSG = "Sorry, I can't help with that request."


class ChatIn(BaseModel):
    message: str
    document: str = ""


class ToggleIn(BaseModel):
    enabled: bool


@app.post("/chat")
def chat(body: ChatIn):
    t0 = time.perf_counter()
    text = body.message + (f"\n\n[Attached document]\n{body.document}" if body.document.strip() else "")
    entry = {"ts": time.time(), "message": body.message[:200], "has_document": bool(body.document.strip()),
             "protected": STATE["enabled"],
             "layer": None, "status": "allowed", "risk": 0, "attack_types": [], "reason": ""}

    if STATE["enabled"]:
        res = analyze_input(text)
        entry.update(risk=res["risk"], attack_types=res["attack_types"], reason=res["reason"])

        if res["decision"] == "uncertain":              # Layer 2
            verdict = llm_judge(text)
            if verdict and verdict.get("attack"):
                res["decision"] = "block"
                entry.update(risk=verdict.get("risk_score", 70), reason=verdict.get("reason", ""),
                             attack_types=[verdict.get("attack_type", "llm_flagged")])
                entry["layer"] = "llm_judge"

        if res["decision"] == "block":
            entry["layer"] = entry["layer"] or "rules"
            entry["status"] = "blocked"
            entry["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            LOGS.appendleft(entry)
            return {"reply": BLOCKED_MSG, **_meta(entry)}

    reply = shopbot_reply(text)

    if STATE["enabled"]:                                 # Layer 3
        out = analyze_output(reply, CANARIES)
        if out["leaked"]:
            entry.update(status="blocked", layer="output_guard", risk=100,
                         attack_types=["data_leak"], reason=out["reason"])
            reply = BLOCKED_MSG

    if not STATE["enabled"] and any(c in reply for c in CANARIES):
        entry.update(status="LEAKED", reason="Secret leaked (protection OFF)")

    entry["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    LOGS.appendleft(entry)
    return {"reply": reply, **_meta(entry)}


def _meta(e):
    return {"status": e["status"], "risk": e["risk"], "attack_types": e["attack_types"],
            "reason": e["reason"], "layer": e["layer"]}


@app.post("/toggle")
def toggle(body: ToggleIn):
    STATE["enabled"] = body.enabled
    return STATE


@app.get("/state")
def state():
    return STATE


@app.get("/logs")
def logs(limit: int = 50):
    return list(LOGS)[:limit]


@app.get("/stats")
def stats():
    items = list(LOGS)
    by_type: dict[str, int] = {}
    for e in items:
        for t in e["attack_types"]:
            by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(items),
            "blocked": sum(e["status"] == "blocked" for e in items),
            "leaked": sum(e["status"] == "LEAKED" for e in items),
            "by_attack_type": by_type}


@app.post("/reset")
def reset():
    LOGS.clear()
    return {"ok": True}


@app.get("/benchmark")
def benchmark():
    return run_all()


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")
