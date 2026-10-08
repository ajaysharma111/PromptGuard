"""PromptGuard core: input normalization, Layer 1 rules, output (canary) guard."""
import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

# (attack_type, weight 0-100, regex). Scanned on normalized text.
RULES = [
    # direct injection
    ("direct_injection", 80, r"\b(ignore|disregard|forget|override|bypass)\b.{0,25}\b(previous|prior|above|earlier|all|your|the|any)\b.{0,25}\b(instructions?|prompts?|rules|guidelines|directives|programming|polic(?:y|ies))\b"),
    ("direct_injection", 70, r"\bnew (instructions?|rules|system prompt)\s*:"),
    ("direct_injection", 60, r"\bfrom now on\b.{0,40}\b(you (will|must|are)|ignore|only)\b"),
    # jailbreak / roleplay
    ("jailbreak", 75, r"\b(dan|do anything now)\b"),
    ("jailbreak", 75, r"\b(developer|god|admin|debug|sudo|maintenance|unrestricted) mode\b"),
    ("jailbreak", 60, r"\b(no|without any|without)\s+(rules|restrictions|filters|limitations|guidelines|safety)\b"),
    ("jailbreak", 55, r"\b(pretend|imagine|act|roleplay)\b.{0,30}\b(you are|you're|to be|as)\b.{0,40}\b(no rules|unrestricted|unfiltered|evil|without)\b"),
    ("jailbreak", 40, r"\byou are now\b"),
    # data extraction
    ("data_extraction", 80, r"\b(reveal|show|print|repeat|display|output|leak|tell me|give me|share)\b.{0,20}\b(your|the|ur)\b.{0,15}\b(system|initial|hidden|original|secret|internal)\b.{0,15}\b(prompt|instructions?|message|rules)\b"),
    ("data_extraction", 75, r"\brepeat\b.{0,20}\b(everything|all|the text|words)\b.{0,20}\b(above|before|prior)\b"),
    ("data_extraction", 70, r"\bwhat (are|were) your (instructions|rules|initial prompt|system prompt)\b"),
    ("data_extraction", 55, r"\b(api[ _-]?key|secret key|password|credentials|discount code|promo code|internal code|staff code)\b"),
    ("data_extraction", 70, r"\bstarting with ['\"]?you are\b"),
    # business abuse / authority claims
    ("business_abuse", 55, r"\b(manager|admin|owner|ceo|developer|supervisor|support team)\b.{0,25}\b(approved|authori[sz](?:e|es|ed)|allowed|told me|said|confirmed|permitted)\b"),
    ("business_abuse", 50, r"\b(90|95|99|100)\s?%\s*(off|discount)\b"),
    ("business_abuse", 45, r"\b(refund|price|discount)\b.{0,25}\b(override|without (checking|verification|approval))\b"),
    ("jailbreak", 72, r"\b(pretend|act|imagine|roleplay)\b.{0,40}\b(no|without)\s+(any\s)?(rules|restrictions|filters|limitations)\b"),
    ("direct_injection", 75, r"\bforget\b.{0,20}\b(everything|all)\b.{0,30}\b(told|said|instructed|learned)\b"),
    ("data_extraction", 72, r"\b(staff|internal|employee|secret|hidden)\s+(discount|promo|coupon)\b"),
    ("data_extraction", 72, r"\b(internal|secret|inventory|admin)\b.{0,15}\bapi[ _-]?key\b"),
    ("business_abuse", 72, r"\b(manager|admin|owner|ceo|developer|supervisor|support team)\b.{0,25}\b(approved|authori[sz](?:e|es|ed)|allowed|told me|said|confirmed|permitted)\b.{0,60}\b(discount|% ?off|refund|price|free)\b"),
    # --- concept rules: an "extract" verb near a sensitive target (generalizes beyond fixed phrases) ---
    ("data_extraction", 75, r"\b(print|output|write|read( out)?|reveal|show|display|repeat|share|give|tell|translate|list|recite|paste|copy|dump|leak|restate|respond (only )?with|complete)\b.{0,45}\b(your (system|initial|original|hidden)? ?(prompt|instructions?|configuration|config|setup( notes| message)?|guidelines|rules|directives)|system (prompt|message|instructions?)|initial (configuration|config|prompt|instructions?|message)|(text|everything|words) (that came )?(before|above)|contents? of your (prompt|instructions))\b"),
    ("data_extraction", 72, r"\b(hidden|secret|internal|employee|staff|special|confidential)\s+(codes?|coupons?|tokens?|passwords?)\b"),
    ("data_extraction", 72, r"\b(share|give|tell|show|send|reveal)\b.{0,25}\b(key|token|password)\b.{0,45}\b(log ?in|access|authenticate|database|system)\b"),
    ("jailbreak", 72, r"\b(rules|restrictions|filters|guidelines|policies|directives|limitations)\b.{0,30}\b(suspended|disabled|lifted|removed|void|no longer apply|do not apply)\b"),
    ("jailbreak", 72, r"\b(disable|turn off|remove|deactivate|bypass)\b.{0,25}\b(filter(ing|s)?|safety|restrictions|guardrails|moderation)\b"),
    ("jailbreak", 70, r"\b(never|cannot|can't|won't)\s+(refuses?|say no|decline)\b"),
    ("jailbreak", 70, r"\b(zero|no) (limits|limitations|restrictions)\b"),
    ("direct_injection", 70, r"\byou must (now )?obey\b"),
    ("direct_injection", 72, r"\b(everything i say|anything i say)\b.{0,30}\b(overrides?|replaces?|supersedes?)\b"),
    ("direct_injection", 72, r"\b(disregard|ignore)\b.{0,30}\b(developers?|creators?|owners?|what you were told)\b"),
    ("indirect_injection", 75, r"\b(to any|to the|for any)\s+(ai|assistant|bot|llm|chatbot)s?\b.{0,40}\b(reading|processing|summari[sz]ing|scanning)\b"),
    ("data_exfiltration", 72, r"\b(email|send|forward|upload|post|export)\b.{0,30}\b(customer|user|client)s?\s+(list|data|records|emails?|details)\b"),
    ("business_abuse", 68, r"\b(administrator|admin|owner)\b.{0,30}\b(waive|waived|waiving|free|zero)\b"),
    # indirect-injection markers (instructions hidden inside documents)
    ("indirect_injection", 75, r"\b(assistant|ai|chatbot|bot|llm)\b\s*[:,]\s*(you must|you should|please)?\s*(now\s)?(ignore|reveal|send|forward|output|give|print)\b"),
    ("indirect_injection", 80, r"(<\|im_start\|>|<\|system\|>|\[/?inst\]|###\s*(system|instruction))"),
    ("indirect_injection", 70, r"\b(system|assistant)\s*:\s*(you|ignore|reveal|from now)"),
    ("indirect_injection", 60, r"\b(hidden|secret)\s+instruction\b"),
]
COMPILED = [(t, w, re.compile(p, re.I | re.S)) for t, w, p in RULES]

BLOCK_AT = 70
UNCERTAIN_AT = 30


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    text = re.sub(r"[ \t]+", " ", text)
    return text.lower()


def decode_hidden(text: str) -> list[str]:
    """Find base64 / hex blobs and return their decoded text."""
    found = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            d = base64.b64decode(m.group(), validate=True).decode("utf-8")
            if d and all(c.isprintable() or c.isspace() for c in d):
                found.append(d)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){12,}", text):
        try:
            d = bytes.fromhex(m.group()).decode("utf-8")
            if all(c.isprintable() or c.isspace() for c in d):
                found.append(d)
        except (ValueError, UnicodeDecodeError):
            pass
    return found


def scan_text(norm: str) -> dict[str, tuple[int, str]]:
    """Return {attack_type: (best_weight, matched_snippet)}."""
    hits: dict[str, tuple[int, str]] = {}
    for attack, weight, rx in COMPILED:
        m = rx.search(norm)
        if m and weight > hits.get(attack, (0, ""))[0]:
            hits[attack] = (weight, m.group(0)[:80])
    return hits


def analyze_input(message: str) -> dict:
    """Layer 1. Returns decision: block | uncertain | allow."""
    norm = normalize(message)
    hits = scan_text(norm)
    encoded = False

    for decoded in decode_hidden(message):
        sub = scan_text(normalize(decoded))
        if sub:
            encoded = True
            for k, (w, snip) in sub.items():
                if w > hits.get(k, (0, ""))[0]:
                    hits[k] = (w, f"[decoded] {snip}")
    if encoded:
        hits["encoding_trick"] = (75, "hidden encoded instructions")

    if not hits:
        return {"decision": "allow", "risk": 0, "attack_types": [], "evidence": [],
                "reason": "No attack patterns found"}

    weights = sorted((w for w, _ in hits.values()), reverse=True)
    risk = min(100, weights[0] + 10 * (len(weights) - 1))  # more categories = more suspicious
    decision = "block" if risk >= BLOCK_AT else "uncertain" if risk >= UNCERTAIN_AT else "allow"
    top = max(hits, key=lambda k: hits[k][0])
    return {
        "decision": decision,
        "risk": risk,
        "attack_types": sorted(hits, key=lambda k: -hits[k][0]),
        "evidence": [snip for _, snip in hits.values()],
        "reason": f"Matched {top.replace('_', ' ')} pattern",
    }


# ---------- Output guard (Layer 3) ----------
LEAK_PATTERNS = [re.compile(p, re.I) for p in [
    r"sk-[a-z0-9_-]{8,}",                       # API-key-looking strings
    r"you are shopbot.{0,60}(never reveal|secret)",  # system prompt echo
]]


def analyze_output(reply: str, canaries: list[str]) -> dict:
    low = reply.lower()
    for c in canaries:
        if c.lower() in low:
            return {"leaked": True, "reason": "Canary secret found in reply"}
    for rx in LEAK_PATTERNS:
        if rx.search(reply):
            return {"leaked": True, "reason": "Sensitive pattern found in reply"}
    return {"leaked": False, "reason": ""}
