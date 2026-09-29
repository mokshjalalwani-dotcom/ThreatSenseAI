"""
RulesBackend — deterministic lexicon + regex NLP signal scorer.

Design principles:
  - Zero network calls, zero ML models; works fully offline.
  - All signal scores are in [0, 1].
  - Each signal has its own keyword set + regex patterns.
  - Evidence spans are populated so detectors can show highlighted text.
  - Caching: compiled regexes are module-level constants.

Signal coverage:
  urgency, fear, authority, reward_scarcity, financial_intent,
  credential_request, manipulation, phishing_intent, scam_intent,
  investment_context, recruitment_context, tech_support_context,
  government_service_claim, payment_request, remote_access_request
"""

from __future__ import annotations

import re

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import EvidenceSpan, NLPSignals

# ── Lexicon helpers ────────────────────────────────────────────────────────────

def _kw(*words: str) -> re.Pattern[str]:
    """Compile a case-insensitive whole-word alternation pattern."""
    escaped = [re.escape(w) for w in words]
    return re.compile(r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE)


def _phrase(*phrases: str) -> re.Pattern[str]:
    """Compile a case-insensitive phrase alternation (no word boundary needed)."""
    escaped = [re.escape(p) for p in phrases]
    return re.compile("|".join(escaped), re.IGNORECASE)


# ── Signal patterns ────────────────────────────────────────────────────────────

_URGENCY_KW = _kw(
    "urgent", "immediately", "asap", "right now", "now", "today",
    "deadline", "expir", "expire", "expires", "expired", "expiration",
    "last chance", "final notice", "24 hours", "48 hours", "within hours",
    "act now", "do not delay", "respond immediately", "time sensitive",
    "limited time", "account suspended", "suspended", "terminated",
    "will be closed", "closing soon", "deactivated", "locked",
)

_FEAR_KW = _kw(
    "warning", "alert", "danger", "risk", "threat", "violation",
    "unauthorized access", "suspicious activity", "fraud detected",
    "security breach", "hacked", "compromised", "infected", "malware",
    "virus", "criminal", "legal action", "lawsuit", "arrested",
    "police", "cyber crime", "penalty", "fine", "reported",
    "blocked", "restricted", "banned", "terminated", "permanently closed",
)

_AUTHORITY_KW = _kw(
    "government", "official", "ministry", "department", "rbi", "sebi",
    "trai", "npci", "irdai", "uidai", "epfo", "esic", "income tax",
    "irs", "fbi", "interpol", "cbi", "ed", "enforcement",
    "bank", "reserve bank", "regulator", "regulatory", "authority",
    "court", "tribunal", "judiciary", "legal", "law enforcement",
    "police", "customs", "passport",
)

_REWARD_KW = _kw(
    "winner", "won", "prize", "reward", "lottery", "jackpot",
    "selected", "chosen", "congratulations", "congratulation",
    "free", "gift", "cashback", "refund", "rebate",
    "bonus", "offer", "exclusive", "limited offer", "claim now",
    "cash prize", "lucky draw", "sweepstake", "giveaway",
    "promo", "promotion", "discount", "voucher",
)

_FINANCIAL_KW = _kw(
    "pay", "payment", "transfer", "wire transfer", "bank transfer",
    "debit", "credit", "invoice", "bill", "amount due", "outstanding",
    "wallet", "upi", "neft", "rtgs", "imps", "bitcoin", "crypto",
    "cryptocurrency", "wallet address", "investment", "returns",
    "profit", "interest", "loan", "emi",
)

_CREDENTIAL_KW = _kw(
    "password", "passcode", "pin", "otp", "one time password",
    "verify", "verification code", "enter your", "provide your",
    "submit your", "confirm your", "update your",
    "username", "user name", "login", "log in", "sign in",
    "account number", "card number", "cvv", "expiry date",
    "aadhaar", "aadhar", "pan card", "ssn", "social security",
    "date of birth", "dob", "mother's maiden", "secret question",
)

_MANIPULATION_KW = _kw(
    "do not tell", "keep this confidential", "do not share",
    "trust us", "100% safe", "100% secure", "guaranteed",
    "no questions asked", "private and confidential", "secret",
    "between us", "only you", "special offer just for you",
    "you have been specially selected", "exclusively for you",
)

_PHISHING_PHRASES = _phrase(
    "click here to verify", "verify your account", "confirm your account",
    "update your information", "update your details", "update billing",
    "your account has been", "we have detected", "unusual activity",
    "log in to secure", "link below to", "follow the link",
    "click the link", "click below", "click here to",
    "your account will be", "reactivate your account",
)

_SCAM_PHRASES = _phrase(
    "send money", "need your help", "i need a favour",
    "business proposal", "share profits", "million dollars",
    "transfer funds", "help me transfer", "unclaimed funds",
    "you are the beneficiary", "next of kin", "inheritance",
    "advance fee", "processing fee", "release fee",
    "customs fee", "clearance fee",
)

_INVESTMENT_KW = _kw(
    "invest", "investment", "roi", "returns", "high returns",
    "guaranteed returns", "double your money", "trading",
    "forex", "stock market", "mutual fund", "sip", "ipo",
    "cryptocurrency", "bitcoin", "ethereum", "nft",
    "defi", "staking", "yield", "profit", "portfolio",
    "financial freedom", "passive income",
)

_RECRUITMENT_KW = _kw(
    "job offer", "job opportunity", "hiring", "work from home",
    "remote job", "earn from home", "part time job",
    "salary", "package", "lpa", "per month", "weekly pay",
    "recruiter", "hr manager", "interview", "shortlisted",
    "selected for interview", "employment", "vacancy",
    "apply now", "urgent hiring", "immediate joining",
)

_TECH_SUPPORT_KW = _kw(
    "tech support", "technical support", "customer support",
    "helpline", "toll free", "call us", "call now", "contact us",
    "remote access", "teamviewer", "anydesk", "screen sharing",
    "virus detected", "computer infected", "windows support",
    "microsoft support", "apple support", "google support",
    "device compromised", "scan your device", "fix your pc",
)

_GOVT_PHRASES = _phrase(
    "income tax department", "income tax refund", "it refund",
    "pan card update", "aadhaar update", "aadhaar linking",
    "epfo withdrawal", "pf withdrawal", "lic policy",
    "driving licence", "vehicle registration", "traffic violation",
    "electricity bill", "gas connection", "municipal corporation",
    "ministry of finance", "ministry of home", "prime minister",
    "government scheme", "pm scheme", "pradhan mantri",
    "covid certificate", "vaccination certificate",
    "irs refund", "tax return", "stimulus check",
)

_PAYMENT_REQUEST_KW = _kw(
    "pay now", "make payment", "complete payment", "payment required",
    "send payment", "transfer to", "pay via", "scan qr",
    "use this upi", "upi id", "account details below",
    "pay the amount", "immediate payment", "payment pending",
)

_REMOTE_ACCESS_KW = _kw(
    "download this app", "install this software", "install anydesk",
    "install teamviewer", "share your screen", "give access",
    "remote assistance", "we will connect", "technician will",
    "engineer will call", "give control",
)

# Government org extraction pattern
_GOVT_ORG_RE = re.compile(
    r"\b(rbi|sebi|uidai|epfo|irdai|trai|npci|irs|fbi|cbi|income tax|lic"
    r"|reserve bank of india|ministry of \w+)\b",
    re.IGNORECASE,
)


# ── Signal scorer ──────────────────────────────────────────────────────────────

def _score(text: str, pattern: re.Pattern[str], cap: float = 1.0) -> tuple[float, list[EvidenceSpan]]:
    """Count matches and return a capped score + evidence spans."""
    matches = list(pattern.finditer(text))
    if not matches:
        return 0.0, []
    # Sigmoid-like: each additional match gives diminishing returns
    raw = min(len(matches) * 0.25, cap)
    spans = [
        EvidenceSpan(
            signal=pattern.pattern[:40],
            matched_text=m.group(0),
            char_start=m.start(),
            char_end=m.end(),
        )
        for m in matches[:6]   # cap to 6 spans per signal
    ]
    return round(raw, 4), spans


class RulesBackend(SignalBackend):
    """Fully deterministic lexicon/regex signal scorer.

    Runs in < 1 ms even on long emails.  No external dependencies.
    """

    @property
    def backend_name(self) -> str:
        return "rules"

    async def analyze(self, text: str) -> NLPSignals:
        if not text:
            return NLPSignals(backend_used="rules", text_length=0)

        text_len = len(text)
        all_spans: list[EvidenceSpan] = []

        def _s(pat: re.Pattern[str], cap: float = 1.0) -> float:
            score, spans = _score(text, pat, cap)
            all_spans.extend(spans)
            return score

        urgency           = _s(_URGENCY_KW)
        fear              = _s(_FEAR_KW)
        authority         = _s(_AUTHORITY_KW)
        reward_scarcity   = _s(_REWARD_KW)
        financial_intent  = _s(_FINANCIAL_KW)
        credential_request = _s(_CREDENTIAL_KW)
        manipulation      = _s(_MANIPULATION_KW)
        phishing_intent   = max(_s(_PHISHING_PHRASES), (urgency + credential_request) / 2)
        scam_intent       = max(_s(_SCAM_PHRASES), (fear + reward_scarcity) / 2)
        investment_ctx    = _s(_INVESTMENT_KW)
        recruitment_ctx   = _s(_RECRUITMENT_KW)
        tech_support_ctx  = _s(_TECH_SUPPORT_KW)
        govt_claim        = _s(_GOVT_PHRASES)
        payment_req       = _s(_PAYMENT_REQUEST_KW)
        remote_access     = _s(_REMOTE_ACCESS_KW)

        # Extract claimed org name when govt signal is high
        claimed_org: str | None = None
        if govt_claim >= 0.25:
            m = _GOVT_ORG_RE.search(text)
            if m:
                claimed_org = m.group(0).upper()

        return NLPSignals(
            urgency=min(1.0, urgency),
            fear=min(1.0, fear),
            authority=min(1.0, authority),
            reward_scarcity=min(1.0, reward_scarcity),
            financial_intent=min(1.0, financial_intent),
            credential_request=min(1.0, credential_request),
            manipulation=min(1.0, manipulation),
            phishing_intent=min(1.0, phishing_intent),
            scam_intent=min(1.0, scam_intent),
            investment_context=min(1.0, investment_ctx),
            recruitment_context=min(1.0, recruitment_ctx),
            tech_support_context=min(1.0, tech_support_ctx),
            government_service_claim=min(1.0, govt_claim),
            claimed_org=claimed_org,
            payment_request=min(1.0, payment_req),
            remote_access_request=min(1.0, remote_access),
            evidence_spans=all_spans[:50],
            backend_used="rules",
            text_length=text_len,
        )
