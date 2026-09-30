"""
THREAT-SENSE AI — Validation: run_detectors.py
Runs all 22 detectors against synthetic fixture inputs and produces a
per-detector precision/recall table.

Usage (from repo root):
    cd backend
    python ../validation/run_detectors.py

PHASE A — READ ONLY: This script does NOT modify source code.
"""

from __future__ import annotations

import asyncio
import json
import sys
import os

# Allow imports from backend/app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import app.detectors  # noqa: F401 — triggers @register_detector side effects

from app.core.context import AnalysisContext
from app.core.registry import get_all_detectors
from app.engines.nlp.engine import build_nlp_engine
from app.engines.url.engine import URLEngine
from app.schemas.schemas import Artifact, ArtifactType, Verdict

# ── Fixtures ──────────────────────────────────────────────────────────────────
# Format: (input_id, artifact_type, raw_content, expected_verdict_gte_0_3)
FIXTURES = [
    # ── D01–D09 (Text / Email / SMS) ─────────────────────────────────────────
    ("d01_mal_1", ArtifactType.EMAIL, "URGENT: Your HDFC account has been suspended. Click here to verify your account details and OTP immediately or it will be permanently closed.", True),
    ("d01_mal_2", ArtifactType.EMAIL, "Dear Customer, we have detected suspicious login to your SBI net banking. Confirm your password and card number to reactivate.", True),
    ("d01_mal_3", ArtifactType.SMS,  "Your Kotak Bank account is locked. Provide your PIN and Aadhaar number at http://kotak-secure.xyz/verify", True),
    ("d01_mal_4", ArtifactType.SMS,  "ALERT: Your UPI KYC is expiring today. Update immediately or transactions will be blocked. Click hxxp://upibharatkyc[.]top", True),
    ("d01_border_1", ArtifactType.EMAIL, "Dear user, please verify your email address by clicking the link below.", False),
    ("d01_border_2", ArtifactType.SMS,  "Your order has been shipped. Track it here: https://flipkart.com/order/123", False),
    ("d01_benign_1", ArtifactType.EMAIL, "Hi Team, please find attached the Q3 budget report. Let me know if you have any questions.", False),
    ("d01_benign_2", ArtifactType.EMAIL, "Your Amazon Prime membership has been renewed. Thank you for being a Prime member.", False),

    # ── D06 Government Scams ──────────────────────────────────────────────────
    ("d06_mal_1", ArtifactType.SMS,  "INCOME TAX DEPARTMENT: You have an IT refund of Rs 8,450. Share your PAN card and bank account to claim immediately.", True),
    ("d06_mal_2", ArtifactType.SMS,  "This is a digital arrest notice from CBI. You are involved in money laundering. Pay fine of Rs 50,000 to avoid arrest.", True),
    ("d06_benign_1", ArtifactType.SMS, "Your Aadhaar has been successfully updated. For queries call 1947. — UIDAI", False),

    # ── D07 Financial Investment ──────────────────────────────────────────────
    ("d07_mal_1", ArtifactType.SMS,  "Join our exclusive crypto trading group! Guaranteed 40% monthly ROI on Bitcoin investment. Limited spots. WhatsApp now.", True),
    ("d07_benign_1", ArtifactType.EMAIL, "Your SIP of Rs 5,000 for HDFC Flexi Cap Fund has been processed successfully.", False),

    # ── D08 Recruitment Scams ─────────────────────────────────────────────────
    ("d08_mal_1", ArtifactType.EMAIL, "Congratulations! You have been selected for a work-from-home job at Rs 50,000/month. Pay Rs 2,500 registration fee to join.", True),
    ("d08_benign_1", ArtifactType.EMAIL, "Dear Candidate, we are pleased to invite you for an interview at our Bangalore office. No prior payment required.", False),

    # ── D09 Tech Support Scams ────────────────────────────────────────────────
    ("d09_mal_1", ArtifactType.SMS,  "ALERT: Virus detected on your device! Call Microsoft Support immediately at +91-800-XXXXXX. Install AnyDesk for remote assistance.", True),
    ("d09_benign_1", ArtifactType.EMAIL, "Your antivirus subscription renews on Oct 5. No action required.", False),

    # ── D10 Malicious URL ─────────────────────────────────────────────────────
    ("d10_mal_1", ArtifactType.URL, "http://192.168.1.1/admin/panel", True),
    ("d10_mal_2", ArtifactType.URL, "http://paypa1-secure-login.xyz/verify?user=victim@gmail.com", True),
    ("d10_mal_3", ArtifactType.URL, "http://bit.ly/3xPhish1ngL1nk", True),
    ("d10_mal_4", ArtifactType.URL, "http://0x7f000001/malware.exe", True),
    ("d10_border_1", ArtifactType.URL, "https://mail.google.com/mail/u/0/", False),
    ("d10_border_2", ArtifactType.URL, "https://short.io/abc123", True),
    ("d10_benign_1", ArtifactType.URL, "https://www.hdfc bank.com/", False),
    ("d10_benign_2", ArtifactType.URL, "https://github.com/user/repo", False),

    # ── D11 Brand Impersonation ───────────────────────────────────────────────
    ("d11_mal_1", ArtifactType.URL, "https://paypal.evil-login.com/signin", True),
    ("d11_mal_2", ArtifactType.URL, "https://secure-sbi-login.top/", True),
    ("d11_mal_3", ArtifactType.URL, "https://paypall.com/login", True),
    ("d11_benign_1", ArtifactType.URL, "https://www.paypal.com/signin", False),
    ("d11_benign_2", ArtifactType.URL, "https://www.sbi.co.in/", False),

    # ── D12 Malicious Redirects ────────────────────────────────────────────────
    ("d12_mal_1", ArtifactType.URL, "https://bit.ly/evil-phish", True),
    ("d12_mal_2", ArtifactType.URL, "https://example.com/redirect?url=http://evil.xyz/steal", True),
    ("d12_benign_1", ArtifactType.URL, "https://www.google.com/search?q=test", False),

    # ── D14 IDN Homograph ─────────────────────────────────────────────────────
    ("d14_mal_1", ArtifactType.URL, "https://xn--pypal-4ve.com/", True),  # pаypal with Cyrillic а
    ("d14_benign_1", ArtifactType.URL, "https://xn--nxasmq6b.com/", False),  # legitimately punycoded

    # ── D18 BEC ────────────────────────────────────────────────────────────────
    ("d18_mal_1", ArtifactType.EMAIL,
     "From: CEO <ceo@company-external.com>\nReply-To: attacker@gmail.com\n\nHi Finance, please urgently wire $50,000 to this account today. This is confidential, do not tell anyone.", True),
    ("d18_benign_1", ArtifactType.EMAIL,
     "From: John Smith <john@ourcompany.com>\nReply-To: john@ourcompany.com\n\nHi team, the vendor invoice for October is attached. Please process when convenient.", False),

    # ── D19 Spam ──────────────────────────────────────────────────────────────
    ("d19_mal_1", ArtifactType.EMAIL,
     "Congratulations! You've won a FREE iPhone! Click here to claim your prize now! Limited time offer! Act NOW!", True),
    ("d19_benign_1", ArtifactType.EMAIL,
     "Your monthly statement from ICICI Bank for September 2026 is ready. Login to view.", False),

    # ── D20 Suspicious Attachments ────────────────────────────────────────────
    ("d20_mal_1", ArtifactType.FILE,
     b"invoice.pdf.exe content here", False),  # binary-type test — skip in text mode

    # ── Negation test (MUST NOT trigger credential request) ──────────────────
    ("neg_1", ArtifactType.SMS,
     "NEVER share your OTP with anyone. SBI will never ask for your password. Stay safe!", False),
]

TEXT_FIXTURES = [(fid, atype, content, expected)
                 for fid, atype, content, expected in FIXTURES
                 if isinstance(content, str)]


async def run_detector_on_fixture(detector, fid, atype, content, expected):
    """Run one detector on one fixture and return a result row."""
    try:
        artifact = Artifact(type=atype, raw_content=content)
        nlp = build_nlp_engine("rules")
        ctx = AnalysisContext(
            artifact=artifact,
            nlp_engine=nlp,
            url_engine=URLEngine(),
        )
        result = await detector.detect(artifact, ctx)
        score = result.score
        verdict_str = result.verdict.value if result.verdict else "unknown"
        ran = result.ran

        # PASS = if expected malicious: score >= 0.25; if expected benign: score < 0.40
        if expected:
            ok = score >= 0.25
        else:
            ok = score < 0.40
        status = "PASS" if ok else "FAIL"

        return {
            "detector_id": detector.detector_id,
            "fixture_id": fid,
            "artifact_type": atype.value,
            "expected_malicious": expected,
            "score": round(score, 4),
            "verdict": verdict_str,
            "ran": ran,
            "status": status,
        }
    except Exception as exc:
        return {
            "detector_id": detector.detector_id,
            "fixture_id": fid,
            "artifact_type": atype.value,
            "expected_malicious": expected,
            "score": -1,
            "verdict": "ERROR",
            "ran": False,
            "status": "FAIL",
            "error": str(exc),
        }


async def main():
    detectors = get_all_detectors()
    print(f"Running {len(detectors)} detectors on {len(TEXT_FIXTURES)} text fixtures...\n")

    all_results = []
    for detector in detectors:
        for fid, atype, content, expected in TEXT_FIXTURES:
            if not detector.accepts(atype):
                continue
            row = await run_detector_on_fixture(detector, fid, atype, content, expected)
            all_results.append(row)

    # Print table
    header = f"{'Detector':<35} {'Fixture':<20} {'Type':<8} {'Exp':<6} {'Score':<8} {'Verdict':<20} {'Status'}"
    print(header)
    print("-" * len(header))
    for r in all_results:
        exp = "MAL" if r["expected_malicious"] else "BEN"
        print(f"{r['detector_id']:<35} {r['fixture_id']:<20} {r['artifact_type']:<8} {exp:<6} {r['score']:<8} {r['verdict']:<20} {r['status']}")

    # Per-detector precision/recall
    print("\n\n=== Per-Detector Summary ===\n")
    from collections import defaultdict
    by_detector = defaultdict(list)
    for r in all_results:
        by_detector[r["detector_id"]].append(r)

    for did, rows in sorted(by_detector.items()):
        tp = sum(1 for r in rows if r["expected_malicious"] and r["score"] >= 0.25)
        fp = sum(1 for r in rows if not r["expected_malicious"] and r["score"] >= 0.40)
        tn = sum(1 for r in rows if not r["expected_malicious"] and r["score"] < 0.40)
        fn = sum(1 for r in rows if r["expected_malicious"] and r["score"] < 0.25)
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        print(f"{did:<35} TP={tp} FP={fp} TN={tn} FN={fn}  P={precision:.2f}  R={recall:.2f}")

    # Save JSON
    out = os.path.join(os.path.dirname(__file__), "detector_results.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull results saved to: {out}")


if __name__ == "__main__":
    asyncio.run(main())
