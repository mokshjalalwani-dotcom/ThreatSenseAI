"""
Full validation suite — tests every artifact type against true/false examples.
Text types (url/email/sms/webpage) are sent as JSON body.
Binary types (image/qr/file) are sent as multipart.
"""
import json, sys
import requests

BASE = "http://127.0.0.1:8000"

def c(text, code): return f"\033[{code}m{text}\033[0m"
PASS = c("PASS", 92)
FAIL = c("FAIL", 91)

CASES = [
    # (label, type, relpath, expected_verdicts, is_binary)
    ("Safe URL",        "url",     "true/1_safe_url.txt",          {"safe"},                                        False),
    ("Malicious URL",   "url",     "false/1_malicious_url.txt",    {"malicious","likely_malicious","suspicious"},    False),
    ("Benign email",    "email",   "true/2_benign_email.eml",      {"safe"},                                        False),
    ("Phishing email",  "email",   "false/2_phishing_email.eml",   {"malicious","likely_malicious","suspicious"},    False),
    ("Safe SMS",        "sms",     "true/3_safe_sms.txt",          {"safe"},                                        False),
    ("Smishing SMS",    "sms",     "false/3_smishing_sms.txt",     {"malicious","likely_malicious","suspicious"},    False),
    ("Safe webpage",    "webpage", "true/4_safe_webpage.html",     {"safe"},                                        False),
    ("Fake login page", "webpage", "false/4_fake_login_webpage.html", {"malicious","likely_malicious","suspicious"}, False),
    ("Safe file",       "file",    "true/5_safe_file.txt",         {"safe"},                                        True),
    ("Malicious bat",   "file",    "false/5_suspicious_file.bat",  {"malicious","likely_malicious","suspicious"},    True),
]

results = []
all_pass = True

for label, atype, relpath, expected, is_binary in CASES:
    path = f"../examples/{relpath}"
    try:
        with open(path, "rb") as f:
            raw = f.read()

        if is_binary:
            fname = relpath.split("/")[-1]
            mime  = "application/octet-stream"
            resp  = requests.post(
                BASE + "/analyze",
                data={"type": atype},
                files={"file": (fname, raw, mime)},
                timeout=15,
            )
        else:
            # Text artifact: send as JSON body
            text = raw.decode("utf-8", errors="replace").strip()
            resp = requests.post(
                BASE + "/analyze",
                json={"type": atype, "raw_content": text},
                timeout=15,
            )

        if resp.status_code != 200:
            print(f"[{FAIL}] {label}: HTTP {resp.status_code} — {resp.text[:300]}")
            all_pass = False
            results.append({"label": label, "pass": False, "error": resp.text[:200]})
            continue

        r = resp.json()
        verdict = r.get("verdict", "?")
        score   = r.get("risk_score", 0)
        conf    = r.get("confidence", 0)
        ok      = verdict in expected
        tag     = PASS if ok else FAIL
        if not ok:
            all_pass = False

        print(f"[{tag}] {label:22s}  verdict={verdict:22s} score={score:5.1f}  conf={conf:.0%}")

        # Show evidence detail when failing
        if not ok:
            print(f"       Expected one of: {expected}")
            print(f"       Top evidence:")
            for ev in r.get("top_evidence", [])[:5]:
                print(f"         [{ev['severity'].upper():8s}] {ev['description']}")
            print(f"       Domain scores:")
            for d in r.get("per_domain_scores", []):
                print(f"         {d['domain_id']} = {d['score']:.3f}  ({d['detectors_ran']}/{d['detector_count']} detectors ran)")

        results.append({
            "label": label, "type": atype, "verdict": verdict,
            "score": score, "confidence": conf,
            "expected": list(expected), "pass": ok,
            "evidence": r.get("top_evidence", []),
            "domain_scores": {d["domain_id"]: d["score"] for d in r.get("per_domain_scores", [])},
            "detectors": {
                det["detector_id"]: {"score": det["score"], "ran": det["ran"], "verdict": det.get("verdict")}
                for d in r.get("per_domain_scores", [])
                for det in d.get("detectors", [])
            }
        })
    except Exception as exc:
        print(f"[{FAIL}] {label}: Exception — {exc}")
        all_pass = False
        results.append({"label": label, "pass": False, "error": str(exc)})

print()
passed = sum(1 for r in results if r.get("pass"))
total  = len(results)
print(f"=== RESULT: {passed}/{total} tests passed ===")

# Save full results
with open("validation_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("Full results saved to validation_results.json")

# Detailed detector analysis for failures
failures = [r for r in results if not r.get("pass") and "detectors" in r]
if failures:
    print("\n=== DETECTOR BREAKDOWN FOR FAILURES ===")
    for r in failures:
        print(f"\n  [{r['label']}]  verdict={r['verdict']}  score={r['score']}")
        for did, info in r["detectors"].items():
            if info["ran"]:
                print(f"    {did:35s} score={info['score']:.3f}  verdict={info.get('verdict')}")

sys.exit(0 if all_pass else 1)
