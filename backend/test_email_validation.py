import requests, json

BACKEND = "http://127.0.0.1:8000"

def analyze_email(path, label):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    res = requests.post(BACKEND + "/analyze", data={"type": "email", "content": content})
    r = res.json()
    print(f"\n{'='*60}")
    print(f"  [{label}]")
    print(f"  File       : {path}")
    print(f"  Risk Score : {r['risk_score']}")
    print(f"  Verdict    : {r['verdict']}")
    print(f"  Confidence : {r['confidence']}")
    print(f"  D1 score   : {next((d['score'] for d in r['per_domain_scores'] if d['domain_id']=='d1'), 'N/A')}")
    print(f"  D4 score   : {next((d['score'] for d in r['per_domain_scores'] if d['domain_id']=='d4'), 'N/A')}")
    print("  Top evidence:")
    for ev in r.get("top_evidence", [])[:8]:
        print(f"    [{ev['severity'].upper():8s}] {ev['description']}")
    if not r.get("top_evidence"):
        print("    (none)")
    print("  D4 detectors:")
    d4 = next((d for d in r["per_domain_scores"] if d["domain_id"] == "d4"), None)
    if d4:
        for det in d4["detectors"]:
            print(f"    {det['name']:38s} score={det['score']} ran={det['ran']}")
    return r

r_benign  = analyze_email(r"../examples/true/2_benign_email.eml",   "BENIGN (should be SAFE)")
r_phishing = analyze_email(r"../examples/false/2_phishing_email.eml", "PHISHING (should be MALICIOUS)")

# Summary
print("\n\n=== VALIDATION SUMMARY ===")
bv = r_benign["verdict"]
pv = r_phishing["verdict"]
print(f"  Benign email verdict   : {bv} {'PASS' if bv == 'safe' else 'FAIL - expected safe'}")
print(f"  Phishing email verdict : {pv} {'PASS' if pv in ('malicious','likely_malicious','suspicious') else 'FAIL - expected malicious/suspicious'}")
