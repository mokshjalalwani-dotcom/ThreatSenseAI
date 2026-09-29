#!/usr/bin/env python3
"""
Download URL training datasets.

Usage:
    python ml/training/download_url_data.py

Downloads to ml/data/url_datasets/:
  - PhiUSIIL_Phishing_URL_Dataset.csv  (UCI ML Repository, no auth)
  - tranco_top1m.csv                   (Tranco, no auth)
  - urlhaus_recent.csv                 (URLhaus, requires URLHAUS_AUTH_KEY in env)

Run from repo root.  Skips files that already exist.
"""

from __future__ import annotations

import csv
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "ml" / "data" / "url_datasets"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Dataset URLs ──────────────────────────────────────────────────────────────

PHIUSIIL_URL = (
    "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def download_file(url: str, dest: Path, description: str) -> bool:
    """Download *url* to *dest*.  Returns True on success."""
    if dest.exists():
        print(f"[SKIP] {description} already exists at {dest}")
        return True

    print(f"[DOWNLOAD] {description}")
    print(f"  URL: {url}")
    print(f"  Dest: {dest}")
    try:
        urllib.request.urlretrieve(url, dest)
        print(f"  ✓ Downloaded {dest.stat().st_size:,} bytes")
        return True
    except Exception as exc:
        print(f"  ✗ Failed: {exc}")
        return False


def download_phiusiil() -> None:
    zip_path = DATA_DIR / "phiusiil.zip"
    csv_path = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"

    if csv_path.exists():
        print(f"[SKIP] PhiUSIIL already at {csv_path}")
        return

    ok = download_file(PHIUSIIL_URL, zip_path, "PhiUSIIL Phishing URL Dataset (UCI)")
    if not ok:
        return

    print("[EXTRACT] PhiUSIIL zip")
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        print(f"  Contents: {names[:5]}")
        # Find the CSV inside the zip
        csv_files = [n for n in names if n.endswith(".csv")]
        if not csv_files:
            print("  ✗ No CSV found in zip")
            return
        zf.extract(csv_files[0], DATA_DIR)
        extracted = DATA_DIR / csv_files[0]
        if extracted != csv_path:
            extracted.rename(csv_path)
    zip_path.unlink(missing_ok=True)
    print(f"  ✓ Extracted to {csv_path}")

    # Quick sanity check
    with csv_path.open() as f:
        reader = csv.reader(f)
        header = next(reader, [])
        print(f"  Columns: {header[:5]}")


def download_tranco() -> None:
    zip_path = DATA_DIR / "tranco_top1m.zip"
    csv_path = DATA_DIR / "tranco_top1m.csv"

    if csv_path.exists():
        print(f"[SKIP] Tranco already at {csv_path}")
        return

    ok = download_file(TRANCO_URL, zip_path, "Tranco Top-1M List")
    if not ok:
        return

    print("[EXTRACT] Tranco zip")
    with zipfile.ZipFile(zip_path, "r") as zf:
        csv_files = [n for n in zf.namelist() if n.endswith(".csv")]
        if not csv_files:
            print("  ✗ No CSV in Tranco zip")
            return
        zf.extract(csv_files[0], DATA_DIR)
        extracted = DATA_DIR / csv_files[0]
        if extracted != csv_path:
            extracted.rename(csv_path)
    zip_path.unlink(missing_ok=True)
    print(f"  ✓ Extracted to {csv_path}")


def download_urlhaus() -> None:
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        print(
            "[SKIP] URLhaus — set URLHAUS_AUTH_KEY environment variable to download.\n"
            "  Register free at: https://urlhaus-api.abuse.ch/\n"
            "  URLhaus is optional; the model trains fine without it."
        )
        return

    csv_path = DATA_DIR / "urlhaus_recent.csv"
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    download_file(url, csv_path, "URLhaus recent malicious URLs")


if __name__ == "__main__":
    print("=" * 60)
    print("ThreatSenseAI — URL Dataset Downloader")
    print("=" * 60)
    download_phiusiil()
    download_tranco()
    download_urlhaus()
    print("\nDone.  Run ml/training/train_url_model.py next.")
