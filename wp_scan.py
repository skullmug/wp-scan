#!/usr/bin/env python3
"""
This script pulls recently-added/updated WordPress.org plugins and run a
first-pass static scan for common vulnerability-prone patterns.

Usage:
    python3 wp_scan.py --browse new --pages 2 --per-page 50
    python3 wp_scan.py --browse updated --pages 5
    python3 wp_scan.py --slug some-specific-plugin

Requires: requests
    pip install requests --break-system-packages
"""

import argparse
import json
import os
import re
import zipfile
import io
import time
from pathlib import Path

import requests

API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOAD_BASE = "https://downloads.wordpress.org/plugin/"
WORK_DIR = Path("./wp_plugins")
REPORT_FILE = Path("./scan_report.json")

PATTERNS = [
    (
        "raw_superglobal_in_sql",
        re.compile(
            r"""(?:mysqli_query|->query|\$wpdb->query|\$wpdb->get_(?:results|row|var|col))\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)""",
            re.IGNORECASE,
        ),
        "Possible SQL injection: superglobal concatenated directly into a query call.",
    ),
    (
        "wpdb_prepare_missing_concat",
        re.compile(r"""\$wpdb->query\s*\(\s*["'].*\.\s*\$""", re.IGNORECASE),
        "Query string built via concatenation instead of $wpdb->prepare().",
    ),
    (
        "unserialize_call",
        re.compile(r"""\bunserialize\s*\(""", re.IGNORECASE),
        "unserialize() on potentially attacker-controlled data can lead to PHP object injection.",
    ),
    (
        "eval_call",
        re.compile(r"""\beval\s*\(""", re.IGNORECASE),
        "eval() use - check whether input reaching it is attacker-influenced.",
    ),
    (
        "extract_call",
        re.compile(r"""\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)""", re.IGNORECASE),
        "extract() on user input can clobber arbitrary variables.",
    ),
    (
        "missing_nonce_ajax",
        re.compile(
            r"""add_action\s*\(\s*['"]wp_ajax(?:_nopriv)?_[^'"]+['"]\s*,\s*['"][^'"]+['"]\s*\)""",
            re.IGNORECASE,
        ),
        "AJAX action registered - verify the handler calls check_ajax_referer()/wp_verify_nonce().",
    ),
    (
        "missing_cap_check_marker",
        re.compile(r"""add_action\s*\(\s*['"]admin_post""", re.IGNORECASE),
        "admin-post hook registered - verify current_user_can() gate exists in the handler.",
    ),
    (
        "file_write_funcs",
        re.compile(
            r"""\b(?:file_put_contents|fwrite|fopen)\s*\([^)]*\$_(?:GET|POST|REQUEST|FILES)""",
            re.IGNORECASE,
        ),
        "File write using request data - check path traversal / arbitrary file write potential.",
    ),
    (
        "file_upload_no_ext_check",
        re.compile(r"""\$_FILES\[[^\]]+\]\[['"]tmp_name['"]\]""", re.IGNORECASE),
        "File upload handling present - verify extension/mime allowlist and upload directory restrictions.",
    ),
    (
        "include_require_dynamic",
        re.compile(
            r"""\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST)""",
            re.IGNORECASE,
        ),
        "Dynamic include/require from request data - local/remote file inclusion risk.",
    ),
    (
        "system_exec_calls",
        re.compile(r"""\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(""", re.IGNORECASE),
        "Command execution function present - check whether arguments touch user input.",
    ),
    (
        "disabled_ssl_verify",
        re.compile(r"""sslverify['"]?\s*=>\s*false""", re.IGNORECASE),
        "TLS verification disabled on an HTTP request (wp_remote_* args).",
    ),
    (
        "hardcoded_secret_marker",
        re.compile(r"""(?:api[_-]?key|secret|password)\s*=\s*['"][A-Za-z0-9_\-]{10,}['"]""", re.IGNORECASE),
        "Possible hardcoded credential/secret.",
    ),
    (
        "old_php_baseline",
        re.compile(r"""Requires PHP:\s*5\.[0-9]""", re.IGNORECASE),
        "Plugin declares a very old minimum PHP version - often correlates with copy-pasted/tutorial-derived code.",
    ),
]

SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "tests", "test"}


def fetch_plugin_list(browse: str, pages: int, per_page: int):
    plugins = []
    for page in range(1, pages + 1):
        params = {
            "action": "query_plugins",
            "request[browse]": browse,
            "request[page]": page,
            "request[per_page]": per_page,
        }
        print(f"[*] Fetching {browse} page {page}/{pages} ...")
        resp = requests.get(API_BASE, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("plugins", [])
        if not batch:
            break
        plugins.extend(batch)
        time.sleep(0.5) # be polite, brah
    return plugins


def download_plugin_zip(slug: str, version: str = None) -> bytes:
    url = f"{DOWNLOAD_BASE}{slug}.zip" if not version else f"{DOWNLOAD_BASE}{slug}.{version}.zip"
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.content


def extract_zip(slug: str, zip_bytes: bytes) -> Path:
    target = WORK_DIR / slug
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(target)
    return target


def scan_directory(root: Path):
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for fname in filenames:
            if not fname.endswith(".php"):
                continue
            fpath = Path(dirpath) / fname
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for label, pattern, note in PATTERNS:
                for m in pattern.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    hits.append(
                        {
                            "pattern": label,
                            "note": note,
                            "file": str(fpath.relative_to(root)),
                            "line": line_no,
                            "snippet": text.splitlines()[line_no - 1].strip()[:200],
                        }
                    )
    return hits

# This is just a cheap heruristic score for quick severity ranking
def score_plugin(plugin_meta: dict, hits: list) -> int:
    score = len(hits)
    active_installs = plugin_meta.get("active_installs", 0) or 0
    # Gotta figure out a sweet spot for this
    if 1000 <= active_installs <= 100000:
        score += 5
    last_updated = plugin_meta.get("last_updated", "")
    if last_updated and "202" in last_updated:
        # Crude recency boost
        score += 2
    return score


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browse", default="new", choices=["new", "updated", "popular"],
                     help="Which WP.org listing to pull from (default: new)")
    ap.add_argument("--pages", type=int, default=1, help="Number of result pages to fetch")
    ap.add_argument("--per-page", type=int, default=50, help="Plugins per page (max ~250)")
    ap.add_argument("--slug", help="Scan a single plugin by slug instead of browsing")
    ap.add_argument("--keep-files", action="store_true", help="Don't delete extracted plugin source after scanning")
    args = ap.parse_args()

    WORK_DIR.mkdir(exist_ok=True)
    report = []

    if args.slug:
        plugin_list = [{"slug": args.slug, "name": args.slug, "active_installs": None, "last_updated": None}]
    else:
        plugin_list = fetch_plugin_list(args.browse, args.pages, args.per_page)

    print(f"[*] {len(plugin_list)} plugins queued for scanning.\n")

    for i, meta in enumerate(plugin_list, 1):
        slug = meta.get("slug")
        if not slug:
            continue
        print(f"[{i}/{len(plugin_list)}] {slug} ...", end=" ", flush=True)
        try:
            zip_bytes = download_plugin_zip(slug)
            plugin_dir = extract_zip(slug, zip_bytes)
            hits = scan_directory(plugin_dir)
            score = score_plugin(meta, hits)
            print(f"{len(hits)} hits, score={score}")
            report.append(
                {
                    "slug": slug,
                    "name": meta.get("name"),
                    "active_installs": meta.get("active_installs"),
                    "last_updated": meta.get("last_updated"),
                    "version": meta.get("version"),
                    "score": score,
                    "hit_count": len(hits),
                    "hits": hits,
                }
            )
            if not args.keep_files:
                import shutil
                shutil.rmtree(plugin_dir, ignore_errors=True)
        except requests.HTTPError as e:
            print(f"skip (HTTP error: {e})")
        except Exception as e:
            print(f"skip (error: {e})")
        time.sleep(0.3)  # be polite to WP.org

    report.sort(key=lambda r: r["score"], reverse=True)
    REPORT_FILE.write_text(json.dumps(report, indent=2))

    print(f"\n[*] Done. {len(report)} plugins scanned.")
    print(f"[*] Full report written to {REPORT_FILE.resolve()}")
    print("\nTop 10 by score:")
    for r in report[:10]:
        print(f"  {r['score']:>3}  {r['slug']:<35} hits={r['hit_count']:<3} installs={r['active_installs']}")


if __name__ == "__main__":
    main()
