#!/usr/bin/env python3
"""
bola_hunter.py — authenticated IDOR / BOLA access-control oracle.

WHAT IT DOES
    Broken Object-Level Authorization (BOLA/IDOR) is the #1 web/API bug class and
    the one automated scanners are worst at: deciding whether user A can read
    user B's object requires understanding *intent*, not matching a signature.

    This harness provisions two low-privilege accounts (a "victim" and an
    "attacker"), learns what the victim's own objects legitimately look like,
    then requests that same object space AS THE ATTACKER and flags any case
    where the attacker is served the victim's data. It handles the things that
    make Burp Intruder choke on real apps — per-request CSRF tokens and session
    expiry — and it writes reproducible evidence (request/response pairs + a CSV
    verdict log) so every finding lands in the report as proof, not a claim.

AUTHORIZED USE ONLY
    Run this only against systems you have explicit written permission to test.
    Unauthorized access-control testing is illegal.

USAGE
    python3 bola_hunter.py \
        --base-url https://target.example \
        --login-path /login \
        --object-path "/api/v2/records/{id}" \
        --victim-user alice --victim-pass '***' \
        --victim-ids 48213,48214 \
        --attacker-user bob --attacker-pass '***' \
        --scan-range 48200-48260 \
        --victim-markers 'alice@corp.example,555-0142' \
        --throttle 0.4 \
        --out ./bola-run

DESIGN RATIONALE
    * The oracle is layered: a hard confirm (attacker response contains the
      victim's known marker values) plus a soft flag (200 where 403/404 was
      expected, with a high body-similarity ratio to the victim's real object).
    * CSRF handling and re-auth live in AuthSession so the scan loop stays clean.
    * Everything is throttled and logged — built to be safe on a live client
      system and defensible in a written deliverable.
"""

import argparse
import csv
import hashlib
import re
import sys
import time
from difflib import SequenceMatcher
from pathlib import Path

import requests

CSRF_INPUT_RE = re.compile(
    r'name=["\'](?:csrf_token|_csrf|authenticity_token|__RequestVerificationToken)["\']'
    r'[^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class AuthSession:
    """A requests.Session that logs in, tracks a CSRF token, and re-auths on expiry."""

    def __init__(self, base_url, login_path, username, password, verify_tls=True):
        self.base = base_url.rstrip("/")
        self.login_path = login_path
        self.username = username
        self.password = password
        self.s = requests.Session()
        self.s.verify = verify_tls
        self.s.headers["User-Agent"] = "bola-hunter/1.0 (authorized test)"
        self.csrf = None
        self.login()

    def _extract_csrf(self, html):
        m = CSRF_INPUT_RE.search(html or "")
        return m.group(1) if m else None

    def login(self):
        """Fetch the login page for a CSRF token, then POST credentials."""
        r = self.s.get(self.base + self.login_path, timeout=20)
        self.csrf = self._extract_csrf(r.text)
        payload = {"username": self.username, "password": self.password}
        if self.csrf:
            payload["csrf_token"] = self.csrf
        r = self.s.post(self.base + self.login_path, data=payload,
                        allow_redirects=True, timeout=20)
        if r.status_code >= 400 or "logout" not in r.text.lower() and self._looks_like_login(r):
            # Not fatal for every app shape — warn, don't crash, so a tester can adapt.
            print(f"[!] Login for {self.username} may have failed "
                  f"(status {r.status_code}); verify selectors for this app.",
                  file=sys.stderr)
        return r

    @staticmethod
    def _looks_like_login(resp):
        return bool(re.search(r"(sign in|log ?in|password)", resp.text or "", re.I)) \
            and resp.status_code == 200

    def _expired(self, resp):
        """Heuristic: session died if we got bounced to login or a 401."""
        if resp.status_code == 401:
            return True
        if resp.status_code in (302, 303) and "login" in resp.headers.get("Location", "").lower():
            return True
        if resp.status_code == 200 and self._looks_like_login(resp):
            return True
        return False

    def get(self, path):
        """GET with one automatic re-auth if the session has expired."""
        url = self.base + path
        r = self.s.get(url, allow_redirects=False, timeout=20)
        if self._expired(r):
            print(f"[*] {self.username} session expired — re-authenticating.",
                  file=sys.stderr)
            self.login()
            r = self.s.get(url, allow_redirects=False, timeout=20)
        return r


def fingerprint(text):
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def similarity(a, b):
    return round(SequenceMatcher(None, a or "", b or "").ratio(), 3)


def parse_ids(spec):
    """Accept '1,2,3' and '100-120' (and mixes) -> sorted unique list of ints."""
    ids = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ids.update(range(int(lo), int(hi) + 1))
        else:
            ids.add(int(part))
    return sorted(ids)


def learn_victim(victim, object_path, victim_ids):
    """Log in as the victim and record what their OWN objects legitimately return."""
    known = {}
    for oid in victim_ids:
        r = victim.get(object_path.format(id=oid))
        known[oid] = {
            "status": r.status_code,
            "body": r.text,
            "len": len(r.text),
            "fp": fingerprint(r.text),
        }
        print(f"[victim] object {oid}: {r.status_code} ({len(r.text)} bytes)")
    return known


def judge(attacker_resp, victim_ref, markers):
    """
    Return (verdict, note). Verdict is CONFIRMED / SUSPECT / expected / notfound.
    CONFIRMED  = attacker got 200 and the victim's marker data is present.
    SUSPECT    = attacker got 200 with a body highly similar to the victim's real object.
    """
    body = attacker_resp.text or ""
    if attacker_resp.status_code in (403, 404, 401):
        return "expected", f"{attacker_resp.status_code} (properly denied)"
    if attacker_resp.status_code != 200:
        return "notfound", f"status {attacker_resp.status_code}"

    hit_markers = [m for m in markers if m and m in body]
    if hit_markers:
        return "CONFIRMED", f"victim markers leaked: {', '.join(hit_markers)}"

    if victim_ref is not None:
        ratio = similarity(victim_ref["body"], body)
        if ratio >= 0.85 and len(body) > 0:
            return "SUSPECT", f"body similarity {ratio} to victim object"
    if len(body) > 0:
        return "SUSPECT", "200 where denial was expected (non-empty body)"
    return "expected", "200 empty"


def run(args):
    out = Path(args.out)
    (out / "responses").mkdir(parents=True, exist_ok=True)
    markers = [m.strip() for m in (args.victim_markers or "").split(",") if m.strip()]
    victim_ids = parse_ids(args.victim_ids)
    scan_ids = parse_ids(args.scan_range) if args.scan_range else victim_ids

    victim = AuthSession(args.base_url, args.login_path,
                         args.victim_user, args.victim_pass, not args.insecure)
    known = learn_victim(victim, args.object_path, victim_ids)

    attacker = AuthSession(args.base_url, args.login_path,
                           args.attacker_user, args.attacker_pass, not args.insecure)

    findings = []
    csv_path = out / "verdicts.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["object_id", "attacker_status", "content_length",
                    "verdict", "note", "response_file"])
        for oid in scan_ids:
            path = args.object_path.format(id=oid)
            r = attacker.get(path)
            verdict, note = judge(r, known.get(oid), markers)

            resp_file = out / "responses" / f"{oid}_{args.attacker_user}.txt"
            resp_file.write_text(
                f"GET {args.base_url}{path}\n"
                f"HTTP {r.status_code}  len={len(r.text)}\n\n{r.text}",
                encoding="utf-8", errors="replace")

            w.writerow([oid, r.status_code, len(r.text), verdict, note, resp_file.name])
            tag = {"CONFIRMED": "[!!]", "SUSPECT": "[?]"}.get(verdict, "[ ]")
            print(f"{tag} object {oid}: {r.status_code} -> {verdict} ({note})")
            if verdict in ("CONFIRMED", "SUSPECT"):
                findings.append((oid, verdict, note))

            time.sleep(args.throttle)

    print("\n=== SUMMARY ===")
    confirmed = [f for f in findings if f[1] == "CONFIRMED"]
    suspect = [f for f in findings if f[1] == "SUSPECT"]
    print(f"CONFIRMED BOLA/IDOR: {len(confirmed)}")
    print(f"SUSPECT (manual review): {len(suspect)}")
    print(f"Evidence + verdict log written to: {out.resolve()}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="Authenticated IDOR/BOLA access-control oracle.")
    p.add_argument("--base-url", required=True)
    p.add_argument("--login-path", default="/login")
    p.add_argument("--object-path", required=True,
                   help="Object URL template with {id}, e.g. /api/v2/records/{id}")
    p.add_argument("--victim-user", required=True)
    p.add_argument("--victim-pass", required=True)
    p.add_argument("--victim-ids", required=True,
                   help="IDs the victim legitimately owns, e.g. 48213,48214")
    p.add_argument("--attacker-user", required=True)
    p.add_argument("--attacker-pass", required=True)
    p.add_argument("--scan-range", help="IDs to probe as attacker, e.g. 48200-48260")
    p.add_argument("--victim-markers", help="Comma-separated known victim data (email, phone) for hard confirmation")
    p.add_argument("--throttle", type=float, default=0.4, help="Seconds between requests (stay under lockout/WAF)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (test envs only)")
    p.add_argument("--out", default="./bola-run", help="Output directory for evidence + CSV")
    return p


if __name__ == "__main__":
    sys.exit(run(build_parser().parse_args()))
