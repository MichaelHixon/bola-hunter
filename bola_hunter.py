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
    * Auth is a swappable seam: BaseAuthSession owns the re-auth contract while
      FormAuthSession (CSRF + cookies) and JwtAuthSession (bearer token) each
      implement login/expiry, so the scan loop and evidence logging stay clean.
    * A session that cannot authenticate is fatal, never silent: an
      unauthenticated attacker would make every object read as "properly
      denied" and the tool would report a false all-clear. This is enforced on
      BOTH seams at startup, plus a proof-of-life control — the victim must read
      its own objects (200), and the attacker can be required to (--attacker-ids)
      — so a stale token or a bad password aborts loudly instead of scanning
      blind.
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
    r'name=["\'](csrf_token|_csrf|authenticity_token|__RequestVerificationToken)["\']'
    r'[^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class AuthError(Exception):
    """
    Authentication failed. Fatal at startup (a session that can't authenticate
    has no valid verdict to emit); caught-and-stopped mid-scan (a transient
    re-auth failure ends the scan cleanly with partial results, rather than
    crashing past the summary).
    """


class BaseAuthSession:
    """
    A requests.Session that authenticates and re-auths on expiry.

    The login/expiry logic is the SEAM: real apps authenticate two different
    ways, so the two subclasses implement the same contract — FormAuthSession
    (login form + CSRF token + cookie session) and JwtAuthSession (JSON login
    -> ``Authorization: Bearer <jwt>``). The scan loop and evidence logging
    never change; only which seam is instantiated.

    Authentication is VERIFIED, never assumed: __init__ raises AuthError if the
    login didn't take. An unauthenticated session is the worst failure mode for
    a BOLA oracle — every object reads "properly denied", so the tool reports a
    false all-clear — therefore a dead login is fatal and loud on BOTH seams.

    Only login()/_authenticated()/_expired() vary between seams; if a third
    auth type ever lands, an injected strategy would beat a deeper hierarchy.
    Two seams don't earn that yet.
    """

    REAUTH_TRIES = 3   # bounded re-auth attempts on a mid-scan expiry

    def __init__(self, base_url, login_path, username, password, verify_tls=True,
                 user_field="username", pass_field="password"):
        self.base = base_url.rstrip("/")
        self.login_path = login_path
        self.username = username
        self.password = password
        self.user_field = user_field   # login field name for the identity (e.g. 'email')
        self.pass_field = pass_field
        self.s = requests.Session()
        self.s.verify = verify_tls
        self.s.headers["User-Agent"] = "bola-hunter/1.0 (authorized test)"
        self.login()
        if not self._authenticated():
            raise AuthError(
                f"login for {self.username} did not authenticate: {self._auth_detail()}")

    # --- seam contract -------------------------------------------------
    def login(self):
        raise NotImplementedError("subclass must implement the login seam")

    def _authenticated(self):
        """True iff the last login produced a usable authenticated session."""
        raise NotImplementedError("subclass must implement the auth-success check")

    def _auth_detail(self):
        """Human-readable reason the auth check failed, for the error message."""
        return "see login response"

    def _expired(self, resp):
        raise NotImplementedError("subclass must implement the expiry heuristic")

    # --- shared request path ------------------------------------------
    def get(self, path):
        """
        GET with automatic re-auth on expiry. A transient re-auth failure gets
        a few bounded retries with backoff; only if the session stays dead do
        we raise AuthError — so a mid-scan hiccup ends the scan loudly instead
        of silently reading everything as "denied" (a false all-clear).
        """
        url = self.base + path
        r = self.s.get(url, allow_redirects=False, timeout=20)
        if not self._expired(r):
            return r
        for attempt in range(1, self.REAUTH_TRIES + 1):
            print(f"[*] {self.username} session expired — re-auth {attempt}/{self.REAUTH_TRIES}.",
                  file=sys.stderr)
            try:
                self.login()
            except requests.exceptions.RequestException as exc:
                print(f"[*] re-auth request failed ({exc}).", file=sys.stderr)
            if self._authenticated():
                r = self.s.get(url, allow_redirects=False, timeout=20)
                if not self._expired(r):
                    return r
            time.sleep(min(2 ** attempt, 8))
        raise AuthError(
            f"{self.username} lost its session mid-scan and could not re-authenticate "
            f"after {self.REAUTH_TRIES} tries: {self._auth_detail()}")


class FormAuthSession(BaseAuthSession):
    """Login-form seam: fetch a CSRF token, POST credentials, ride a cookie session."""

    def _extract_csrf(self, html):
        """Return (field_name, value) for the login CSRF token, or (None, None)."""
        m = CSRF_INPUT_RE.search(html or "")
        return (m.group(1), m.group(2)) if m else (None, None)

    def login(self):
        """Fetch the login page for a CSRF token, then POST credentials."""
        r = self.s.get(self.base + self.login_path, timeout=20)
        csrf_name, csrf_value = self._extract_csrf(r.text)
        payload = {self.user_field: self.username, self.pass_field: self.password}
        if csrf_value:
            payload[csrf_name] = csrf_value   # submit under the field's REAL name
        self._last = self.s.post(self.base + self.login_path, data=payload,
                                 allow_redirects=True, timeout=20)
        return self._last

    def _authenticated(self):
        """
        Best-available signal that the cookie session is live: the post-login
        page came back OK and no longer looks like the login form (or exposes a
        logout affordance). This is a heuristic — documented as such — but
        promoting it from a warning to a gate is what stops a bad-password run
        from scanning unauthenticated and reporting a false all-clear.
        """
        r = getattr(self, "_last", None)
        if r is None or r.status_code >= 400:
            return False
        body = (r.text or "").lower()
        if "logout" in body or "sign out" in body:
            return True
        return not self._looks_like_login(r)

    def _auth_detail(self):
        r = getattr(self, "_last", None)
        if r is None:
            return "no login response"
        return (f"post-login HTTP {r.status_code}, still looks like the login page "
                f"(no logout link) — check credentials and "
                f"--login-user-field / --login-pass-field for this app")

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


class JwtAuthSession(BaseAuthSession):
    """
    Bearer-token seam: POST JSON credentials, pull the token out of the JSON
    response at ``--token-path``, and carry it as an auth header on every
    request. Matches modern JSON APIs (OWASP Juice Shop, most SPAs).
    """

    def __init__(self, base_url, login_path, username, password, verify_tls=True,
                 user_field="username", pass_field="password",
                 token_path="token",
                 auth_header="Authorization", auth_scheme="Bearer"):
        # Set the JWT-specific config before super().__init__ runs login().
        self.token_path = token_path
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme
        self.token = None
        self._last = None
        super().__init__(base_url, login_path, username, password, verify_tls,
                         user_field, pass_field)

    @staticmethod
    def _is_index(key):
        """True iff key is a clean integer (list index). '--1' is NOT — and
        must not reach int(), which would crash the graceful token-miss path."""
        try:
            int(key)
            return True
        except ValueError:
            return False

    def _extract_token(self, resp):
        """
        Walk the dot-path into the JSON login body. Supports dict keys and
        numeric list indices, so 'authentication.token' and 'data.tokens.0'
        both resolve. A malformed key never crashes — it just misses and
        returns None (which triggers the graceful auth-failure abort upstream).
        """
        try:
            node = resp.json()
        except ValueError:
            return None
        for key in self.token_path.split("."):
            if isinstance(node, dict) and key in node:
                node = node[key]
            elif isinstance(node, list) and self._is_index(key) \
                    and -len(node) <= int(key) < len(node):
                node = node[int(key)]
            else:
                return None
        return node if isinstance(node, str) and node else None

    @staticmethod
    def _response_keys(resp):
        """Top-level shape of the login response, for a helpful failure message."""
        try:
            data = resp.json()
        except ValueError:
            return "<non-JSON body>"
        return list(data.keys()) if isinstance(data, dict) else f"<{type(data).__name__}>"

    def login(self):
        """POST JSON credentials, extract the token, set the bearer header."""
        # Never let a stale bearer ride the login POST: a cross-host login
        # redirect (SSO/IdP, apex<->www) would leak the previous token, and it
        # isn't needed to authenticate. allow_redirects=False keeps it in scope.
        self.s.headers.pop(self.auth_header, None)
        self.token = None
        self._last = self.s.post(
            self.base + self.login_path,
            json={self.user_field: self.username, self.pass_field: self.password},
            allow_redirects=False, timeout=20)
        self.token = self._extract_token(self._last)
        if self.token:
            prefix = (self.auth_scheme + " ") if self.auth_scheme else ""
            self.s.headers[self.auth_header] = prefix + self.token
        return self._last

    def _authenticated(self):
        # A token was extracted. That it actually WORKS is proven separately by
        # the victim/attacker proof-of-life reads (a stale token passes here but
        # 401s there), which is why both gates exist.
        return bool(self.token)

    def _auth_detail(self):
        r = self._last
        status = r.status_code if r is not None else "?"
        keys = self._response_keys(r) if r is not None else "<none>"
        return (f"no token at --token-path '{self.token_path}' "
                f"(login HTTP {status}; top-level response keys: {keys})")

    def _expired(self, resp):
        """401, or a redirect to a login page (some JWT apps bounce on expiry)."""
        if resp.status_code == 401:
            return True
        if resp.status_code in (302, 303) and "login" in resp.headers.get("Location", "").lower():
            return True
        return False


def make_session(args, username, password):
    """Instantiate the auth seam selected by --auth."""
    common = dict(verify_tls=not args.insecure,
                  user_field=args.login_user_field,
                  pass_field=args.login_pass_field)
    if args.auth == "jwt":
        return JwtAuthSession(args.base_url, args.login_path, username, password,
                              token_path=args.token_path,
                              auth_header=args.auth_header,
                              auth_scheme=args.auth_scheme,
                              **common)
    return FormAuthSession(args.base_url, args.login_path, username, password, **common)


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
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    print(f"[!] range '{part}' is reversed (lo > hi) — skipping.", file=sys.stderr)
                    continue
                ids.update(range(lo, hi + 1))
            else:
                ids.add(int(part))
        except ValueError:
            raise SystemExit(
                f"[!] invalid id spec: '{part}' — expected integers like '48213' or '48200-48260'")
    return sorted(ids)


def learn_victim(victim, object_path, victim_ids):
    """
    Log in as the victim and record what their OWN objects legitimately return.

    Proof-of-life: the victim must actually READ its own objects (HTTP 200). If
    none come back 200 the session isn't really authenticated (or the IDs/path
    are wrong), and the reference corpus would be login-page garbage — every
    later similarity check would compare noise to noise. That is fatal, because
    a poisoned reference silently fabricates verdicts.
    """
    known = {}
    live = 0
    for oid in victim_ids:
        r = victim.get(object_path.format(id=oid))
        known[oid] = {
            "status": r.status_code,
            "body": r.text,
            "len": len(r.text),
            "fp": fingerprint(r.text),
        }
        note = "" if r.status_code == 200 else "  [!] not 200 — not a usable reference"
        print(f"[victim] object {oid}: {r.status_code} ({len(r.text)} bytes){note}")
        if r.status_code == 200:
            live += 1
    if live == 0:
        raise AuthError(
            f"victim {victim.username} read NONE of its own objects at HTTP 200 "
            f"(checked {sorted(victim_ids)}). Either the login failed or "
            f"--victim-ids / --object-path are wrong; the reference corpus would "
            f"be poisoned, so every verdict would be fiction. Aborting.")
    return known


def prove_attacker_liveness(attacker, object_path, attacker_ids):
    """
    Optional positive control: the attacker must read its OWN objects at 200,
    proving the attacker session is genuinely authenticated (a token can parse
    but be stale/expired, passing the startup gate yet 401-ing every read).
    Returns True if verified; raises AuthError if the attacker can't read its
    own objects. Callers pass an empty list to skip (liveness then unverified).
    """
    if not attacker_ids:
        return False
    live = 0
    for oid in attacker_ids:
        r = attacker.get(object_path.format(id=oid))
        print(f"[attacker] own object {oid}: {r.status_code}")
        if r.status_code == 200:
            live += 1
    if live == 0:
        raise AuthError(
            f"attacker {attacker.username} read NONE of its own objects at HTTP 200 "
            f"({sorted(attacker_ids)}) — the session is not authenticated, so a scan "
            f"would report a false all-clear. Aborting.")
    return True


def judge(attacker_resp, victim_ref, markers):
    """
    Return (verdict, note): CONFIRMED / SUSPECT / AMBIGUOUS / expected / notfound.
    CONFIRMED  = attacker got 200 and the victim's marker data is present.
    SUSPECT    = attacker got 200 with a body highly similar to the victim's real object.
    AMBIGUOUS  = a redirect we did not follow — could hide the resource; inspect.
    """
    body = attacker_resp.text or ""
    sc = attacker_resp.status_code
    if sc in (401, 403, 404):
        return "expected", f"{sc} (properly denied)"
    if 300 <= sc < 400:
        # get() does not follow redirects, so a 3xx that _expired() did not
        # read as a login bounce might be hiding the resource behind it. Flag
        # for a human rather than silently counting it as not-found.
        loc = attacker_resp.headers.get("Location", "")
        return "AMBIGUOUS", f"{sc} redirect to '{loc}' — not followed; inspect for a resource behind it"
    if sc != 200:
        return "notfound", f"status {sc}"

    hit_markers = [m for m in markers if m and m in body]
    if hit_markers:
        return "CONFIRMED", f"victim markers leaked: {', '.join(hit_markers)}"

    # Only a genuine 200 victim object is a trustworthy similarity reference —
    # never score against a login page or an error body we failed to fetch.
    if victim_ref is not None and victim_ref.get("status") == 200:
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

    # Startup auth is fatal: a session that can't authenticate (or a victim /
    # attacker that can't read its own objects) has no valid verdict to emit.
    try:
        victim = make_session(args, args.victim_user, args.victim_pass)
        known = learn_victim(victim, args.object_path, victim_ids)
        attacker = make_session(args, args.attacker_user, args.attacker_pass)
        attacker_ids = parse_ids(args.attacker_ids) if args.attacker_ids else []
        attacker_verified = prove_attacker_liveness(attacker, args.object_path, attacker_ids)
    except AuthError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    findings = []
    stopped_early = False
    csv_path = out / "verdicts.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["object_id", "attacker_status", "content_length",
                    "verdict", "note", "response_file"])
        for oid in scan_ids:
            path = args.object_path.format(id=oid)
            try:
                r = attacker.get(path)
            except AuthError as exc:
                # Session died mid-scan and could not be recovered. Stop cleanly
                # with partial results rather than reading the rest as "denied".
                print(f"[x] {exc}\n[x] Stopping scan — results below are PARTIAL.", file=sys.stderr)
                stopped_early = True
                break
            except requests.exceptions.RequestException as exc:
                # A dropped connection mid-scan shouldn't abort a paid run — log and continue.
                w.writerow([oid, "ERR", 0, "error", f"request failed: {exc}", ""])
                fh.flush()
                print(f"[x] object {oid}: request failed ({exc}) — continuing.", file=sys.stderr)
                time.sleep(args.throttle)
                continue
            verdict, note = judge(r, known.get(oid), markers)

            resp_file = out / "responses" / f"{oid}_{args.attacker_user}.txt"
            resp_file.write_text(
                f"GET {args.base_url}{path}\n"
                f"HTTP {r.status_code}  len={len(r.text)}\n\n{r.text}",
                encoding="utf-8", errors="replace")

            w.writerow([oid, r.status_code, len(r.text), verdict, note, resp_file.name])
            fh.flush()   # partial evidence survives a crash / early stop
            tag = {"CONFIRMED": "[!!]", "SUSPECT": "[?]", "AMBIGUOUS": "[~]"}.get(verdict, "[ ]")
            print(f"{tag} object {oid}: {r.status_code} -> {verdict} ({note})")
            if verdict in ("CONFIRMED", "SUSPECT", "AMBIGUOUS"):
                findings.append((oid, verdict, note))

            time.sleep(args.throttle)

    print("\n=== SUMMARY ===")
    confirmed = [f for f in findings if f[1] == "CONFIRMED"]
    suspect = [f for f in findings if f[1] == "SUSPECT"]
    ambiguous = [f for f in findings if f[1] == "AMBIGUOUS"]
    print(f"CONFIRMED BOLA/IDOR: {len(confirmed)}")
    print(f"SUSPECT (manual review): {len(suspect)}")
    if ambiguous:
        print(f"AMBIGUOUS (unfollowed redirects — inspect): {len(ambiguous)}")
    if stopped_early:
        print("[!] Scan STOPPED EARLY on a mid-scan auth failure — results are PARTIAL.")
    if not attacker_verified and not confirmed and not suspect:
        print("[!] Attacker liveness was NOT positively verified (no --attacker-ids given). "
              "A clean result here cannot be trusted as 'no BOLA' — it may just mean the "
              "attacker session wasn't truly authenticated. Re-run with --attacker-ids "
              "<objects the attacker legitimately owns> to make an all-clear meaningful.")
    print(f"Evidence + verdict log written to: {out.resolve()}")
    return 1 if stopped_early else 0


def build_parser():
    p = argparse.ArgumentParser(description="Authenticated IDOR/BOLA access-control oracle.")
    p.add_argument("--base-url", required=True)
    p.add_argument("--login-path", default="/login")
    p.add_argument("--object-path", required=True,
                   help="Object URL template with {id}, e.g. /api/v2/records/{id}")

    auth = p.add_argument_group("auth seam")
    auth.add_argument("--auth", choices=["form", "jwt"], default="form",
                      help="Auth seam: 'form' = login form + CSRF + cookie session (default); "
                           "'jwt' = JSON login -> Authorization: Bearer <token>")
    auth.add_argument("--login-user-field", default="username",
                      help="Login field name for the identity (e.g. 'email' for many JWT APIs)")
    auth.add_argument("--login-pass-field", default="password",
                      help="Login field name for the password")
    auth.add_argument("--token-path", default="token",
                      help="[jwt] Dot-path to the token in the JSON login response; "
                           "supports list indices (default 'token'; e.g. "
                           "'authentication.token', 'data.access_token', 'data.tokens.0')")
    auth.add_argument("--auth-header", default="Authorization",
                      help="[jwt] Header that carries the token")
    auth.add_argument("--auth-scheme", default="Bearer",
                      help="[jwt] Scheme prefix before the token; use '' for a bare token")
    p.add_argument("--victim-user", required=True)
    p.add_argument("--victim-pass", required=True)
    p.add_argument("--victim-ids", required=True,
                   help="IDs the victim legitimately owns, e.g. 48213,48214")
    p.add_argument("--attacker-user", required=True)
    p.add_argument("--attacker-pass", required=True)
    p.add_argument("--attacker-ids",
                   help="Objects the ATTACKER legitimately owns — a proof-of-life control. "
                        "If set, the attacker must read >=1 at HTTP 200 before scanning, or the "
                        "run aborts. Strongly recommended: without it an unauthenticated attacker "
                        "can produce a false all-clear.")
    p.add_argument("--scan-range", help="IDs to probe as attacker, e.g. 48200-48260")
    p.add_argument("--victim-markers", help="Comma-separated known victim data (email, phone) for hard confirmation")
    p.add_argument("--throttle", type=float, default=0.4, help="Seconds between requests (stay under lockout/WAF)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (test envs only)")
    p.add_argument("--out", default="./bola-run", help="Output directory for evidence + CSV")
    return p


if __name__ == "__main__":
    try:
        sys.exit(run(build_parser().parse_args()))
    except AuthError as exc:
        # Backstop: any auth failure that escapes run() exits non-zero and loud,
        # never a silent 0 that a caller could mistake for "no BOLA found".
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
