# bola-hunter

**An authenticated IDOR / BOLA access-control oracle.**

Broken Object-Level Authorization (BOLA / IDOR) is the top web-and-API bug class and the one automated scanners handle worst: deciding whether user A may read user B's object requires understanding *intent*, not matching a signature. `bola-hunter` closes that gap for authenticated testing.

It provisions two low-privilege accounts — a **victim** and an **attacker** — learns what the victim's own objects legitimately look like, then requests that same object space *as the attacker* and flags any case where the attacker is served the victim's data. It handles the things that make Burp Intruder choke on real apps (per-request CSRF tokens, session expiry) and writes reproducible evidence, so every finding lands as proof rather than a claim.

## The verdict oracle

Layered, to keep false positives out of the report:

- **CONFIRMED** — attacker got `200` and the victim's known marker data (email, phone, …) is present in the response body.
- **SUSPECT** — attacker got `200` with a body highly similar (≥ 0.85) to the victim's real object, or `200` where `403/404` was expected.
- **AMBIGUOUS** — a redirect that wasn't followed; the resource may be behind it. Inspect.
- **expected** — properly denied (`401 / 403 / 404`).

### An all-clear you can trust

A BOLA oracle's most dangerous output is a *false* all-clear — reporting a target secure when the tool simply never authenticated. `bola-hunter` refuses to do that:

- **Auth is verified, not assumed** — on both the form and JWT seams a failed login aborts loudly at startup, never scans on.
- **Proof-of-life** — the victim must read its own objects (`200`) or the run aborts (a poisoned reference would fabricate verdicts). Pass **`--attacker-ids`** (objects the attacker legitimately owns) to require the same of the attacker; without it, a clean result is flagged as **not trustworthy** in the summary.
- **Sessions that die mid-scan** get bounded re-auth retries, then a clean stop with partial evidence — not a crash past the summary.

## Usage

> **Authorized use only.** Run this only against systems you have explicit written permission to test. Unauthorized access-control testing is illegal.

```bash
pip install -r requirements.txt

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
```

Output: a `verdicts.csv` verdict log plus per-object request/response evidence under `--out` (both gitignored — they contain target data).

### Auth seams

Real apps authenticate two different ways, so `--auth` selects the seam — the oracle and evidence logging are identical either way:

- **`--auth form`** (default) — login form + CSRF token + cookie session. The example above.
- **`--auth jwt`** — JSON login → `Authorization: Bearer <token>`. For modern JSON APIs / SPAs.

```bash
python3 bola_hunter.py \
  --auth jwt \
  --base-url https://api.target.example \
  --login-path /rest/user/login \
  --login-user-field email \
  --token-path authentication.token \
  --object-path "/rest/basket/{id}" \
  --victim-user alice@target.example --victim-pass '***' --victim-ids 6 \
  --attacker-user bob@target.example --attacker-pass '***' \
  --scan-range 3-9 \
  --victim-markers '"UserId":24' \
  --out ./bola-run
```

`--token-path` is a dot-path into the JSON login response — default `token`, and it also reaches list indices (`authentication.token`, `data.access_token`, `data.tokens.0`, …). If login yields no token there, the run aborts loudly rather than scanning unauthenticated (an unauthenticated attacker would report a false all-clear). `--login-user-field` / `--login-pass-field` name the credential fields; `--auth-header` / `--auth-scheme` override the default `Authorization: Bearer` carrier.

> **Credentials:** for real engagements, prefer passing `--victim-pass` / `--attacker-pass` via an environment variable or a wrapper rather than inline — inline arguments are visible in shell history and `ps`.

## Design notes

- Auth is a swappable seam: `BaseAuthSession` owns the re-auth contract, `FormAuthSession` (CSRF + cookies) and `JwtAuthSession` (bearer token) implement it, and `--auth` picks one — so the scan loop and evidence logging never change.
- Everything is throttled and logged — safe on a live client system and defensible in a written deliverable.
- Requires Python 3 and `requests`.

## Limitations

Verdicts are signals, not gospel — read the evidence before you report:

- **Marker matching is substring, not word-boundary.** A short or common marker (a first name, a bare `id`) can match incidentally and produce a false CONFIRMED. Choose distinctive markers (a full email, `"UserId":24`), not `Dan` or `555`.
- **`SUSPECT` on `200`-with-body is noisy against SPAs.** Apps that serve the same `200` shell (or a soft-404 JSON) for a forbidden object will flag every request SUSPECT. The similarity-to-victim signal is the reliable one; treat the bare "non-empty 200" fallback as a prompt to look, not a finding.
- **No checkpoint/resume.** A crash or early stop means re-running from the first ID. For very large scans, chunk the `--scan-range` yourself.

## License

MIT © 2026 Michael Hixon
