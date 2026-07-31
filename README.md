# bola-hunter

**An authenticated IDOR / BOLA access-control oracle.**

Broken Object-Level Authorization (BOLA / IDOR) is the top web-and-API bug class and the one automated scanners handle worst: deciding whether user A may read user B's object requires understanding *intent*, not matching a signature. `bola-hunter` closes that gap for authenticated testing.

It provisions two low-privilege accounts — a **victim** and an **attacker** — learns what the victim's own objects legitimately look like, then requests that same object space *as the attacker* and flags any case where the attacker is served the victim's data. It handles the things that make Burp Intruder choke on real apps (per-request CSRF tokens, session expiry) and writes reproducible evidence, so every finding lands as proof rather than a claim.

## The verdict oracle

Layered, to keep false positives out of the report:

- **CONFIRMED** — attacker got `200` and the victim's known marker data (email, phone, …) is present in the response body.
- **SUSPECT** — attacker got `200` with a body highly similar (≥ 0.85) to the victim's real object, or `200` where `403/404` was expected.
- **expected** — properly denied (`401 / 403 / 404`).

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

> **Credentials:** for real engagements, prefer passing `--victim-pass` / `--attacker-pass` via an environment variable or a wrapper rather than inline — inline arguments are visible in shell history and `ps`.

## Design notes

- CSRF handling and automatic re-auth live in `AuthSession`, so the scan loop stays clean.
- Everything is throttled and logged — safe on a live client system and defensible in a written deliverable.
- Requires Python 3 and `requests`.

## License

MIT © 2026 Michael Hixon
