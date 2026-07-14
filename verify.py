#!/usr/bin/env python3
"""
verify.py — independently verify the GRAILB calibration log.

This script lives in the calibration-log repo and is meant to be run by people
who do not trust GRAILB. It requires no GRAILB credentials and, for the chain
and timestamp checks, no network access at all.

    git clone https://github.com/grailb/calibration-log
    cd calibration-log
    python verify.py

What it checks, in order:

  1. CHAIN INTEGRITY (offline)
     Recomputes every chain_hash from its published fields and confirms each
     record links to its predecessor. Also confirms chain_seq is gap-free.
     A gap means a record was withheld. This is the check that makes it hard
     to publish only the predictions that turned out well.

  2. TIMESTAMPS (offline, needs `ots`)
     Verifies the OpenTimestamps proofs in anchors/ against the Bitcoin
     blockchain. Each proof establishes that a chain tip existed no later than
     a given Bitcoin block. Because each tip commits to all records before it,
     one confirmed anchor bounds the age of the entire history behind it.

     `ots verify` needs a local Bitcoin node to look up the block header. With
     no node, the proof cannot be checked *here* — that is INCOMPLETE, not
     FAILED. `ots info <proof>` shows the attestation without any lookup.

  3. CONTENT (optional, --fetch, needs network)
     For each record, fetches the full analysis result from the GRAILB API and
     confirms it hashes to the published content_hash. This step is the only
     one that depends on GRAILB's infrastructure — and note what that means:
     GRAILB cannot serve you an *altered* result (the hash would not match),
     but it can decline to serve you one at all. The chain in step 1 is what
     tells you a record is missing.

Exit code 0 if everything checks out.

    pip install opentimestamps-client   # for step 2
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from grailb_chain import PUBLISHED_FIELDS, replay_chain

# There is deliberately no default here. --fetch is the only check that talks to
# GRAILB's infrastructure, and it is optional by design: the chain and timestamp
# checks are fully offline. If the API is private (or never exists), verify.py
# still proves everything except "the result GRAILB serves matches its hash" —
# which is the one claim that inherently requires GRAILB to be reachable.
DEFAULT_API = os.getenv("GRAILB_API")
BITCOIN_MARKER = "BitcoinBlockHeaderAttestation"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}  PASS{RESET}  {msg}")


def bad(msg: str) -> None:
    print(f"{RED}  FAIL{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}  WARN{RESET}  {msg}")


def load_records(path: Path) -> list[dict]:
    if not path.exists():
        sys.exit(f"{path} not found — run this from the root of the calibration-log repo")

    records = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.exit(f"line {lineno}: not valid JSON: {e}")

        # Reject unexpected keys. A record with an extra field is a record whose
        # preimage we may be computing wrong, and a silent mismatch is worse
        # than a loud one.
        extra = set(rec) - PUBLISHED_FIELDS
        if extra:
            sys.exit(f"line {lineno}: unexpected field(s) {sorted(extra)} — this "
                     f"verifier does not know how to hash them")
        records.append(rec)

    records.sort(key=lambda r: r.get("chain_seq", 0))
    return records


def check_chain(records: list[dict]) -> bool:
    print("\n1. CHAIN INTEGRITY")
    if not records:
        warn("the log is empty")
        return True

    passed, errors = replay_chain(records)
    if passed:
        first, last = records[0], records[-1]
        ok(f"{len(records)} records replay cleanly, seq {first['chain_seq']}–{last['chain_seq']}, no gaps")
        print(f"{DIM}        tip: {last['chain_hash']}{RESET}")
    else:
        for e in errors:
            bad(e)
    return passed


def check_stamped(repo: Path, grace_minutes: int = 30) -> bool:
    """Every tip must have an .ots. A tip without one is a hole in the coverage.

    This is the check that catches a dead stamping cron. Without it the failure is
    invisible: the engine keeps writing .tip files, commits keep landing, the
    directory keeps growing — and every one of those records is silently
    un-anchored. You would not find out until someone tried to rely on a timestamp
    that was never taken, and by then the moment to take it has passed.

    A short grace window is allowed: a tip written seconds ago has legitimately
    not been picked up by the cron yet.
    """
    print("\n0. STAMP COVERAGE")
    anchors = repo / "anchors"
    if not anchors.exists():
        warn("no anchors/ directory")
        return True

    now = time.time()
    grace = grace_minutes * 60
    missing, too_fresh = [], 0

    for tip in sorted(anchors.glob("*.tip")):
        if tip.with_suffix(".tip.ots").exists():
            continue
        age = now - tip.stat().st_mtime
        if age < grace:
            too_fresh += 1
        else:
            missing.append((tip, age))

    if missing:
        for tip, age in missing:
            bad(f"{tip.name}: no .ots after {int(age // 60)} min — NOT ANCHORED. "
                f"Is the stamping cron running?")
        print(f"{DIM}        Run ots_anchor.py, then check the cron. Records at or above "
              f"the oldest unstamped tip have no independent timestamp.{RESET}")
        return False

    if too_fresh:
        warn(f"{too_fresh} tip(s) written in the last {grace_minutes} min, not yet stamped "
             f"— fine, the cron has not run yet")

    ok(f"all {len(list(anchors.glob('*.tip')))} tip(s) have an OpenTimestamps proof")
    return True


def check_timestamps(repo: Path, records: list[dict]) -> bool | None:
    """Returns True (verified), False (failed), or None (could not check)."""
    print("\n2. TIMESTAMPS")

    if subprocess.run(["which", "ots"], capture_output=True).returncode != 0:
        warn("`ots` not installed — CANNOT CHECK TIMESTAMPS. "
             "Install: pip install opentimestamps-client")
        return None

    anchors = repo / "anchors"
    proofs = sorted(anchors.glob("*.ots")) if anchors.exists() else []
    if not proofs:
        bad("no OpenTimestamps proofs found — this log has no independent timestamp, "
            "only GitHub's, which the log's owner can overwrite")
        return False

    by_seq = {r["chain_seq"]: r for r in records}
    failed = False      # something is actually WRONG
    confirmed = 0       # proofs backed by a Bitcoin block
    pending = 0         # stamped, awaiting confirmation — normal, not an error
    unverifiable = 0    # proof is fine; THIS MACHINE cannot check it

    for proof in proofs:
        tip_file = proof.with_suffix("")
        try:
            tip = json.loads(tip_file.read_text())
        except (OSError, json.JSONDecodeError) as e:
            bad(f"{proof.name}: cannot read the tip it anchors: {e}")
            failed = True
            continue

        # An anchor over a hash that isn't in the log proves nothing about the log.
        record = by_seq.get(tip["chain_seq"])
        if not record:
            bad(f"{proof.name}: anchors seq {tip['chain_seq']}, which is absent from the log")
            failed = True
            continue
        if record["chain_hash"] != tip["chain_hash"]:
            bad(f"{proof.name}: anchored hash != the log's hash at seq {tip['chain_seq']}")
            failed = True
            continue

        proc = subprocess.run(
            ["ots", "verify", str(proof.relative_to(repo))],
            cwd=repo, capture_output=True, text=True,
        )
        out = (proc.stdout + proc.stderr).strip()
        low = out.lower()

        if "success!" in low or "as of" in low:
            ok(f"seq {tip['chain_seq']} anchored — {out.splitlines()[-1]}")
            confirmed += 1

        elif "could not connect to bitcoin node" in low or "cookie file" in low:
            # The proof is fine — THIS MACHINE cannot check it. Reporting a
            # failure here tells someone their log is broken when their laptop
            # is merely missing a daemon. A verifier that cries wolf gets ignored.
            unverifiable += 1

        elif "pending" in low:
            pending += 1
            warn(f"seq {tip['chain_seq']}: stamped, awaiting Bitcoin confirmation "
                 f"(normal — takes a few hours; re-run ots_anchor.py to upgrade)")

        else:
            bad(f"{proof.name}: {out[:160]}")
            failed = True

    if failed:
        return False

    if unverifiable:
        warn(f"{unverifiable} proof(s) carry a Bitcoin attestation, but this machine "
             f"has no Bitcoin node to check it against.")
        print(f"{DIM}        The proofs are present and well-formed; only the lookup failed."
              f"\n        Run a Bitcoin node, or inspect directly: ots info <proof>{RESET}")
        return None      # INCOMPLETE, not FAILED

    if confirmed:
        newest = max(
            json.loads(p.with_suffix("").read_text())["chain_seq"]
            for p in proofs
        )
        covered = sum(1 for r in records if r["chain_seq"] <= newest)
        print(f"{DIM}        {confirmed} confirmed anchor(s); records at or below the newest "
              f"anchored tip ({covered}/{len(records)}) are timestamp-bounded{RESET}")
        if covered < len(records):
            warn(f"{len(records) - covered} record(s) are newer than the last confirmed anchor "
                 f"and are not yet independently timestamped")
        return True

    # Stamped but nothing confirmed yet. This is the expected state for the first
    # few hours after any seal. It is NOT a failure — but it is NOT verification
    # either, and saying so plainly is the whole job of this script.
    print(f"{DIM}        {pending} pending anchor(s), 0 confirmed. Until one reaches a "
          f"Bitcoin block, the only timestamp on this log is GitHub's.{RESET}")
    return None


def check_content(records: list[dict], api: str) -> bool:
    print("\n3. CONTENT")
    passed = True
    checked = unavailable = 0

    for rec in records:
        run_id = rec["run_id"]
        url = f"{api.rstrip('/')}/api/analysis/run/{run_id}"
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                body = json.loads(resp.read())
        except Exception as e:
            unavailable += 1
            warn(f"{run_id[:8]}: could not fetch from the API ({e})")
            continue

        result = body.get("result") if isinstance(body, dict) else None
        if result is None:
            unavailable += 1
            warn(f"{run_id[:8]}: API returned no result field")
            continue

        # Canonical serialization: json.dumps(..., sort_keys=True).
        # This must match exactly what the engine hashed.
        recomputed = hashlib.sha256(
            json.dumps(result, sort_keys=True).encode()
        ).hexdigest()

        if recomputed == rec["content_hash"]:
            checked += 1
        else:
            bad(f"{run_id[:8]}: content_hash mismatch — the served result is NOT "
                f"the one that was sealed")
            passed = False

    if checked:
        ok(f"{checked} result(s) hash to their published content_hash")
    if unavailable:
        warn(f"{unavailable} record(s) could not be fetched — GRAILB can withhold a "
             f"result, but the chain above proves the record exists")
    return passed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=Path("."), help="path to the calibration-log checkout")
    ap.add_argument("--fetch", action="store_true", help="also re-derive content hashes from the GRAILB API")
    ap.add_argument("--grace", type=int, default=30,
                    help="minutes a fresh tip may go unstamped before it is an error")
    ap.add_argument("--api", default=DEFAULT_API,
                    help="GRAILB API base URL (or set GRAILB_API). Required with --fetch.")
    args = ap.parse_args()

    if args.fetch and not args.api:
        sys.exit("--fetch needs an API base URL: pass --api http://localhost:8000 "
                 "or set GRAILB_API")

    repo = args.repo.resolve()
    records = load_records(repo / "calibration_log.jsonl")

    print(f"GRAILB calibration log — {len(records)} sealed record(s)")

    stamped_ok = check_stamped(repo, args.grace)
    chain_ok = check_chain(records)
    ts_ok = check_timestamps(repo, records)
    content_ok: bool | None = None
    if args.fetch:
        content_ok = check_content(records, args.api)
    else:
        print(f"\n{DIM}3. CONTENT — not checked (pass --fetch to re-derive hashes from the API){RESET}")

    results = [stamped_ok, chain_ok, ts_ok, content_ok]

    print()
    if any(r is False for r in results):
        print(f"{RED}FAILED{RESET} — see above.\n")
        return 1
    if any(r is None for r in results):
        # Never print a green check for a test that did not run. A verifier that
        # says "VERIFIED" when it skipped the timestamp check is worse than no
        # verifier at all — it launders an unchecked claim into a confirmed one.
        skipped = []
        if ts_ok is None:
            skipped.append("timestamps")
        if content_ok is None:
            skipped.append("content")
        print(f"{YELLOW}INCOMPLETE{RESET} — everything checked passed, but "
              f"{' and '.join(skipped)} could not be verified.\n")
        return 2
    print(f"{GREEN}VERIFIED{RESET} — chain intact, timestamps confirmed against Bitcoin.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())