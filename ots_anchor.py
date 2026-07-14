#!/usr/bin/env python3
"""
ots_anchor.py — OpenTimestamps worker for the GRAILB calibration log.

Run this on a cron (every 15 min is plenty). It does three things:

  1. STAMP   any anchors/*.tip that has no .ots proof yet.
  2. UPGRADE any .ots proof that is still "pending" into a real Bitcoin attestation.
  3. PUSH    the resulting proofs back to the log repo.

WHY TWO PHASES
--------------
`ots stamp` returns in about a second, but what it gives you is a *calendar
commitment*: a promise from public calendar servers that your hash will be
included in an upcoming Bitcoin block. That is not yet a Bitcoin timestamp.
Several hours later, once the block confirms, `ots upgrade` rewrites the .ots
file to contain the full Merkle path down to a Bitcoin block header. Only then
is the proof independently verifiable by anyone with a Bitcoin node and no
trust in the calendar servers, in GitHub, or in you.

If you only ever run `ots stamp` and never `ots upgrade`, you have a pile of
IOUs, not timestamps. This is the single most common way OTS integrations
quietly fail — the files look right and verify against nothing.

WHAT AN OTS PROOF ACTUALLY PROVES
---------------------------------
It proves the hash existed NO LATER THAN the timestamp of the Bitcoin block.
It cannot prove the hash wasn't created earlier — and that's fine, because for
a calibration claim the direction you need is exactly the one you get:
"this prediction existed before the PR resolved."

It does NOT prove:
  - that you ran the engine only once on this PR (the UNIQUE index on
    pr_identifier is what gives you that, and it's a stronger guarantee)
  - that the prediction is any good

Setup:
    pip install opentimestamps-client
    git clone git@github.com:grailb/calibration-log.git /srv/calibration-log

Usage:
    python ots_anchor.py --repo /srv/calibration-log
    python ots_anchor.py --repo /srv/calibration-log --verify-only
    python ots_anchor.py --repo /srv/calibration-log --backfill  # stamp historical tips
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grailb_chain import replay_chain  # noqa: E402

log = logging.getLogger("ots_anchor")

# A proof that has been upgraded contains a Bitcoin attestation. A pending one
# only carries calendar-server URLs.
#
# This is the tag byte-string the OpenTimestamps format uses to mark a Bitcoin
# block header attestation. Scanning for it lets us answer "is this upgraded?"
# by reading a few hundred bytes, instead of spawning an `ots info` subprocess.
# That matters: this check runs against EVERY anchor on EVERY cron tick, and an
# upgraded proof can never become un-upgraded — so at 1000+ anchors we would be
# forking 1000 processes every 15 minutes to re-answer a settled question.
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
BITCOIN_MARKER = "BitcoinBlockHeaderAttestation"


def is_upgraded(ots_path: Path, repo: Path) -> bool:
    """True if the proof carries a Bitcoin attestation rather than only calendar URLs.

    Fast path: look for the attestation tag in the raw bytes.
    Slow path: if the tag is absent, confirm with `ots info` before treating the
    proof as pending. The fallback keeps us correct even if the tag constant is
    ever wrong — a false 'pending' costs one redundant `ots upgrade` (a harmless
    no-op), whereas a false 'upgraded' would silently skip a proof forever.
    """
    try:
        if BITCOIN_TAG in ots_path.read_bytes():
            return True
    except OSError:
        return False

    proc = run(["ots", "info", str(ots_path.relative_to(repo))], cwd=repo, check=False)
    return BITCOIN_MARKER in proc.stdout


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc


def ensure_ots_installed() -> None:
    if subprocess.run(["which", "ots"], capture_output=True).returncode != 0:
        sys.exit("`ots` not found. Install it: pip install opentimestamps-client")


def load_log(repo: Path) -> list[dict]:
    path = repo / "calibration_log.jsonl"
    if not path.exists():
        return []
    records = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            records.append(json.loads(raw))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"calibration_log.jsonl line {lineno} is not valid JSON: {e}")
    records.sort(key=lambda r: r.get("chain_seq", 0))
    return records


def stamp_new_tips(repo: Path) -> list[Path]:
    """Stamp every .tip that has no .ots yet."""
    anchors = repo / "anchors"
    if not anchors.exists():
        log.info("no anchors/ directory yet — nothing to stamp")
        return []

    unstamped = sorted(t for t in anchors.glob("*.tip") if not t.with_suffix(".tip.ots").exists())
    if not unstamped:
        log.info("all tips already stamped")
        return []

    stamped = []
    for tip in unstamped:
        rel = tip.relative_to(repo)
        log.info("stamping %s", rel)
        try:
            # `ots stamp` writes <file>.ots next to the file.
            run(["ots", "stamp", str(rel)], cwd=repo)
            stamped.append(tip.with_suffix(".tip.ots"))
        except RuntimeError as e:
            # Calendar servers are best-effort and occasionally flaky. The next
            # cron run retries this tip; nothing is lost, we just anchor later.
            log.warning("stamp failed for %s (will retry next run): %s", rel, e)
    return stamped


def upgrade_pending(repo: Path) -> list[Path]:
    """Upgrade any still-pending proof into a Bitcoin attestation.

    Already-upgraded proofs are skipped on a byte check, so the cost of this does
    not grow with the size of the archive — only with the number of proofs still
    awaiting confirmation, which is bounded by the seal rate over a few hours.
    """
    anchors = repo / "anchors"
    if not anchors.exists():
        return []

    all_proofs = sorted(anchors.glob("*.ots"))
    pending = [p for p in all_proofs if not is_upgraded(p, repo)]

    if not pending:
        log.info("all %d proof(s) confirmed in Bitcoin", len(all_proofs))
        return []

    upgraded, still_pending = [], []
    for ots in pending:
        rel = ots.relative_to(repo)
        # `ots upgrade` is a harmless no-op (rc != 0) if the block has not
        # confirmed yet — typically a few hours after stamping.
        proc = run(["ots", "upgrade", str(rel)], cwd=repo, check=False)
        if proc.returncode == 0 and is_upgraded(ots, repo):
            log.info("upgraded %s → Bitcoin attestation", rel)
            upgraded.append(ots)
        else:
            still_pending.append(ots.name)

    # One line, not one per file. A wall of routine "still pending" lines is how
    # a genuine error scrolls past unread.
    if still_pending:
        log.info("%d proof(s) awaiting Bitcoin confirmation (%s%s) — %d confirmed",
                 len(still_pending),
                 ", ".join(still_pending[:3]),
                 "…" if len(still_pending) > 3 else "",
                 len(all_proofs) - len(still_pending))

    return upgraded


def verify_all(repo: Path) -> bool:
    """Replay the chain, then verify every OTS proof. Both must pass."""
    ok = True

    records = load_log(repo)
    chain_ok, errors = replay_chain(records)
    if chain_ok:
        log.info("chain OK — %d records, no gaps, no forks", len(records))
    else:
        ok = False
        log.error("CHAIN BROKEN — %d problem(s):", len(errors))
        for e in errors:
            log.error("  %s", e)

    anchors = repo / "anchors"
    proofs = sorted(anchors.glob("*.ots")) if anchors.exists() else []
    if not proofs:
        log.warning("no OTS proofs found — the log has no independent timestamp")
        return False

    # Cross-check: every anchored tip hash must actually appear in the chain.
    # An anchor for a hash that isn't in the log is meaningless.
    by_seq = {r.get("chain_seq"): r for r in records}
    confirmed = 0
    for ots in proofs:
        tip_file = ots.with_suffix("")  # anchors/000123.tip.ots -> anchors/000123.tip
        try:
            tip = json.loads(tip_file.read_text())
        except (OSError, json.JSONDecodeError) as e:
            log.error("%s: cannot read tip file: %s", ots.name, e)
            ok = False
            continue

        record = by_seq.get(tip["chain_seq"])
        if not record:
            log.error("%s: anchors seq %s, which is not in the log", ots.name, tip["chain_seq"])
            ok = False
            continue
        if record["chain_hash"] != tip["chain_hash"]:
            log.error("%s: anchored hash does not match the log's hash at that seq", ots.name)
            ok = False
            continue

        proc = run(["ots", "verify", str(ots.relative_to(repo))], cwd=repo, check=False)
        out = proc.stdout + proc.stderr
        if "Success!" in out or "as of" in out:
            log.info("%s: %s", ots.name, out.strip().splitlines()[-1])
            confirmed += 1
        elif "Pending" in out or "pending" in out:
            log.info("%s: still pending Bitcoin confirmation", ots.name)
        else:
            log.error("%s: verification failed: %s", ots.name, out.strip()[:200])
            ok = False

    if confirmed == 0:
        log.warning(
            "no proof has a confirmed Bitcoin attestation yet — until one does, "
            "the only timestamp you have is GitHub's, which you can overwrite"
        )

    return ok


def commit_and_push(repo: Path, paths: list[Path], message: str) -> None:
    if not paths:
        return
    rels = [str(p.relative_to(repo)) for p in paths]
    run(["git", "add", *rels], cwd=repo)
    status = run(["git", "status", "--porcelain"], cwd=repo)
    if not status.stdout.strip():
        log.info("nothing to commit")
        return
    run(["git", "commit", "-m", message], cwd=repo)
    run(["git", "push"], cwd=repo)
    log.info("pushed: %s", message)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, required=True, help="local checkout of the calibration-log repo")
    ap.add_argument("--verify-only", action="store_true", help="verify chain + proofs, change nothing")
    ap.add_argument("--no-push", action="store_true", help="commit locally but don't push")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s",
    )
    ensure_ots_installed()

    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        sys.exit(f"{repo} is not a git checkout")

    if args.verify_only:
        return 0 if verify_all(repo) else 1

    run(["git", "pull", "--ff-only"], cwd=repo)

    # Never anchor a chain that doesn't replay. A Bitcoin attestation over a
    # broken chain makes the break permanent and publicly provable.
    records = load_log(repo)
    chain_ok, errors = replay_chain(records)
    if not chain_ok:
        log.error("refusing to anchor — the chain does not replay:")
        for e in errors:
            log.error("  %s", e)
        return 1

    stamped = stamp_new_tips(repo)
    if stamped and not args.no_push:
        commit_and_push(repo, stamped, f"ots: stamp {len(stamped)} tip(s)")

    upgraded = upgrade_pending(repo)
    if upgraded and not args.no_push:
        commit_and_push(repo, upgraded, f"ots: upgrade {len(upgraded)} proof(s) to Bitcoin attestation")

    # A tip with no proof after a full run means the calendars rejected it or the
    # network is down. Exit non-zero so this lands in ots.log as an error rather
    # than scrolling past as a normal-looking run. An unstamped tip is a record
    # with no independent timestamp, and every minute it stays that way is a
    # minute of the ordering claim you cannot get back.
    anchors = repo / "anchors"
    unstamped = [t for t in sorted(anchors.glob("*.tip"))
                 if not t.with_suffix(".tip.ots").exists()] if anchors.exists() else []
    if unstamped:
        log.error(
            "%d tip(s) STILL UNSTAMPED after this run: %s — these records are NOT anchored",
            len(unstamped), ", ".join(t.name for t in unstamped),
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())