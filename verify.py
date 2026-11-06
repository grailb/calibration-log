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

     `ots verify` normally checks against a local Bitcoin node. Most people
     don't run one, so when it can't, this script falls back to public block
     explorers: `ots --no-bitcoin verify` computes, from YOUR copy of the tip
     file, the merkle root a specific Bitcoin block must have; two independent
     explorers (blockstream.info, mempool.space) are asked what that block's
     merkle root actually is. A match is reported as confirmed VIA EXPLORER,
     which means trusting those explorers to report Bitcoin honestly. Pass
     --no-explorer to refuse that trust; without a node the result is then
     INCOMPLETE, not FAILED.

  3. CONTENT (optional, --fetch, needs network and an API that serves results)
     For each record, fetches the full analysis result and confirms it hashes
     to the published content_hash. The analyses are NOT currently served
     publicly: they name individual reviewers. content_hash still commits to
     each one, so GRAILB cannot later reveal an *altered* result; it can only
     decline to reveal one. This step exists for anyone GRAILB grants access to.
     It is not part of a default run, and its absence does not make a run
     incomplete.

Exit codes: 0 verified, 1 failed, 2 incomplete (a check that should have run
could not, e.g. no Bitcoin node or no `ots`).

    pip install opentimestamps-client   # for step 2
"""

from __future__ import annotations

import argparse
import random
import re
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from grailb_chain import PUBLISHED_FIELDS, replay_chain
from grailb_policy import POLICY_VERSION, RESPONSE_KINDS, counts_as_response, is_bot

# There is deliberately no default here. --fetch is the only check that talks to
# GRAILB's infrastructure, and it is optional by design: the chain and timestamp
# checks are fully offline. If the API is private (or never exists), verify.py
# still proves everything except "the result GRAILB serves matches its hash" —
# which is the one claim that inherently requires GRAILB to be reachable.
DEFAULT_API = os.getenv("GRAILB_API")
BITCOIN_MARKER = "BitcoinBlockHeaderAttestation"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def fmt_age(seconds: float) -> str:
    m = int(seconds // 60)
    if m < 120:
        return f"{m} min"
    h = m // 60
    return f"{h} h" if h < 48 else f"{h // 24} days"


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
        missing = PUBLISHED_FIELDS - set(rec)
        if missing:
            sys.exit(f"line {lineno}: missing field(s) {sorted(missing)} — every "
                     f"published record carries the same key set")
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


def tip_written_at(repo: Path, tip: Path) -> float:
    """When this tip was written: the time of the commit that added it.

    NOT the file's mtime. On a fresh clone every file's mtime is the moment of
    the clone, so a tip left unstamped for months would look "written seconds
    ago" and be excused by the grace window — on exactly the machines this
    script is for. Falls back to mtime only for a tip that isn't committed yet
    (the maintainer's working copy) or when git isn't available.
    """
    try:
        proc = subprocess.run(
            ["git", "log", "--diff-filter=A", "-1", "--format=%ct", "--",
             str(tip.relative_to(repo))],
            cwd=repo, capture_output=True, text=True, timeout=20,
        )
        out = proc.stdout.strip()
        if proc.returncode == 0 and out:
            return float(out.splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return tip.stat().st_mtime


def _ranges(seqs: list[int]) -> str:
    """[1,2,3,7,9,10] -> '1–3, 7, 9–10' (first few ranges only)."""
    out, start, prev = [], None, None
    for s in sorted(seqs):
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            out.append(f"{start}–{prev}" if start != prev else f"{start}")
            start = prev = s
    if start is not None:
        out.append(f"{start}–{prev}" if start != prev else f"{start}")
    return ", ".join(out[:6]) + (f", and {len(out) - 6} more ranges" if len(out) > 6 else "")


def check_identity(records: list[dict]) -> bool:
    """Bind the readable fields to the sealed ones, and say what each seal covers.

    repo, pr_number and pr_url are published but NOT in the chain preimage.
    pr_identifier IS, and it is sha256("{repo}::pr::{pr_number}"). Recomputing
    it is what stops a record being relabelled to a different pull request.
    """
    print("\n1b. PULL REQUEST IDENTITY AND SEAL COVERAGE")
    wrong_id, wrong_url = [], []
    for r in records:
        expected = hashlib.sha256(f"{r['repo']}::pr::{r['pr_number']}".encode()).hexdigest()
        if r["pr_identifier"] != expected:
            wrong_id.append(r["chain_seq"])
        if r.get("pr_url") and r["pr_url"].rstrip("/") != f"https://github.com/{r['repo']}/pull/{r['pr_number']}":
            wrong_url.append(r["chain_seq"])

    passed = True
    if wrong_id:
        bad(f"{len(wrong_id)} record(s) name a repo or PR number that doesn't match their sealed "
            f"pr_identifier: seq {_ranges(wrong_id)}")
        passed = False
    else:
        ok(f"every record's repo and PR number match its sealed pr_identifier")
    if wrong_url:
        bad(f"{len(wrong_url)} record(s) have a pr_url that doesn't match their repo and PR number: "
            f"seq {_ranges(wrong_url)}")
        passed = False

    # What each seal commits to. Not a failure either way: just what's true.
    no_trace = [r["chain_seq"] for r in records if not r.get("trace_hash")]
    no_merged = [r["chain_seq"] for r in records if not r.get("merged_hash")]
    full = len(records) - len(set(no_trace) | set(no_merged))
    print(f"{DIM}        {full}/{len(records)} record(s) seal all three: content, trace and analytical hashes{RESET}")
    if no_trace:
        print(f"{DIM}        {len(no_trace)} seal no trace_hash (seq {_ranges(no_trace)}): their retrieval "
              f"trace, and the model recorded in it, aren't committed{RESET}")
    if no_merged:
        print(f"{DIM}        {len(no_merged)} seal no merged_hash (seq {_ranges(no_merged)}): their "
              f"analytical layer isn't committed{RESET}")
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

    tips = sorted(anchors.glob("*.tip"))
    for tip in tips:
        if tip.with_suffix(".tip.ots").exists():
            continue
        age = now - tip_written_at(repo, tip)
        if age < grace:
            too_fresh += 1
        else:
            missing.append((tip, age))

    if missing:
        for tip, age in missing:
            bad(f"{tip.name}: no .ots after {fmt_age(age)} — NOT ANCHORED")
        print(f"{DIM}        Records covered only by an unstamped tip have no independent "
              f"timestamp.\n        (Maintainers: run ots_anchor.py, then check the "
              f"stamping cron.){RESET}")
        return False

    if too_fresh:
        warn(f"{too_fresh} tip(s) committed in the last {grace_minutes} min, not yet "
             f"stamped — expected, stamping runs on a schedule")

    stamped = len(tips) - too_fresh
    if stamped:
        ok(f"{stamped} of {len(tips)} tip(s) have an OpenTimestamps proof")
    return True


# ── public block explorers (fallback when there is no local Bitcoin node) ────

EXPLORERS = (
    ("blockstream.info", "https://blockstream.info/api"),
    ("mempool.space",    "https://mempool.space/api"),
)
_MANUAL_RE = re.compile(r"block\s+(\d+)\s+has\s+merkleroot\s+([0-9a-fA-F]{64})")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_explorer_cache: dict[tuple[str, int], dict] = {}
EXPLORERS_USED: set[str] = set()


def _http_get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "grailb-verify/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _explorer_block(name: str, base: str, height: int) -> dict:
    """{'merkle_root', 'time', 'hash'} for the block at `height`, or {'error'}."""
    key = (name, height)
    if key in _explorer_cache:
        return _explorer_cache[key]
    try:
        block_hash = _http_get(f"{base}/block-height/{height}").decode().strip().lower()
        if not _HEX64.match(block_hash):
            raise ValueError(f"unexpected block hash {block_hash[:40]!r}")
        block = json.loads(_http_get(f"{base}/block/{block_hash}"))
        root = str(block.get("merkle_root", "")).lower()
        if not _HEX64.match(root):
            raise ValueError("no merkle_root in response")
        result = {"merkle_root": root, "time": block.get("timestamp"), "hash": block_hash}
    except Exception as e:  # network, TLS, JSON, shape: all mean "couldn't ask"
        msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in msg:
            msg += (" (on macOS with python.org Python, run 'Install Certificates.command' "
                    "from the Python folder in Applications)")
        result = {"error": msg[:200]}
    _explorer_cache[key] = result
    return result


def _same_root(a: str, b: str) -> bool:
    """Merkle roots are conventionally shown byte-reversed; accept either order."""
    return a == b or a == bytes.fromhex(b)[::-1].hex()


def check_via_explorers(repo: Path, proof: Path) -> tuple[str, str]:
    """
    Returns (state, message), state one of:
      'confirmed'    every explorer that answered agrees with the proof
      'mismatch'     an explorer reports a DIFFERENT merkle root: something is wrong
      'unreachable'  the proof names a block, but no explorer could be asked
      'none'         the proof has no Bitcoin attestation yet (pending)
    """
    proc = subprocess.run(
        ["ots", "--no-bitcoin", "verify", str(proof.relative_to(repo))],
        cwd=repo, capture_output=True, text=True,
    )
    out = proc.stdout + proc.stderr
    if "does not match" in out.lower():
        return "mismatch", "the tip file does not match the proof (ots: file does not match original)"
    claims = {(int(h), r.lower()) for h, r in _MANUAL_RE.findall(out)}
    if not claims:
        return "none", out.strip()[:160]

    # A proof can carry attestations from several calendars; one confirmed one suffices.
    errors = []
    for height, root in sorted(claims):
        answers = {name: _explorer_block(name, base, height) for name, base in EXPLORERS}
        good = {n: a for n, a in answers.items() if "error" not in a}
        if not good:
            errors.extend(f"{n}: {a['error']}" for n, a in answers.items())
            continue
        wrong = [n for n, a in good.items() if not _same_root(a["merkle_root"], root)]
        if wrong:
            return "mismatch", (f"block {height}: {', '.join(wrong)} report merkle root "
                                f"{good[wrong[0]]['merkle_root'][:16]}…, the proof needs {root[:16]}…")
        EXPLORERS_USED.update(good)
        t = next((a["time"] for a in good.values() if a.get("time")), None)
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "time unknown"
        return "confirmed", (f"Bitcoin block {height} ({when}), merkle root agreed by "
                             f"{' and '.join(sorted(good))}")
    return "unreachable", "; ".join(errors)[:300]


def check_timestamps(repo: Path, records: list[dict], use_explorers: bool = True,
                     verbose: bool = False) -> bool | None:
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
    confirmed_seqs: list[int] = []
    passed_by_block: dict[str, list[int]] = {}   # one PASS line per block, not per tip
    via_explorer = 0    # confirmed through public explorers, not a node

    for proof in proofs:
        tip_file = proof.with_suffix("")
        try:
            tip = json.loads(tip_file.read_text())
            tip_seq, tip_hash = tip["chain_seq"], tip["chain_hash"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as e:
            bad(f"{proof.name}: cannot read the tip it anchors: {e!r}")
            failed = True
            continue

        # An anchor over a hash that isn't in the log proves nothing about the log.
        record = by_seq.get(tip_seq)
        if not record:
            bad(f"{proof.name}: anchors seq {tip_seq}, which is absent from the log")
            failed = True
            continue
        if record["chain_hash"] != tip_hash:
            bad(f"{proof.name}: anchored hash != the log's hash at seq {tip_seq}")
            failed = True
            continue

        proc = subprocess.run(
            ["ots", "verify", str(proof.relative_to(repo))],
            cwd=repo, capture_output=True, text=True,
        )
        out = (proc.stdout + proc.stderr).strip()
        low = out.lower()

        if "success!" in low or "as of" in low:
            passed_by_block.setdefault(out.splitlines()[-1], []).append(tip_seq)
            confirmed += 1
            confirmed_seqs.append(tip_seq)

        elif use_explorers and "does not match" not in low:
            # No local node (the usual case). Ask public explorers instead.
            state, msg = check_via_explorers(repo, proof)
            if state == "confirmed":
                passed_by_block.setdefault(msg, []).append(tip_seq)
                confirmed += 1
                via_explorer += 1
                confirmed_seqs.append(tip_seq)
            elif state == "mismatch":
                bad(f"{proof.name}: {msg}")
                failed = True
            elif state == "unreachable":
                warn(f"seq {tip_seq}: proof names a Bitcoin block, but no explorer could be "
                     f"reached ({msg})")
                unverifiable += 1
            elif "pending" in low or "pending" in msg.lower():
                pending += 1
                warn(f"seq {tip_seq}: stamped, awaiting Bitcoin confirmation "
                     f"(normal for a few hours after stamping)")
            else:
                bad(f"{proof.name}: {out[:160]}")
                failed = True

        elif "could not connect to bitcoin node" in low or "cookie file" in low:
            # --no-explorer and no node: the proof may be fine, THIS MACHINE can't
            # check it. Reporting a failure here tells someone their log is broken
            # when their laptop is merely missing a daemon.
            unverifiable += 1

        elif "pending" in low:
            pending += 1
            warn(f"seq {tip_seq}: stamped, awaiting Bitcoin confirmation "
                 f"(normal for a few hours after stamping)")

        else:
            bad(f"{proof.name}: {out[:160]}")
            failed = True

    # One line per Bitcoin block, in seq order. --verbose prints every tip.
    for msg, seqs in sorted(passed_by_block.items(), key=lambda kv: min(kv[1])):
        if verbose:
            for q in sorted(seqs):
                ok(f"seq {q} anchored — {msg}")
        else:
            ok(f"{len(seqs)} tip(s), seq {_ranges(seqs)} — {msg}")

    if failed:
        return False

    if via_explorer:
        print(f"{DIM}        {via_explorer} of these confirmed through public block explorers, "
              f"not a Bitcoin node you run.\n        To remove that trust: run a node, or "
              f"pass --no-explorer.{RESET}")

    if unverifiable and not confirmed:
        warn(f"{unverifiable} proof(s) carry a Bitcoin attestation that this machine "
             f"could not check.")
        print(f"{DIM}        The proofs are present; only the lookup failed. Run a Bitcoin "
              f"node, allow network access, or inspect by hand:\n        "
              f"ots --no-bitcoin verify <proof>  (prints the block and merkle root to look up){RESET}")
        return None      # INCOMPLETE, not FAILED
    if unverifiable:
        warn(f"{unverifiable} other proof(s) could not be checked from this machine")

    if confirmed:
        # Only CONFIRMED anchors bound anything. A pending proof is a promise.
        newest = max(confirmed_seqs)
        covered = sum(1 for r in records if r["chain_seq"] <= newest)
        print(f"{DIM}        {confirmed} confirmed anchor(s); records at or below the newest "
              f"confirmed tip, seq {newest} ({covered}/{len(records)}), are timestamp-bounded{RESET}")
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


# ── 4. spot-check single PRs (--pr / --seq / --sample) ──────────────────────
#
# The policy: GRAILB never seals a PR once any human other than its author has
# responded. A record PROVES that only if its earliest Bitcoin anchor came
# before the first such response (and before the PR resolved). This checks it,
# one PR at a time, against GitHub and Bitcoin, without trusting GRAILB.

# What counts as a human response lives in grailb_policy.py, the same file the
# crawler runs, so this check applies the engine's rule exactly.

BLOCK_TIME_MARGIN_H = 2   # Bitcoin header timestamps can be off by ~2 hours


def _ts(iso: str | None) -> float | None:
    if not iso:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _fmt(t: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t is not None else "—"


def _gh(path: str) -> tuple[object, str | None]:
    """GET api.github.com/<path>; returns (json, next_page_url)."""
    url = path if path.startswith("http") else f"https://api.github.com/{path}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "grailb-verify/1"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            nxt = None
            for part in (resp.headers.get("Link") or "").split(","):
                if 'rel="next"' in part:
                    nxt = part[part.find("<") + 1:part.find(">")]
            return json.loads(resp.read()), nxt
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise RuntimeError("GitHub rate limit reached; set GITHUB_TOKEN to a personal "
                               "access token (no scopes needed) and re-run") from None
        raise RuntimeError(f"GitHub returned HTTP {e.code} for {url}") from None


def _first_human_response(owner: str, repo: str, number: int, author: str):
    """Earliest response that closes the prediction window under grailb_policy.
    Returns (time, kind, bare_review_time). bare_review_time is the earliest
    review by a human with no text, which policy v1 does not count; it's
    reported, not judged. Logins are never printed."""
    earliest, kind, bare = None, None, None
    sources = (
        (f"repos/{owner}/{repo}/issues/{number}/comments?per_page=100", "issue_comment", "comment"),
        (f"repos/{owner}/{repo}/pulls/{number}/reviews?per_page=100", "review", "review"),
        (f"repos/{owner}/{repo}/pulls/{number}/comments?per_page=100", "review_comment", "review comment"),
    )
    for path, k, label in sources:
        field = RESPONSE_KINDS[k]
        url = path
        while url:
            items, url = _gh(url)
            found = None
            for it in items:
                t = _ts(it.get(field))
                if t is None:
                    continue
                if counts_as_response(k, it, author):
                    found = t if found is None else min(found, t)
                elif k == "review":
                    u = it.get("user") or {}
                    if not is_bot(u.get("login") or "", u.get("type", "")) and u.get("login") != author:
                        bare = t if bare is None else min(bare, t)
            if found is not None:
                if earliest is None or found < earliest:
                    earliest, kind = found, label
                if k != "review":
                    break   # chronological listing: later pages can't be earlier
    return earliest, kind, bare


_proof_index: list[dict] | None = None


def _load_proofs(repo: Path, by_seq: dict) -> list[dict]:
    """Every anchor whose .ots carries a Bitcoin attestation, parsed in-process.
    Only anchors whose tip file matches the proof AND the log are kept."""
    global _proof_index
    if _proof_index is not None:
        return _proof_index
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    except ImportError:
        sys.exit("spot-checks need the OpenTimestamps library: pip install opentimestamps-client")

    out = []
    for proof in sorted((repo / "anchors").glob("*.tip.ots")):
        tip_file = proof.with_suffix("")
        try:
            raw = tip_file.read_bytes()
            tip = json.loads(raw)
            with open(proof, "rb") as f:
                dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
        except Exception:
            continue   # the full run reports unreadable anchors; here we just skip them
        if dtf.file_digest != hashlib.sha256(raw).digest():
            continue
        rec = by_seq.get(tip.get("chain_seq"))
        if not rec or rec["chain_hash"] != tip.get("chain_hash"):
            continue
        for msg, att in dtf.timestamp.all_attestations():
            if isinstance(att, BitcoinBlockHeaderAttestation):
                out.append({"seq": tip["chain_seq"], "height": att.height,
                            "root": msg[::-1].hex(), "file": proof.name})
    _proof_index = out
    return out


def _earliest_anchor(repo: Path, by_seq: dict, seq: int, use_explorers: bool) -> dict:
    """The earliest Bitcoin block that bounds record `seq`: any anchor over a tip
    at or after `seq` commits to it, so take the lowest block among them."""
    cands = sorted((p for p in _load_proofs(repo, by_seq) if p["seq"] >= seq),
                   key=lambda p: p["height"])
    if not cands:
        return {"state": "none"}
    if not use_explorers:
        c = cands[0]
        return {"state": "no_time", "height": c["height"], "file": c["file"]}
    errors = []
    for c in cands[:5]:   # lowest first; fall through only if explorers can't answer
        answers = {n: _explorer_block(n, b, c["height"]) for n, b in EXPLORERS}
        good = {n: a for n, a in answers.items() if "error" not in a}
        if not good:
            errors += [a["error"] for a in answers.values()]
            continue
        wrong = [n for n, a in good.items() if not _same_root(a["merkle_root"], c["root"])]
        if wrong:
            return {"state": "mismatch", "file": c["file"], "height": c["height"],
                    "explorers": wrong}
        EXPLORERS_USED.update(good)
        t = next((a["time"] for a in good.values() if a.get("time")), None)
        return {"state": "confirmed", "height": c["height"], "time": t, "file": c["file"],
                "explorers": sorted(good)}
    return {"state": "unreachable", "error": "; ".join(errors)[:200]}


_PR_RE = re.compile(r"(?:github\.com/)?([\w.-]+)/([\w.-]+)(?:#|/pull/)(\d+)")


def spot_check(repo: Path, records: list[dict], targets: list[dict],
               use_explorers: bool, margin_h: float) -> bool | None:
    print(f"\n4. SPOT CHECK — {len(targets)} pull request(s)")
    print(f"{DIM}        policy ({POLICY_VERSION}, see grailb_policy.py): no PR is sealed after "
          f"any human other than its author has responded.\n        proved when the earliest Bitcoin anchor precedes that response "
          f"and the resolution by > {margin_h:g} h.{RESET}")
    by_seq = {r["chain_seq"]: r for r in records}
    margin = margin_h * 3600
    failed = inconclusive = False
    tally = {"PROVED": 0, "NOT PROVABLE": 0, "INCONCLUSIVE": 0, "VIOLATION": 0,
             "ANCHOR MISMATCH": 0}

    for rec in targets:
        seq, owner_repo, number = rec["chain_seq"], rec["repo"], rec["pr_number"]
        print(f"\n  {owner_repo}#{number}  (seq {seq})")
        sealed = _ts(rec.get("ran_at_iso"))
        print(f"{DIM}        sealed, by our clock      {_fmt(sealed)}{RESET}")

        anchor = _earliest_anchor(repo, by_seq, seq, use_explorers)
        if anchor["state"] == "confirmed":
            print(f"{DIM}        earliest anchor           Bitcoin block {anchor['height']}, "
                  f"{_fmt(anchor['time'])} ({anchor['file']}, via {' and '.join(anchor['explorers'])}){RESET}")
        elif anchor["state"] == "mismatch":
            bad(f"{anchor['file']}: {', '.join(anchor['explorers'])} disagree with the proof "
                f"about block {anchor['height']}")
            tally["ANCHOR MISMATCH"] += 1
            failed = True
            continue
        else:
            why = {"none": "no confirmed anchor covers this record yet",
                   "no_time": f"anchored in block {anchor.get('height')}, but --no-explorer leaves "
                              f"no block time to compare; look it up on your node",
                   "unreachable": f"no explorer reachable ({anchor.get('error')})"}[anchor["state"]]
            warn(f"INCONCLUSIVE — {why}")
            tally["INCONCLUSIVE"] += 1
            inconclusive = True
            continue

        try:
            owner, name = owner_repo.split("/", 1)
            pr, _ = _gh(f"repos/{owner}/{name}/pulls/{number}")
            author = (pr.get("user") or {}).get("login") or ""
            resolved = _ts(pr.get("merged_at") or pr.get("closed_at"))
            outcome = "merged" if pr.get("merged_at") else ("closed" if pr.get("closed_at") else "open")
            first, kind, bare = _first_human_response(owner, name, number, author)
        except Exception as e:
            warn(f"INCONCLUSIVE — {e}")
            tally["INCONCLUSIVE"] += 1
            inconclusive = True
            continue

        print(f"{DIM}        first human response      "
              f"{(_fmt(first) + ' (' + kind + ')') if first else 'none yet'}{RESET}")
        if bare is not None and sealed is not None and bare < sealed and (first is None or bare < first):
            print(f"{DIM}        note: a review with no text came at {_fmt(bare)}, before the seal. "
                  f"{POLICY_VERSION} doesn't count those as a response.{RESET}")
        print(f"{DIM}        resolved                  "
              f"{(_fmt(resolved) + ' (' + outcome + ')') if resolved else 'still open'}{RESET}")

        # Our own clock against the policy. Not proof of anything, but a seal
        # that our clock places AFTER a human response contradicts the policy.
        if sealed is not None and first is not None and sealed > first:
            mins = (sealed - first) / 60
            gap = f"{mins:.0f} min" if mins < 120 else f"{mins / 60:.1f} h"
            bad(f"VIOLATION — sealed {_fmt(sealed)} by our own clock, {gap} after a human "
                f"response at {_fmt(first)}")
            tally["VIOLATION"] += 1
            failed = True
            continue

        events = [t for t in (first, resolved) if t is not None]
        t_anchor = anchor["time"]
        if all(t_anchor + margin < t for t in events):
            ok(f"PROVED — anchored {_fmt(t_anchor)}, more than {margin_h:g} h before "
               f"{'any human response or resolution' if events else 'anything has happened on the PR yet'}")
            tally["PROVED"] += 1
        else:
            # Not proved. Name the event that blocks it and say by how much.
            name, t_ev = (("the first human response", first)
                          if first is not None and not (t_anchor + margin < first)
                          else ("the resolution", resolved))
            d = abs(t_anchor - t_ev) / 60
            gap = f"{d:.0f} min" if d < 120 else f"{d / 60:.1f} h"
            when = (f"came {gap} after {name}" if t_anchor >= t_ev
                    else f"came only {gap} before {name}, inside Bitcoin's ~{margin_h:g} h timestamp tolerance")
            ours = ""
            if sealed is not None and sealed < t_ev:
                s_gap = (t_ev - sealed) / 60
                ours = (f" Our clock says sealed {s_gap:.0f} min before it"
                        if s_gap < 120 else f" Our clock says sealed {s_gap / 60:.1f} h before it")
                ours += "; Bitcoin can't confirm that."
            print(f"  {YELLOW}NOT PROVABLE{RESET}  the anchor ({_fmt(t_anchor)}) {when}.{ours}")
            tally["NOT PROVABLE"] += 1

    print("\n  " + ", ".join(f"{v} {k.lower()}" for k, v in tally.items() if v))
    if failed:
        return False
    return None if inconclusive else True


def pick_targets(records: list[dict], prs: list[str], seqs: list[int],
                 sample: int, seed: str | None) -> list[dict]:
    by_seq = {r["chain_seq"]: r for r in records}
    by_pr = {(r["repo"].lower(), int(r["pr_number"])): r for r in records
             if r.get("repo") and r.get("pr_number") is not None}
    out = []
    for p in prs:
        m = _PR_RE.search(p)
        if not m:
            sys.exit(f"--pr {p!r}: expected owner/repo#123 or a pull request URL")
        key = (f"{m.group(1)}/{m.group(2)}".lower(), int(m.group(3)))
        if key not in by_pr:
            sys.exit(f"--pr {p}: not in the log. GRAILB never sealed this pull request.")
        out.append(by_pr[key])
    for s in seqs:
        if s not in by_seq:
            sys.exit(f"--seq {s}: not in the log")
        out.append(by_seq[s])
    if sample:
        seed = seed or str(random.SystemRandom().randrange(10**9))
        print(f"{DIM}Sampling {sample} record(s) with --seed {seed} "
              f"(re-run with the same seed to get the same sample){RESET}")
        out += random.Random(seed).sample(records, min(sample, len(records)))
    seen, uniq = set(), []
    for r in out:
        if r["chain_seq"] not in seen:
            seen.add(r["chain_seq"])
            uniq.append(r)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=Path("."), help="path to the calibration-log checkout")
    ap.add_argument("--fetch", action="store_true",
                    help="also re-derive content hashes from an API that serves results "
                         "(not public: the analyses name individual reviewers)")
    ap.add_argument("--pr", action="append", default=[], metavar="OWNER/REPO#N",
                    help="spot-check one pull request (repeatable; a PR URL also works)")
    ap.add_argument("--seq", action="append", default=[], type=int, metavar="N",
                    help="spot-check the record at this chain_seq (repeatable)")
    ap.add_argument("--sample", type=int, default=0, metavar="K",
                    help="spot-check K records drawn at random")
    ap.add_argument("--seed", help="seed for --sample, so anyone can reproduce the draw")
    ap.add_argument("--margin-hours", type=float, default=BLOCK_TIME_MARGIN_H,
                    help="required gap between anchor and response, for Bitcoin's "
                         "timestamp tolerance (default 2)")
    ap.add_argument("--verbose", action="store_true",
                    help="print a line for every anchor instead of one per Bitcoin block")
    ap.add_argument("--no-explorer", action="store_true",
                    help="never consult public block explorers; without a local Bitcoin "
                         "node, timestamps are then reported INCOMPLETE")
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

    if args.pr or args.seq or args.sample:
        targets = pick_targets(records, args.pr, args.seq, args.sample, args.seed)
        chain_ok = check_chain(records) and check_identity(records)
        spot_ok = spot_check(repo, records, targets, not args.no_explorer, args.margin_hours)
        print()
        if not chain_ok or spot_ok is False:
            print(f"{RED}FAILED{RESET} — see above.\n")
            return 1
        if spot_ok is None:
            print(f"{YELLOW}INCOMPLETE{RESET} — no failures, but some records couldn't be checked "
              f"(see INCONCLUSIVE above).\n")
            return 2
        print(f"{GREEN}CHECKED{RESET} — chain intact; every spot-checked record is either proved "
              f"or honestly reported as not provable.\n")
        return 0

    stamped_ok = check_stamped(repo, args.grace)
    chain_ok = check_chain(records)
    id_ok = check_identity(records) if records else True
    ts_ok = check_timestamps(repo, records, use_explorers=not args.no_explorer, verbose=args.verbose)
    content_ok: bool | None = None
    if args.fetch:
        content_ok = check_content(records, args.api)
    else:
        print(f"\n{DIM}3. CONTENT — not checked: the analyses are not public (they name "
              f"individual reviewers). content_hash still commits to each one.{RESET}")

    # content_ok is None when --fetch wasn't requested. That's not a check that
    # failed to run; it's a check nobody asked for. Only count it if requested.
    results = [stamped_ok, chain_ok, id_ok, ts_ok] + ([content_ok] if args.fetch else [])

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
        if args.fetch and content_ok is None:
            skipped.append("content")
        print(f"{YELLOW}INCOMPLETE{RESET} — everything checked passed, but "
              f"{' and '.join(skipped)} could not be verified.\n")
        return 2
    via = (f" (via {' and '.join(sorted(EXPLORERS_USED))}, not your own node)"
           if EXPLORERS_USED else "")
    print(f"{GREEN}VERIFIED{RESET} — chain intact, timestamps confirmed against Bitcoin{via}"
          + ("" if args.fetch else "; content not checked (the analyses are not public)")
          + ".\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())