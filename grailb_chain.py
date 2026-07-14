"""
grailb_chain.py — canonical hash-chain definition for the GRAILB calibration log.

This module is the SINGLE SOURCE OF TRUTH for how a chain hash is computed.
It is deliberately dependency-free (stdlib only) so that the exact same file can
be vendored into the public calibration-log repo and used by verify.py.

If you change CHAIN_VERSION or the preimage format, every prior record becomes
unverifiable. Don't. Add a new version and branch on it instead.
"""

from __future__ import annotations

import hashlib

CHAIN_VERSION = "grailb-chain-v1"
GENESIS = "GENESIS"

# Fields that make up the chain preimage, in order. Order is part of the spec.
PREIMAGE_FIELDS = (
    "chain_version",
    "prev_chain_hash",
    "chain_seq",
    "run_id",
    "pr_identifier",
    "content_hash",
    "merged_hash",
    "trace_hash",
    "ran_at_iso",
    "engine_version",
)

# The exact set of keys published to calibration_log.jsonl, in sorted order.
# verify.py rejects any line whose key set differs.
PUBLISHED_FIELDS = frozenset({
    "chain_version",
    "chain_seq",
    "prev_chain_hash",
    "chain_hash",
    "run_id",
    "pr_identifier",
    "repo",
    "pr_number",
    "pr_url",
    "content_hash",
    "merged_hash",
    "trace_hash",
    "ran_at_iso",
    "engine_version",
})


def _norm(value) -> str:
    """Normalize a preimage component to a string.

    None and missing values collapse to the empty string. Everything else is
    str()'d. Integers must be passed as ints (not floats) so that chain_seq
    stringifies as "42" and never "42.0".
    """
    if value is None:
        return ""
    if isinstance(value, bool):  # guard: bools are ints in Python
        raise TypeError("bool is not a valid chain preimage component")
    if isinstance(value, float):
        raise TypeError(
            "float is not a valid chain preimage component — float repr is not "
            "stable across platforms. Use an ISO-8601 string for timestamps."
        )
    return str(value)


def build_preimage(record: dict) -> str:
    """Build the canonical preimage string for a chain record.

    Components are joined with '|'. No component may itself contain '|';
    all of them are hex digests, UUIDs, ISO timestamps, or version strings,
    so this is safe — but we assert it rather than assume it.
    """
    parts = []
    for field in PREIMAGE_FIELDS:
        if field == "chain_version":
            part = CHAIN_VERSION
        else:
            part = _norm(record.get(field))
        if "|" in part:
            raise ValueError(f"chain preimage component {field!r} contains a '|' separator")
        parts.append(part)
    return "|".join(parts)


def compute_chain_hash(record: dict) -> str:
    """SHA-256 of the canonical preimage."""
    return hashlib.sha256(build_preimage(record).encode("utf-8")).hexdigest()


def verify_record(record: dict) -> tuple[bool, str]:
    """Check that record['chain_hash'] matches its own preimage.

    Does NOT check linkage to the previous record — that is replay_chain's job.
    """
    claimed = record.get("chain_hash")
    if not claimed:
        return False, "missing chain_hash"
    expected = compute_chain_hash(record)
    if claimed != expected:
        return False, f"chain_hash mismatch (claimed {claimed[:12]}…, computed {expected[:12]}…)"
    return True, "ok"


def replay_chain(records: list[dict]) -> tuple[bool, list[str]]:
    """Replay an ordered list of published records and verify the full chain.

    Checks, for every record:
      - chain_seq is exactly one greater than its predecessor (no gaps, no forks)
      - prev_chain_hash equals the predecessor's chain_hash
      - chain_hash is a correct hash of the record's own preimage

    A gap in chain_seq means a record was withheld. A prev_chain_hash mismatch
    means a record was altered or reordered. Both are fatal.

    Returns (ok, errors). Records must already be sorted by chain_seq.
    """
    errors: list[str] = []
    prev_hash = GENESIS
    prev_seq = 0

    for record in records:
        seq = record.get("chain_seq")
        rid = record.get("run_id", "<no run_id>")

        if not isinstance(seq, int):
            errors.append(f"{rid}: chain_seq is not an integer ({seq!r})")
            continue

        if seq != prev_seq + 1:
            errors.append(
                f"seq {seq} (run {rid}): expected seq {prev_seq + 1} — "
                f"{'GAP: record(s) withheld' if seq > prev_seq + 1 else 'FORK or duplicate'}"
            )

        if record.get("prev_chain_hash") != prev_hash:
            errors.append(
                f"seq {seq} (run {rid}): prev_chain_hash does not match the "
                f"previous record's chain_hash — the chain is broken here"
            )

        ok, reason = verify_record(record)
        if not ok:
            errors.append(f"seq {seq} (run {rid}): {reason}")

        prev_hash = record.get("chain_hash") or prev_hash
        prev_seq = seq if isinstance(seq, int) else prev_seq

    return (not errors), errors


def tip_of(records: list[dict]) -> dict:
    """Return {'chain_hash', 'chain_seq'} for the last record, or genesis."""
    if not records:
        return {"chain_hash": GENESIS, "chain_seq": 0}
    last = records[-1]
    return {"chain_hash": last["chain_hash"], "chain_seq": last["chain_seq"]}