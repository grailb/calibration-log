# GRAILB Calibration Log

An append-only, hash-chained, Bitcoin-timestamped log of predictions made by the GRAILB instrument about GitHub pull requests.

Each record is sealed **before** before any human reviewer responded. The point of this repo is to make it possible for someone who does not trust us to check that claim.

```bash
git clone https://github.com/grailb/calibration-log
cd calibration-log
pip install opentimestamps-client
python verify.py
```

---

## What's here

| File | |
|---|---|
| `calibration_log.jsonl` | One JSON object per sealed prediction, in chain order. |
| `anchors/NNNNNN.tip` | A chain tip: the hash of the log as of sequence `NNNNNN`. |
| `anchors/NNNNNN.tip.ots` | An OpenTimestamps proof anchoring that tip to the Bitcoin blockchain. |
| `grailb_chain.py` | The canonical hash-chain definition. The same file runs in production. |
| `verify.py` | The verifier. Run it. |

## The record format

```json
{
  "chain_version":   "grailb-chain-v1",
  "chain_seq":       124,
  "prev_chain_hash": "ab12…",
  "chain_hash":      "cd34…",
  "run_id":          "…",
  "pr_identifier":   "…",
  "repo":            "kubernetes/kubernetes",
  "pr_number":       12345,
  "pr_url":          "https://github.com/…",
  "content_hash":    "ef56…",
  "merged_hash":     "…",
  "trace_hash":      "…",
  "ran_at":          "2026-07-14T09:31:02Z",
  "engine_version":  "1.5.0"
}
```

`chain_hash` is the SHA-256 of these fields joined in a fixed order, including the previous record's `chain_hash`. `content_hash` is the SHA-256 of the canonical (`sort_keys=True`) serialization of the full analysis result.

## What this proves

**The predictions were not altered after the fact.**
Each `content_hash` commits to the full analysis. Fetch the result from the GRAILB API, re-hash it, compare. `python verify.py --fetch` does this for every record.

**No prediction has been quietly removed.**
Each record includes the previous record's hash and a strictly incrementing sequence number. Deleting a record from the middle of the log leaves a gap and breaks every link after it. This is the property that stops a calibration log from becoming a highlight reel of the predictions that happened to work out.

**The predictions existed by a specific time — and we can't fake that time.**
This is the part that git alone cannot do. Git commit timestamps are attacker-supplied metadata; `GIT_COMMITTER_DATE=...` is a one-line forgery. So we anchor chain tips to Bitcoin using [OpenTimestamps](https://opentimestamps.org). A confirmed `.ots` proof shows that a given tip hash existed no later than a given Bitcoin block, and because each tip commits to every record before it, one confirmed anchor bounds the age of the whole history behind it. Forging that would require rewriting Bitcoin.

**Only the first analysis of a PR counts.**
`pr_identifier` is `UNIQUE` in the production database. The first seal for a PR is permanent; a second one is rejected, not overwritten. We cannot run the instrument ten times and keep the run we like. This is arguably a stronger guarantee than any of the cryptography above, and no amount of hashing would provide it.

## What this does *not* prove

Being precise about this is the point of the exercise.

- **It does not prove the predictions are any good.** That's what the scores are for. This log only establishes that they are *real* and *timely*.
- **An OTS proof is an upper bound, not an exact time.** It shows a hash existed *no later than* a Bitcoin block. It cannot show the hash wasn't created earlier. For our purposes that's the right direction — "sealed before the PR resolved" is exactly an upper bound — but it is not a claim that the timestamp is precise.
- **Records newer than the last confirmed anchor are not yet independently timestamped.** OTS confirmation takes a few hours. `verify.py` tells you how many records fall into this window. Until an anchor confirms, the only timestamp on a record is GitHub's — and while commits made through GitHub's API are server-timestamped and signed with GitHub's `web-flow` key, we could still force-push this repo. Treat the unanchored tail with the skepticism it deserves.
- **We can decline to serve you a result.** `content_hash` means we can't hand you an *altered* analysis, but the full result lives on our API, and an API can go away. The chain proves a record exists; it does not compel us to show it to you. If a `--fetch` run reports a record as unavailable, that's on us.
- **The chain does not prove the log is complete with respect to reality.** It proves no record was removed *from the log*. If the instrument were never pointed at a PR at all, nothing here would show that.

## Verifying by hand

The chain:

```python
import json, hashlib
from grailb_chain import replay_chain

records = [json.loads(l) for l in open("calibration_log.jsonl") if l.strip()]
records.sort(key=lambda r: r["chain_seq"])
ok, errors = replay_chain(records)
assert ok, errors
```

A timestamp:

```bash
ots verify anchors/000124.tip.ots
# Success! Bitcoin block N attests existence as of <date>
```

Then confirm the anchored tip is actually the chain's tip at that sequence — an anchor over a hash that isn't in the log proves nothing:

```bash
grep '"chain_seq": *124' calibration_log.jsonl
cat anchors/000124.tip
```

A result:

```python
import hashlib, json, urllib.request

record = records[123]
result = json.load(urllib.request.urlopen(
    f"https://api.grailb.com/api/analysis/run/{record['run_id']}"))["result"]

assert hashlib.sha256(
    json.dumps(result, sort_keys=True).encode()   # sort_keys=True is the canonical form
).hexdigest() == record["content_hash"]
```

## Reporting a problem

If `verify.py` fails on a clean clone, that is a finding, and we want it. Open an issue with the output.
