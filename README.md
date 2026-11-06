# GRAILB Calibration Log

An append-only, hash-chained, Bitcoin-timestamped log of predictions made by the GRAILB instrument about GitHub pull requests.

Each record is sealed **before** any human reviewer responded. The point of this repo is to make it possible for someone who does not trust us to check that claim, and to say plainly where it can't yet be checked.

```bash
git clone https://github.com/grailb/calibration-log
cd calibration-log
pip install opentimestamps-client
python verify.py
```

`verify.py` exits `0` (verified), `1` (failed) or `2` (incomplete: a check couldn't run on your machine). Incomplete is not failed, and the script never reports a check as passed that it didn't run.

You don't need a Bitcoin node. Without one, `verify.py` computes from your copy of each anchor the merkle root a specific Bitcoin block must have, then asks two independent public explorers (blockstream.info and mempool.space) for that block's real merkle root. The output says when it relied on them. If you'd rather trust nothing but your own node, pass `--no-explorer`.

The scores, calls and per-PR results built on this log are at [grailb.com/calibration-log](https://grailb.com/calibration-log). Every number there traces to a `chain_seq` here.

---

## Read this first: two limits

### 1. The first 1,051 records were not timestamped when they were sealed

Records `1` to `1051` were sealed and hash-chained, but at the time their only timestamp was this repo's git history. Git history can be rewritten: commit dates are set by whoever makes the commit, and a repo can be force-pushed. We added Bitcoin anchoring after realising that, and the first anchor was taken on **2026-07-14 at 17:56 UTC, in Bitcoin block 958038**.

What that means for those records, precisely:

- **They can't have been altered or added after 2026-07-14 17:56 UTC.** That first anchor commits to the chain tip at the time, and the tip commits to every record before it. Changing any early record now would break the link to an anchor in Bitcoin.
- **For most of them, the claim at the top of this page can't be proved.** It can only be proved where the anchor came first: the PR's first reviewer response *and* its resolution both happened after 2026-07-14 17:56 UTC. For every other early record, you have our git history and our word, and you should weigh them accordingly.
- **Some early records also show later anchors** (for example seq 1035 to 1049 in block 960000, 2026-07-28). These were stamped afterwards and add nothing; the 2026-07-14 anchor is the earliest bound on everything before it.

From record `1052` on, each record is anchored to Bitcoin within hours of being sealed. `verify.py` reports any record that isn't. The same rule applies to these: the claim is proved for a record when its anchor's block precedes the PR's first reviewer response. If a reviewer replied in the hours between seal and anchor, that record is in the same position as the early ones.

We'd rather publish this than have someone find it.

### 2. The analyses themselves are not public

Each record's `content_hash` commits to the full analysis, but we don't publish the analyses: they name individual reviewers. You can check that every analysis exists and hasn't changed since it was sealed; you can't read them here. Anyone with a serious reason to check them can do so under NDA; see [Checking the analyses](#checking-the-analyses).

---

## What's here

| File | |
|---|---|
| `calibration_log.jsonl` | One JSON object per sealed prediction, in chain order. |
| `anchors/NNNNNN.tip` | A chain tip: `{"chain_seq": N, "chain_hash": "…"}`, the log as of sequence `NNNNNN`. |
| `anchors/NNNNNN.tip.ots` | An OpenTimestamps proof anchoring that tip to the Bitcoin blockchain. |
| `grailb_chain.py` | The canonical hash-chain definition. The same file runs in production. |
| `grailb_policy.py` | When a PR may be sealed: what counts as a human response. The rule our crawler applies, written down so you can check it. |
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
  "ran_at_iso":      "2026-07-14T09:31:02Z",
  "engine_version":  "1.5.0"
}
```

`chain_hash` is the SHA-256 of these fields joined in a fixed order, including the previous record's `chain_hash`. `content_hash` is the SHA-256 of the full analysis result serialized as `json.dumps(result, sort_keys=True)`, with Python's default separators and `ensure_ascii`. Every record carries exactly these keys; `verify.py` rejects a line with more or fewer.

## What this proves

**No prediction has been quietly removed.**
Each record includes the previous record's hash and a strictly incrementing sequence number. Deleting a record from the middle of the log leaves a gap and breaks every link after it. This is the property that stops a calibration log from becoming a highlight reel of the predictions that happened to work out. It holds for every record, including the first 1,051.

**The predictions existed by a specific time, and we can't fake that time.**
This is the part git alone cannot do. So we anchor chain tips to Bitcoin using [OpenTimestamps](https://opentimestamps.org). A confirmed `.ots` proof shows that a given tip existed no later than a given Bitcoin block, and because each tip commits to every record before it, one confirmed anchor bounds the age of the whole history behind it. Forging that would require rewriting Bitcoin. For records `1052` onward the anchor follows the seal by hours. For records `1` to `1051` the bound is 2026-07-14 17:56 UTC; see above.

**The analyses can't be swapped.**
Each `content_hash` commits to the full analysis. Whenever an analysis is shown to anyone, under NDA now or publicly later, it must hash to the value sealed here. We can withhold an analysis; we can't change one.

**Only the first analysis of a PR counts.**
`pr_identifier` is `UNIQUE` in the production database. The first seal for a PR is permanent; a second one is rejected, not overwritten. We cannot run the instrument ten times and keep the run we like. This is arguably a stronger guarantee than any of the cryptography above, and no amount of hashing would provide it. It is also the one guarantee here you have to take partly on trust, since the database isn't public; what you *can* check is that no `pr_identifier` appears twice in the log.

## What this does *not* prove

Being precise about this is the point of the exercise.

- **It does not prove the predictions are any good.** That's what the scores are for. This log only establishes that they are *real* and *timely*.
- **It does not prove a record was sealed before the first reviewer response unless its anchor's block came before that response.** That excludes most of records 1 to 1051 (see above), and any later record whose PR got a reply in the hours before its anchor confirmed.
- **That a fast-moving PR was sealed before its first human response.** Anchoring takes from under an hour to a few hours, and Bitcoin's block timestamps carry about two hours of tolerance, so a PR that got a response within roughly three hours of our seal can't be proved, even when our clock says we sealed first. See [Spot-checking a single pull request](#spot-checking-a-single-pull-request).
- **An OTS proof is an upper bound, not an exact time.** It shows a hash existed *no later than* a Bitcoin block. It cannot show the hash wasn't created earlier. "Sealed before the PR resolved" is exactly an upper-bound claim, so this is the right direction, but it is not a claim that the timestamp is precise.
- **Records newer than the last confirmed anchor are not yet independently timestamped.** OTS confirmation takes a few hours. `verify.py` tells you how many records fall into this window. Until an anchor confirms, the only timestamp on a record is GitHub's, which we could overwrite by force-pushing. Treat the unanchored tail with the skepticism it deserves.
- **What the analyses say.** Not public; see below.
- **That the log is complete with respect to reality.** The chain proves no record was removed *from the log*. If the instrument were never pointed at a PR at all, nothing here would show that.

## Spot-checking a single pull request

Our policy: **we never seal a PR once any human other than its author has responded.** A record proves that only if its earliest Bitcoin anchor came before the first such response, and before the PR resolved. You can check any record yourself, against GitHub and Bitcoin, without trusting us:

```bash
python verify.py --pr kubernetes/kubernetes#12345      # or paste the PR's URL
python verify.py --seq 1840                            # by position in the log
python verify.py --sample 20 --seed anything-you-like  # a random draw you can reproduce
```

For each record it prints our seal time, the earliest Bitcoin block that bounds the record, the PR's first human response, and its resolution, then one verdict:

| Verdict | Meaning |
|---|---|
| `PROVED` | The anchor came more than two hours before any human response and before the resolution. |
| `NOT PROVABLE` | The anchor came after the first human response or the resolution, or less than two hours before it. Our clock may say we sealed first; Bitcoin can't confirm it. Expected for most of records 1 to 1051, and for any PR that got a human response within a few hours of being sealed. |
| `INCONCLUSIVE` | Couldn't be checked: GitHub or the explorers couldn't be reached, or no confirmed anchor covers the record yet. |
| `VIOLATION` | By our own clock, we sealed after a human had responded. That contradicts our policy and is a failure. |

**Why a fast PR can't be proved, however honest the seal.** Two delays stack up:

1. **Anchoring takes time.** A seal is submitted to OpenTimestamps calendars, which batch many hashes into one Bitcoin transaction, and that transaction then has to be mined into a block. This usually takes between under an hour and a few hours. Record 3279, for example, was sealed at 08:31 UTC and its anchor landed in a block at 09:18.
2. **Bitcoin's clock is approximate.** A block's timestamp is set by whoever mined it and can be off by up to about two hours, so `verify.py` only counts an anchor as coming first if it came more than two hours before the event (`--margin-hours` changes this).

Together, any PR that gets a human response within roughly three hours of being sealed can't be `PROVED`. Record 3279's first human comment came at 08:58, 27 minutes after our seal by our clock and 20 minutes before the anchor, so it is `NOT PROVABLE`. That's a limit of Bitcoin as a clock, not something we can engineer away, and it falls hardest on the pull requests that move fastest.

"Human response" is defined in `grailb_policy.py`. That's the rule our crawler applies before sealing. You don't have to take our word that it does: the spot-check holds every record to this rule using GitHub's own timestamps, so any seal that broke it shows up as a `VIOLATION`. Under the current version (`grailb-policy-v1`) it is an issue comment, an inline review comment, or a review *with text*, by anyone other than the PR's author and not a bot. Two consequences you should know about:

- **A review with no text, such as a bare approval, does not count.** If one came before our seal, the spot-check prints a note saying so rather than hiding it.
- **Any login ending in `bot` is treated as a bot**, as are accounts GitHub marks as bots and the accounts listed in `BOT_LOGINS`. A human whose login happens to end in `bot` would be missed.

Reviewer names are never printed. Spot-checks need `pip install opentimestamps-client`. They make a few GitHub API calls per PR; for more than about fifteen PRs an hour, set `GITHUB_TOKEN` to any personal access token (no scopes needed).

What a spot-check can't see: a comment that was deleted from GitHub before you checked.

## Checking the analyses

The analyses name individual reviewers, so the API that serves them is not public. If you're an investor, design partner, researcher or journalist with a serious reason to check them, we'll give you access under NDA, in a data room or against a private endpoint.

The terms that make this worth doing:

- **You choose the records.** Name any `chain_seq` values you like, or have us draw them at random from a seed you supply. A review where we pick the records proves nothing.
- **We produce every record you name.** A record we can't or won't produce is itself a finding, and you're free to say so publicly. The chain shows that it exists.
- **You check the hashes yourself, on your machine.** With access to a private endpoint:
  ```bash
  python verify.py --fetch --api <endpoint we give you>
  ```
  With files from a data room, see "A result" under [Verifying by hand](#verifying-by-hand).
- **What you can publish:** whether the hashes matched, and how many records you checked. The NDA covers the content of the analyses, not the outcome of your check.

To ask: kjalleda@gmail.com

## Verifying by hand

The chain:

```python
import json
from grailb_chain import replay_chain

records = [json.loads(l) for l in open("calibration_log.jsonl") if l.strip()]
records.sort(key=lambda r: r["chain_seq"])
ok, errors = replay_chain(records)
assert ok, errors
```

No PR sealed twice:

```python
ids = [r["pr_identifier"] for r in records]
assert len(ids) == len(set(ids))
```

A timestamp, with a Bitcoin node:

```bash
ots verify anchors/001050.tip.ots
```

Without one, print the block and merkle root to look up, then compare against any block explorer you trust:

```bash
ots --no-bitcoin verify anchors/001050.tip.ots
# To verify manually, check that Bitcoin block 958038 has merkleroot …
```

Then confirm the anchored tip is actually the chain's tip at that sequence. An anchor over a hash that isn't in the log proves nothing:

```bash
cat anchors/001050.tip
grep '"chain_seq": *1050,' calibration_log.jsonl   # the comma keeps 1050 from matching 10500
```

The two `chain_hash` values must be identical.

A result, if one has been shared with you under NDA:

```python
import hashlib, json

record = next(r for r in records if r["chain_seq"] == 1050)
result = json.load(open("result_1050.json"))       # however you received it

assert hashlib.sha256(
    json.dumps(result, sort_keys=True).encode()   # the canonical form
).hexdigest() == record["content_hash"]
```

## Reporting a problem

If `verify.py` fails on a clean clone, that is a finding, and we want it. Open an issue with the output.