# GRAILB Public Calibration Log

This repository is an append-only log of sealed analysis records produced by 
the GRAILB instrument. Each line in `calibration_log.jsonl` is a JSON object 
representing one sealed PR analysis.

## Verification

1. Find the entry for the PR you want to verify in `calibration_log.jsonl`
2. Fetch the result from the GRAILB API: <TODO>
3. Recompute the hash:
```python
   import hashlib, json
   # sort_keys=True is required — this is the canonical serialization
   recomputed = hashlib.sha256(
       json.dumps(result_json, sort_keys=True).encode()
   ).hexdigest()
   assert recomputed == published_content_hash
```
4. Check the git commit timestamp — that is the authoritative clock
   proving when this prediction was sealed.

## What this proves

- The instrument's prediction was not altered after the fact
- The prediction was sealed at the git commit timestamp — before reviewers responded
- Anyone can independently verify without trusting GRAILB's infrastructure
