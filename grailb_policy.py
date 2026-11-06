"""
grailb_policy.py — when a pull request may be sealed.

The rule GRAILB's crawler applies before sealing, written down so anyone can
check it. verify.py holds every sealed record to this rule using GitHub's own
timestamps: a seal that broke it shows up as a VIOLATION, whatever code made it.
Stdlib only.

The policy: GRAILB never seals a PR once any human other than its author has
responded. A response is an issue comment, an inline review comment, or a
review with text, by an account that is neither the PR's author nor a bot.

If you change this rule, records sealed under the old rule are still judged by
the old rule in public. Version it (POLICY_VERSION) rather than editing in place.
"""

from __future__ import annotations

POLICY_VERSION = "grailb-policy-v1"

# Bot accounts that GitHub reports as ordinary users. Matched case-insensitively.
BOT_LOGINS = frozenset({
    "k8s-ci-robot", "coveralls", "codecov", "dependabot", "renovate",
    "github-actions", "k8s-triage-robot", "k8s-cherrypick-robot", "clawsweeper",
})


def is_bot(login: str, user_type: str = "") -> bool:
    """Exactly the crawler's rule. Note: any login ending in "bot" counts as a
    bot, which would also exclude a human whose login happens to end that way."""
    if user_type == "Bot":
        return True
    l = (login or "").lower()
    return (
        "[bot]" in l
        or l.endswith("-bot")
        or l.endswith("bot")
        or l in BOT_LOGINS
    )


# kind -> the GitHub field holding its time
RESPONSE_KINDS = {
    "issue_comment":  "created_at",     # GET /issues/{n}/comments
    "review_comment": "created_at",     # GET /pulls/{n}/comments
    "review":         "submitted_at",   # GET /pulls/{n}/reviews
}


def counts_as_response(kind: str, item: dict, pr_author: str) -> bool:
    """Does this raw GitHub item close the prediction window?

    `item` is one object as returned by the GitHub REST API for `kind`.
    A review without text (e.g. a bare approval) does NOT count under v1;
    its inline comments, if any, arrive as review_comments and do count.
    """
    user = item.get("user") or {}
    login = user.get("login") or ""
    if is_bot(login, user.get("type", "")):
        return False
    if login == pr_author:
        return False
    if kind == "review" and not (item.get("body") or ""):
        return False
    return True