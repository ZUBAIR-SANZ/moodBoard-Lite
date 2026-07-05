"""
trivy_pr_comment.py
───────────────────
Parses trivy-report.json, posts a formatted Vulnerability Summary comment
on the PR, and submits a blocking "REQUEST_CHANGES" review so the PR
cannot be merged until the review is dismissed or approved.

Env vars (injected by GitHub Actions):
  GH_TOKEN       – GITHUB_TOKEN with pull-requests: write
  REPO           – e.g. "trayalabs1/my-service"
  PR_NUMBER      – pull request number
  PR_HEAD_SHA    – HEAD commit SHA of the PR branch
"""

import json
import os
import sys
import requests
from datetime import datetime, timezone
from collections import defaultdict

# ── Config ───────────────────────────────────────────────────────────────────

TRIVY_REPORT   = "trivy-report.json"
GH_TOKEN       = os.environ["GH_TOKEN"]
REPO           = os.environ["REPO"]
PR_NUMBER      = os.environ["PR_NUMBER"]
PR_HEAD_SHA    = os.environ["PR_HEAD_SHA"]

API_BASE       = "https://api.github.com"
HEADERS        = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_EMOJI  = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "UNKNOWN":  "⚪",
}
SEVERITY_THRESHOLD = {   # counts that trigger REQUEST_CHANGES
    "CRITICAL": 0,       # any CRITICAL → block
    "HIGH":     0,       # any HIGH     → block
    "MEDIUM":   sys.maxsize,   # MEDIUM/LOW → informational only
    "LOW":      sys.maxsize,
}

# ── Parse Trivy JSON ─────────────────────────────────────────────────────────

def parse_trivy_report(path: str) -> dict:
    """Return {severity: count} and a list of top vulnerability details."""
    counts     = defaultdict(int)
    top_vulns  = []          # [(severity, pkg, vuln_id, title), ...]

    if not os.path.exists(path):
        print(f"[WARN] {path} not found — no vulnerabilities reported.")
        return counts, top_vulns

    with open(path) as f:
        report = json.load(f)

    results = report.get("Results", [])
    for result in results:
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] += 1

            # Collect top 10 CRITICAL + HIGH for the detail table
            if sev in ("CRITICAL", "HIGH") and len(top_vulns) < 10:
                top_vulns.append({
                    "severity":  sev,
                    "pkg":       vuln.get("PkgName", "—"),
                    "vuln_id":   vuln.get("VulnerabilityID", "—"),
                    "title":     (vuln.get("Title") or "No title")[:80],
                    "fixed_ver": vuln.get("FixedVersion") or "No fix available",
                })

    return dict(counts), top_vulns


# ── Build PR comment body ────────────────────────────────────────────────────

def build_comment(counts: dict, top_vulns: list, blocking: bool) -> str:
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)

    status_badge = (
        "🚨 **Action Required — vulnerabilities must be resolved before merging.**"
        if blocking else
        "✅ No blocking vulnerabilities found. Review recommended before merge."
    )

    # Summary table
    rows = ""
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        emoji = SEVERITY_EMOJI[sev]
        rows += f"| {emoji} **{sev}** | `{cnt}` |\n"

    summary_table = f"""\
| Severity | Count |
|:---------|------:|
{rows}| **TOTAL** | **`{total}`** |"""

    # Top vulns detail
    detail_section = ""
    if top_vulns:
        detail_rows = "\n".join(
            f"| {SEVERITY_EMOJI[v['severity']]} {v['severity']} "
            f"| `{v['vuln_id']}` "
            f"| `{v['pkg']}` "
            f"| {v['title']} "
            f"| {v['fixed_ver']} |"
            for v in top_vulns
        )
        detail_section = f"""
<details>
<summary>🔍 Top Critical & High Vulnerabilities (up to 10)</summary>

| Severity | CVE / ID | Package | Title | Fix Version |
|:---------|:---------|:--------|:------|:------------|
{detail_rows}

</details>
"""

    comment = f"""## 🛡️ Trivy Vulnerability Scan Report

{status_badge}

### Vulnerability Summary

{summary_table}
{detail_section}
---

**What to do:**
- 🔴 **CRITICAL / HIGH** — Must be fixed or have an approved exception before this PR can be merged.
- 🟡 **MEDIUM / LOW** — Review and remediate where feasible; document accepted risks.
- Run `trivy fs .` locally to reproduce this scan.
- Update dependencies, base images, or apply patches to resolve findings.

> 📅 Scanned at **{scanned_at}** on commit `{PR_HEAD_SHA[:8]}` via [Trivy](https://github.com/aquasecurity/trivy).
> This comment updates automatically on each push to the PR.
"""
    return comment


# ── GitHub API helpers ───────────────────────────────────────────────────────

def find_existing_bot_comment(repo: str, pr: str) -> int | None:
    """Return comment ID of a previous scan comment posted by github-actions[bot]."""
    url  = f"{API_BASE}/repos/{repo}/issues/{pr}/comments"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    for c in resp.json():
        login = c.get("user", {}).get("login", "")
        if "github-actions" in login and "Trivy Vulnerability Scan Report" in c.get("body", ""):
            return c["id"]
    return None


def upsert_pr_comment(repo: str, pr: str, body: str):
    """Update existing bot comment or create a new one."""
    existing_id = find_existing_bot_comment(repo, pr)
    if existing_id:
        url  = f"{API_BASE}/repos/{repo}/issues/comments/{existing_id}"
        resp = requests.patch(url, headers=HEADERS, json={"body": body})
        print(f"[INFO] Updated existing comment #{existing_id}")
    else:
        url  = f"{API_BASE}/repos/{repo}/issues/{pr}/comments"
        resp = requests.post(url, headers=HEADERS, json={"body": body})
        print(f"[INFO] Created new PR comment")
    resp.raise_for_status()


def post_blocking_review(repo: str, pr: str, sha: str):
    """
    Submit a REQUEST_CHANGES review — this blocks the PR from being merged
    until the review is dismissed or a new APPROVE review is submitted.

    Note: GitHub does not allow a user to review their own PR.
    If the workflow token belongs to the PR author, the review call
    will return 422; we catch that and warn instead of failing.
    """
    url     = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews"
    payload = {
        "commit_id": sha,
        "event":     "REQUEST_CHANGES",
        "body":      (
            "🚨 **Trivy found CRITICAL or HIGH vulnerabilities.**\n\n"
            "This review blocks merging. Please resolve the findings listed "
            "in the PR comment above and re-run the scan. Once clean, request a "
            "dismissal of this review from a repo admin or code owner."
        ),
    }
    resp = requests.post(url, headers=HEADERS, json=payload)
    if resp.status_code == 422:
        print(f"[WARN] Cannot submit REQUEST_CHANGES review "
              f"(likely PR author == workflow actor). "
              f"Consider adding a dedicated bot account as a required reviewer. "
              f"Response: {resp.text}")
    else:
        resp.raise_for_status()
        print("[INFO] Blocking REQUEST_CHANGES review submitted.")


def dismiss_stale_blocking_reviews(repo: str, pr: str):
    """
    Dismiss any previously submitted REQUEST_CHANGES reviews from the bot
    when the current scan is clean, so the PR can be merged.
    """
    url  = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    for review in resp.json():
        if (review.get("state") == "CHANGES_REQUESTED"
                and "github-actions" in review.get("user", {}).get("login", "")):
            review_id = review["id"]
            dismiss_url = f"{url}/{review_id}/dismissals"
            d_resp = requests.put(
                dismiss_url,
                headers=HEADERS,
                json={"message": "✅ Trivy scan is now clean — no CRITICAL/HIGH vulnerabilities found."},
            )
            if d_resp.ok:
                print(f"[INFO] Dismissed stale blocking review #{review_id}")
            else:
                print(f"[WARN] Could not dismiss review #{review_id}: {d_resp.text}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"[INFO] Parsing Trivy report: {TRIVY_REPORT}")
    counts, top_vulns = parse_trivy_report(TRIVY_REPORT)

    print(f"[INFO] Vulnerability counts: {dict(counts)}")

    # Determine if we should block the PR
    blocking = any(
        counts.get(sev, 0) > threshold
        for sev, threshold in SEVERITY_THRESHOLD.items()
        if sev in ("CRITICAL", "HIGH")
    )

    comment_body = build_comment(counts, top_vulns, blocking)

    print(f"[INFO] Posting PR comment on {REPO}#{PR_NUMBER}")
    upsert_pr_comment(REPO, PR_NUMBER, comment_body)

    if blocking:
        print(f"[INFO] Submitting blocking REQUEST_CHANGES review...")
        post_blocking_review(REPO, PR_NUMBER, PR_HEAD_SHA)
    else:
        print(f"[INFO] No CRITICAL/HIGH found — dismissing any stale blocking reviews...")
        dismiss_stale_blocking_reviews(REPO, PR_NUMBER)

    print("[DONE] Vulnerability report complete.")
    # Exit 0 always — the PR block is enforced via GitHub review, not CI failure
    sys.exit(0)


if __name__ == "__main__":
    main()
