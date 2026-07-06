"""
trivy_pr_comment.py
───────────────────
Posts Trivy vulnerability results as a RESOLVABLE THREAD on the PR.

Flow:
  1. Trivy scans → JSON
  2. Script posts a review with a line-level comment thread on the first
     changed file → creates a resolvable thread in "Files changed" tab
  3. Branch protection rule "Require conversation resolution" blocks merge
     until an admin clicks "Resolve conversation"
  4. On clean scan → bot dismisses the REQUEST_CHANGES review automatically

Merge is blocked by TWO gates:
  • REQUEST_CHANGES review   → admin must dismiss
  • Status check exit 1      → auto-clears on clean scan
"""

import json
import os
import sys
import requests
from datetime import datetime, timezone
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────

TRIVY_REPORT  = "trivy-report.json"
GH_TOKEN      = os.environ["GH_TOKEN"]
REPO          = os.environ["REPO"]
PR_NUMBER     = os.environ["PR_NUMBER"]
PR_HEAD_SHA   = os.environ["PR_HEAD_SHA"]

API_BASE      = "https://api.github.com"
HEADERS       = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept":        "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "UNKNOWN":  "⚪",
}
BLOCK_ON = {"CRITICAL", "HIGH"}

# ── Parse Trivy JSON ──────────────────────────────────────────────────────────

def parse_trivy_report(path: str):
    counts    = defaultdict(int)
    top_vulns = []

    if not os.path.exists(path):
        print(f"[WARN] {path} not found — treating as zero vulnerabilities.")
        return dict(counts), top_vulns

    with open(path) as f:
        report = json.load(f)

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] += 1
            if sev in BLOCK_ON and len(top_vulns) < 10:
                top_vulns.append({
                    "severity":  sev,
                    "pkg":       vuln.get("PkgName", "—"),
                    "vuln_id":   vuln.get("VulnerabilityID", "—"),
                    "title":     (vuln.get("Title") or "No title")[:80],
                    "fixed_ver": vuln.get("FixedVersion") or "No fix available",
                })

    return dict(counts), top_vulns


# ── Build comment body ────────────────────────────────────────────────────────

def build_thread_body(counts: dict, top_vulns: list) -> str:
    """Vulnerability summary posted as a resolvable review thread."""
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total      = sum(counts.get(s, 0) for s in SEVERITY_ORDER)

    rows = ""
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        rows += f"| {SEVERITY_EMOJI[sev]} **{sev}** | `{cnt}` |\n"

    summary_table = (
        "| Severity | Count |\n"
        "|:---------|------:|\n"
        f"{rows}"
        f"| **TOTAL** | **`{total}`** |"
    )

    detail_section = ""
    if top_vulns:
        detail_rows = "\n".join(
            f"| {SEVERITY_EMOJI[v['severity']]} {v['severity']} "
            f"| `{v['vuln_id']}` | `{v['pkg']}` | {v['title']} | {v['fixed_ver']} |"
            for v in top_vulns
        )
        detail_section = (
            "\n<details>\n"
            "<summary>🔍 Top Critical & High Vulnerabilities (up to 10)</summary>\n\n"
            "| Severity | CVE / ID | Package | Title | Fix Version |\n"
            "|:---------|:---------|:--------|:------|:------------|\n"
            f"{detail_rows}\n\n"
            "</details>\n"
        )

    return (
        f"## 🛡️ Trivy Vulnerability Scan — Action Required\n\n"
        f"🚨 **CRITICAL or HIGH vulnerabilities were found. Merge is BLOCKED.**\n\n"
        f"### Vulnerability Summary\n\n"
        f"{summary_table}\n"
        f"{detail_section}\n"
        f"---\n\n"
        f"### 🔧 How to unblock this PR\n\n"
        f"1. Fix all **CRITICAL** and **HIGH** vulnerabilities above\n"
        f"2. Push the fix — Trivy will re-scan automatically\n"
        f"3. Once the scan is clean, an **Admin** must:\n"
        f"   - Click **Resolve conversation** on this thread ✅\n"
        f"   - Dismiss the `Changes requested` review\n"
        f"4. Merge will be enabled after both steps ✅\n\n"
        f"---\n\n"
        f"> 📅 Scanned at **{scanned_at}** on commit `{PR_HEAD_SHA[:8]}` "
        f"via [Trivy](https://github.com/aquasecurity/trivy).\n"
        f"> ⚠️ Only users with **Admin or Maintain** role can resolve this thread.\n"
    )


def build_clean_body() -> str:
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"## 🛡️ Trivy Vulnerability Scan Report\n\n"
        f"✅ **No CRITICAL or HIGH vulnerabilities found — merge is unblocked.**\n\n"
        f"> 📅 Scanned at **{scanned_at}** on commit `{PR_HEAD_SHA[:8]}`.\n"
    )


# ── GitHub API helpers ────────────────────────────────────────────────────────

def get_pr_files(repo: str, pr: str) -> list:
    """Return list of files changed in the PR."""
    url  = f"{API_BASE}/repos/{repo}/pulls/{pr}/files"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    return resp.json()


def get_first_diffable_file(repo: str, pr: str) -> dict | None:
    """
    Return the first file that has a patch (diff) — needed to anchor
    a review line comment which creates a resolvable thread.
    Prefer package.json / go.mod / requirements.txt as they relate to vulns.
    Falls back to any file with a patch.
    """
    files = get_pr_files(repo, pr)
    preferred_names = {
        "package.json", "package-lock.json", "go.mod", "go.sum",
        "requirements.txt", "Pipfile.lock", "pom.xml", "build.gradle",
        "Gemfile.lock", "composer.lock", "yarn.lock",
    }

    # Try preferred dependency files first
    for f in files:
        if f.get("patch") and os.path.basename(f["filename"]) in preferred_names:
            return f

    # Fall back to any file with a diff
    for f in files:
        if f.get("patch"):
            return f

    return None


def find_bot_review(repo: str, pr: str) -> dict | None:
    """Find the latest REQUEST_CHANGES review from github-actions[bot]."""
    url  = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    for review in reversed(resp.json()):
        login = review.get("user", {}).get("login", "")
        state = review.get("state", "")
        if "github-actions" in login and state == "CHANGES_REQUESTED":
            return review
    return None


def find_bot_review_comments(repo: str, pr: str) -> list:
    """Find all review comments posted by github-actions[bot]."""
    url  = f"{API_BASE}/repos/{repo}/pulls/{pr}/comments"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    return [
        c for c in resp.json()
        if "github-actions" in c.get("user", {}).get("login", "")
        and "Trivy Vulnerability Scan" in c.get("body", "")
    ]


def post_review_with_thread(repo: str, pr: str, sha: str, body: str) -> bool:
    """
    Post a REQUEST_CHANGES review with a line-level comment on the first
    changed file. This creates a resolvable thread in 'Files changed'.

    Returns True if review+thread posted, False if fallback needed.
    """
    target_file = get_first_diffable_file(repo, pr)

    if not target_file:
        print("[WARN] No diffable file found — cannot create line comment thread.")
        return False

    filename = target_file["filename"]
    patch    = target_file.get("patch", "")

    # Find the last added line number in the patch to anchor the comment
    position = 1   # default: first line of diff
    for i, line in enumerate(patch.splitlines(), start=1):
        if line.startswith("+") and not line.startswith("+++"):
            position = i

    print(f"[INFO] Anchoring thread to: {filename} (diff position {position})")

    url     = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews"
    payload = {
        "commit_id": sha,
        "event":     "REQUEST_CHANGES",
        "body":      (
            "🚨 **Trivy found CRITICAL or HIGH vulnerabilities.**\n"
            "See the review thread below. An admin must resolve it before merge."
        ),
        "comments": [
            {
                "path":     filename,
                "position": position,
                "body":     body,
            }
        ],
    }

    resp = requests.post(url, headers=HEADERS, json=payload)

    if resp.status_code == 422:
        print(f"[WARN] 422 from review API — PR author == workflow actor. "
              f"Falling back to plain review (no thread). Response: {resp.text}")
        return False

    resp.raise_for_status()
    review_id = resp.json().get("id")
    print(f"[INFO] Review with thread posted (id={review_id}) on {filename}.")
    return True


def post_plain_review(repo: str, pr: str, sha: str, body: str):
    """
    Fallback: post a REQUEST_CHANGES review without a line comment.
    Used when the bot cannot review its own PR or no diff is available.
    """
    url     = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews"
    payload = {
        "commit_id": sha,
        "event":     "REQUEST_CHANGES",
        "body":      body,
    }
    resp = requests.post(url, headers=HEADERS, json=payload)
    if resp.status_code == 422:
        print(f"[WARN] 422 — cannot post review. Merge still blocked via status check.")
    else:
        resp.raise_for_status()
        print(f"[INFO] Plain blocking review posted (id={resp.json().get('id')}).")


def update_existing_thread_comment(repo: str, comment_id: int, body: str):
    """Update the body of an existing review line comment (thread)."""
    url  = f"{API_BASE}/repos/{repo}/pulls/comments/{comment_id}"
    resp = requests.patch(url, headers=HEADERS, json={"body": body})
    resp.raise_for_status()
    print(f"[INFO] Updated existing thread comment #{comment_id}.")


def dismiss_blocking_review(repo: str, pr: str, review_id: int):
    """Auto-dismiss the bot's REQUEST_CHANGES review when scan is clean."""
    url  = f"{API_BASE}/repos/{repo}/pulls/{pr}/reviews/{review_id}/dismissals"
    resp = requests.put(
        url,
        headers=HEADERS,
        json={"message": "✅ Trivy scan is clean — no CRITICAL/HIGH found. Merge unblocked."},
    )
    if resp.ok:
        print(f"[INFO] Dismissed blocking review #{review_id}.")
    else:
        print(f"[WARN] Could not auto-dismiss review #{review_id}: {resp.text}\n"
              f"       Admin must manually dismiss via GitHub UI.")


def delete_legacy_plain_comments(repo: str, pr: str):
    """Remove any old plain issue comments posted by previous script versions."""
    url  = f"{API_BASE}/repos/{repo}/issues/{pr}/comments"
    resp = requests.get(url, headers=HEADERS, params={"per_page": 100})
    resp.raise_for_status()
    for c in resp.json():
        login = c.get("user", {}).get("login", "")
        if "github-actions" in login and "Trivy Vulnerability Scan" in c.get("body", ""):
            del_resp = requests.delete(
                f"{API_BASE}/repos/{repo}/issues/comments/{c['id']}",
                headers=HEADERS,
            )
            if del_resp.ok:
                print(f"[INFO] Deleted legacy plain comment #{c['id']}.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"[INFO] Parsing {TRIVY_REPORT} ...")
    counts, top_vulns = parse_trivy_report(TRIVY_REPORT)
    print(f"[INFO] Counts: {dict(counts)}")

    blocking = any(counts.get(sev, 0) > 0 for sev in BLOCK_ON)

    # Always clean up old plain comments first
    delete_legacy_plain_comments(REPO, PR_NUMBER)

    existing_review  = find_bot_review(REPO, PR_NUMBER)
    existing_threads = find_bot_review_comments(REPO, PR_NUMBER)

    if blocking:
        body = build_thread_body(counts, top_vulns)

        if existing_threads:
            # Update the existing thread comment in-place (no duplicate thread)
            update_existing_thread_comment(REPO, existing_threads[0]["id"], body)
            print("[INFO] Updated existing vulnerability thread.")
        elif existing_review:
            # Review exists but thread comment was resolved — open a fresh thread
            print("[INFO] Previous thread was resolved but vulns still present — posting new review thread.")
            posted = post_review_with_thread(REPO, PR_NUMBER, PR_HEAD_SHA, body)
            if not posted:
                post_plain_review(REPO, PR_NUMBER, PR_HEAD_SHA, body)
        else:
            # First time — post review + thread
            posted = post_review_with_thread(REPO, PR_NUMBER, PR_HEAD_SHA, body)
            if not posted:
                post_plain_review(REPO, PR_NUMBER, PR_HEAD_SHA, body)

    else:
        # Scan is clean
        if existing_review:
            dismiss_blocking_review(REPO, PR_NUMBER, existing_review["id"])
        else:
            # No previous block — post a clean bill comment
            url  = f"{API_BASE}/repos/{REPO}/issues/{PR_NUMBER}/comments"
            resp = requests.post(url, headers=HEADERS, json={"body": build_clean_body()})
            resp.raise_for_status()
            print("[INFO] Posted clean-scan comment.")

    print("[DONE]")
    sys.exit(0)


if __name__ == "__main__":
    main()
