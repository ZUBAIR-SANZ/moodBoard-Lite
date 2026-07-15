"""trivy_pr_comment.py — Dependabot edition (resolvable-thread model)

Posts the Dependabot vulnerability report as a RESOLVABLE review thread on the
PR (a line comment anchored to a file already in the diff — no branch push).

Merge gating (configure in branch protection):
  * Enable "Require conversation resolution before merging".
  * Keep "Scan & Report Vulnerabilities" as a required check (fail-closed
    backstop — it goes red only if this script errors).

Behaviour:
  * Blocking vulns (CRITICAL/HIGH) -> ensure an UNRESOLVED thread exists.
    - creates it if missing
    - updates the body if it exists
    - re-opens it if a stale resolution is present but code is still vulnerable
  * No blocking vulns -> auto-RESOLVE the thread (no manual click needed).
  * A human can still click "Resolve conversation" to accept risk and merge.

The Dependabot alerts API is CURSOR-paginated: do NOT send a `page` param
(GitHub returns 400). We follow the Link header's rel="next" cursor.
"""

import os
import re
import sys
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

GH_TOKEN       = os.environ["GH_TOKEN"]
DEPENDABOT_PAT = os.environ.get("DEPENDABOT_PAT", "").strip()
REPO           = os.environ["REPO"]
PR_NUMBER      = os.environ["PR_NUMBER"]
PR_HEAD_SHA    = os.environ["PR_HEAD_SHA"]
PR_BRANCH      = os.environ.get("PR_BRANCH", "")
API_BASE       = "https://api.github.com"
GRAPHQL        = "https://api.github.com/graphql"
MARKER         = "Dependabot Vulnerability Report"

# India Standard Time (UTC+5:30, no DST) — used for all report timestamps.
IST = timezone(timedelta(hours=5, minutes=30))

PR_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
ALERT_HEADERS = {
    "Authorization": f"Bearer {DEPENDABOT_PAT if DEPENDABOT_PAT else GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
BLOCK_ON       = {"CRITICAL", "HIGH"}
SEVERITY_MAP   = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH",
    "MODERATE": "MEDIUM",   "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFORMATIONAL": "LOW", "NEGLIGIBLE": "LOW",
}

# ── Fetch (cursor pagination, fail-closed) ────────────────────────────────────

def get_next_url(link_header):
    if not link_header or 'rel="next"' not in link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                return m.group(1)
    return None

def fetch_dependabot_counts(repo):
    """Fetch ALL open alerts -> (counts, top_alerts). Fails CLOSED on any error."""
    counts, blocking_alerts = defaultdict(int), []
    print(f"[INFO] Repo={repo} PR={PR_NUMBER} Branch={PR_BRANCH}")

    url    = f"{API_BASE}/repos/{repo}/dependabot/alerts"
    params = {"state": "open", "per_page": 100}
    all_alerts, page_num = [], 0

    while url:
        page_num += 1
        resp = requests.get(url, headers=ALERT_HEADERS, params=params, timeout=15)
        print(f"[INFO] Page {page_num} status: {resp.status_code}")
        if resp.status_code in (400, 401, 403, 404):
            raise RuntimeError(
                f"Dependabot alerts API returned {resp.status_code} for {repo}. "
                f"Check DEPENDABOT_PAT scope and that alerts are enabled. "
                f"Body: {resp.text[:300]}"
            )
        resp.raise_for_status()
        batch = resp.json()
        all_alerts.extend(batch)
        print(f"[INFO] Page {page_num}: {len(batch)} alerts (running total {len(all_alerts)})")
        url    = get_next_url(resp.headers.get("Link", ""))
        params = None  # next URL already carries cursor + per_page

    print(f"[INFO] Total alerts fetched: {len(all_alerts)}")

    for alert in all_alerts:
        adv  = alert.get("security_advisory", {})
        vuln = alert.get("security_vulnerability", {})
        raw  = (adv.get("severity") or vuln.get("severity") or "UNKNOWN").upper()
        sev  = SEVERITY_MAP.get(raw, raw)
        counts[sev] += 1
        if sev in BLOCK_ON:
            dep  = alert.get("dependency", {})
            pkg  = dep.get("package", {}).get("name", "—")
            eco  = dep.get("package", {}).get("ecosystem", "")
            cve  = adv.get("cve_id") or adv.get("ghsa_id", "—")
            summ = (adv.get("summary") or "No summary")[:80]
            fix  = "—"
            pv   = vuln.get("first_patched_version", {}) or {}
            if pv.get("identifier"):
                fix = pv["identifier"]
            else:
                for v in adv.get("vulnerabilities", []):
                    fpv = v.get("first_patched_version", {}) or {}
                    if fpv.get("identifier"):
                        fix = fpv["identifier"]; break
            blocking_alerts.append({
                "severity": sev,
                "pkg": f"{pkg} ({eco})" if eco else pkg,
                "vuln_id": cve, "title": summ,
                "fixed_ver": fix, "alert_url": alert.get("html_url", ""),
            })

    blocking_alerts.sort(key=lambda a: SEVERITY_ORDER.index(a["severity"]))
    print(f"[INFO] Final counts: {dict(counts)}")
    return dict(counts), blocking_alerts[:10]

# ── Report bodies ─────────────────────────────────────────────────────────────

def build_report(counts, top_alerts, blocking):
    ts    = datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    rows  = "".join(
        f"| {SEVERITY_EMOJI.get(s,'⚪')} **{s}** | `{counts[s]}` |\n"
        for s in SEVERITY_ORDER if counts.get(s, 0) > 0
    )
    table = f"| Severity | Count |\n|:---------|------:|\n{rows}| **TOTAL** | **`{total}`** |"

    detail = ""
    if top_alerts:
        rows2 = "\n".join(
            f"| {SEVERITY_EMOJI.get(a['severity'],'⚪')} {a['severity']} "
            f"| [{a['vuln_id']}]({a['alert_url']}) | `{a['pkg']}` | {a['title']} | {a['fixed_ver']} |"
            for a in top_alerts
        )
        detail = (
            "\n<details>\n<summary>🔍 Top Critical & High Vulnerabilities (up to 10)</summary>\n\n"
            "| Severity | CVE / GHSA | Package | Summary | Fix Version |\n"
            "|:---------|:-----------|:--------|:--------|:------------|\n"
            f"{rows2}\n\n"
            f"> 📋 [View all Dependabot alerts](https://github.com/{REPO}/security/dependabot)\n\n"
            "</details>\n"
        )

    if blocking:
        status = ("🚨 **CRITICAL or HIGH vulnerabilities found. This conversation "
                  "must be resolved before the PR can be merged.**")
        steps  = f"\n---\n\n> 📋 [View all Dependabot alerts](https://github.com/{REPO}/security/dependabot)\n"
    else:
        status = "⚠️ Vulnerabilities found — review recommended, but none are merge-blocking."
        steps  = f"\n---\n\n> 📋 [View all Dependabot alerts](https://github.com/{REPO}/security/dependabot)\n"

    return (
        f"## 🛡️ {MARKER}\n\n{status}\n\n"
        f"### Vulnerability Summary\n\n{table}\n{detail}{steps}\n"
        f"---\n\n> 📅 Checked at **{ts}** on commit `{PR_HEAD_SHA[:8]}`.\n"
    )

def build_clean_report():
    ts = datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")
    return (
        f"## 🛡️ {MARKER}\n\n"
        f"✅ **No CRITICAL or HIGH vulnerabilities — this thread is resolved and merge is unblocked.**\n\n"
        f"> 📅 Checked at **{ts}** on commit `{PR_HEAD_SHA[:8]}`.\n"
    )

# ── GraphQL (find / resolve / unresolve threads) ──────────────────────────────

def gql(query, variables):
    r = requests.post(GRAPHQL, headers=PR_HEADERS,
                      json={"query": query, "variables": variables}, timeout=15)
    r.raise_for_status()
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"GraphQL error: {data['errors']}")
    return data["data"]

def find_bot_thread(repo, pr):
    """Return {thread_id, resolved, comment_id} for our bot's thread, or None."""
    owner, name = repo.split("/", 1)
    q = """
    query($owner:String!,$name:String!,$pr:Int!){
      repository(owner:$owner,name:$name){
        pullRequest(number:$pr){
          reviewThreads(first:100){
            nodes{
              id isResolved
              comments(first:1){ nodes{ databaseId body author{login} } }
            }
          }
        }
      }
    }"""
    data = gql(q, {"owner": owner, "name": name, "pr": int(pr)})
    nodes = data["repository"]["pullRequest"]["reviewThreads"]["nodes"]
    for t in nodes:
        comments = t["comments"]["nodes"]
        if not comments:
            continue
        c = comments[0]
        login = (c.get("author") or {}).get("login", "")
        if "github-actions" in login and MARKER in (c.get("body") or ""):
            return {"thread_id": t["id"], "resolved": t["isResolved"],
                    "comment_id": c["databaseId"]}
    return None

def resolve_thread(thread_id):
    gql("mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}",
        {"id": thread_id})
    print("[INFO] Thread resolved (clean scan).")

def unresolve_thread(thread_id):
    gql("mutation($id:ID!){unresolveReviewThread(input:{threadId:$id}){thread{isResolved}}}",
        {"id": thread_id})
    print("[INFO] Thread re-opened (still vulnerable).")

# ── REST (create / update review comment, find diff anchor) ────────────────────

def find_diff_anchor(repo, pr):
    """First commentable RIGHT-side line in the PR diff -> (path, line) or (None, None)."""
    resp = requests.get(f"{API_BASE}/repos/{repo}/pulls/{pr}/files",
                        headers=PR_HEADERS, params={"per_page": 100}, timeout=15)
    resp.raise_for_status()
    for f in resp.json():
        patch = f.get("patch")
        if not patch:
            continue
        new_line = None
        for line in patch.splitlines():
            if line.startswith("@@"):
                m = re.search(r"\+(\d+)", line)
                new_line = (int(m.group(1)) - 1) if m else None
            elif new_line is not None and line.startswith("+") and not line.startswith("+++"):
                return f["filename"], new_line + 1
            elif new_line is not None and line.startswith(" "):
                return f["filename"], new_line + 1
            # '-' lines and '+++/---' headers do not advance the new-file counter
    return None, None

def create_resolvable_thread(repo, pr, body, path, line):
    r = requests.post(
        f"{API_BASE}/repos/{repo}/pulls/{pr}/comments",
        headers=PR_HEADERS,
        json={"body": body, "commit_id": PR_HEAD_SHA,
              "path": path, "line": line, "side": "RIGHT"},
        timeout=15,
    )
    if not r.ok:
        print(f"[ERROR] create thread failed {r.status_code}: {r.text[:200]}")
    r.raise_for_status()
    print(f"[INFO] ✅ Resolvable thread created id={r.json().get('id')} at {path}:{line}")

def update_thread_comment(repo, comment_id, body):
    r = requests.patch(f"{API_BASE}/repos/{repo}/pulls/comments/{comment_id}",
                       headers=PR_HEADERS, json={"body": body}, timeout=15)
    r.raise_for_status()
    print(f"[INFO] Thread comment #{comment_id} updated.")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("[START] Dependabot resolvable-thread script")
    print("=" * 60)

    counts, top_alerts = fetch_dependabot_counts(REPO)
    blocking = any(counts.get(s, 0) > 0 for s in BLOCK_ON)
    print(f"[INFO] Counts={counts} Blocking={blocking}")

    existing = find_bot_thread(REPO, PR_NUMBER)
    print(f"[INFO] existing_thread={existing}")

    if blocking:
        body = build_report(counts, top_alerts, True)
        if existing:
            update_thread_comment(REPO, existing["comment_id"], body)
            if existing["resolved"]:
                # Stale resolution but code is still vulnerable -> re-block.
                unresolve_thread(existing["thread_id"])
        else:
            path, line = find_diff_anchor(REPO, PR_NUMBER)
            if not path:
                # Can't anchor a resolvable thread -> fail closed so merge stays blocked.
                raise RuntimeError(
                    "Blocking vulnerabilities present but the PR diff has no "
                    "commentable line to anchor a resolvable thread. Failing closed."
                )
            create_resolvable_thread(REPO, PR_NUMBER, body, path, line)
    else:
        if existing:
            update_thread_comment(REPO, existing["comment_id"], build_clean_report())
            if not existing["resolved"]:
                resolve_thread(existing["thread_id"])
        else:
            print("[INFO] Clean scan, no existing thread — nothing to block.")

    print("=" * 60)
    print("[DONE]")
    print("=" * 60)
    sys.exit(0)

if __name__ == "__main__":
    main()
