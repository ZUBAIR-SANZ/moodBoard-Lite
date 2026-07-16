"""pr_quality_gate.py — one PR check, one comment (speed-optimized).

Runs three checks against the CHECKED-OUT SOURCE BRANCH and folds them into a
SINGLE resolvable review thread on the PR:

  1. 🏗️  Build   — auto-detected (npm/yarn/pnpm build, or Python compileall).
  2. 🧹  Lint    — ESLint (Node) + Ruff (Python), scoped to CHANGED files.
  3. 🛡️  Vulns   — Trivy filesystem scan (lockfiles).

Each check gates the merge when its BLOCK_ON_* toggle is "true" (default: all on).
The gate is the resolvable thread + "Require conversation resolution before
merging". Trivy errors fail closed (required check goes red); build/lint tool
errors are caught and reported inline so they never crash the gate.

Speed optimizations:
  * Trivy runs FIRST (before deps are installed) and skips heavy dirs, so it
    only reads lockfiles/manifests — no node_modules tree walk.
  * ESLint / Ruff lint ONLY the files the PR changed, not the whole repo.
  * Node deps are installed ONLY when the PR touches Node-relevant files, with
    offline-friendly flags. (Package-manager download caches live in the
    workflow.)
"""

import os
import re
import sys
import json
import glob
import subprocess
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ── Config / env ──────────────────────────────────────────────────────────────

GH_TOKEN    = os.environ["GH_TOKEN"]
REPO        = os.environ["REPO"]
PR_NUMBER   = os.environ["PR_NUMBER"]
PR_HEAD_SHA = os.environ["PR_HEAD_SHA"]
PR_BRANCH   = os.environ.get("PR_BRANCH", "")
SCAN_PATH   = os.environ.get("SCAN_PATH", ".")
API_BASE    = "https://api.github.com"
GRAPHQL     = "https://api.github.com/graphql"

def _flag(name, default):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")

BLOCK_ON_VULN  = _flag("BLOCK_ON_VULN",  "true")
BLOCK_ON_BUILD = _flag("BLOCK_ON_BUILD", "true")
BLOCK_ON_LINT  = _flag("BLOCK_ON_LINT",  "true")

MARKER        = "<!-- pr-quality-gate -->"
LEGACY_MARKER = "Vulnerability Report"

IST = timezone(timedelta(hours=5, minutes=30))

PR_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
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

LINT_EXT_JS   = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue")
NODE_TRIGGERS = LINT_EXT_JS + (".json",)
LOCKFILES     = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
TRIVY_SKIP_DIRS = ("node_modules,.git,dist,build,.next,out,coverage,"
                   "vendor,.venv,venv,__pycache__")

# ── Small shell helper ────────────────────────────────────────────────────────

def run(cmd, timeout=1200):
    print(f"[RUN] {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"

def tail(text, n=40):
    return "\n".join((text or "").rstrip().splitlines()[-n:])

def has_files(pattern):
    return bool(glob.glob(pattern, recursive=True))

# ── Changed files (scope lint/build to the PR) ────────────────────────────────

def get_changed_files(repo, pr, max_pages=12):
    """Filenames changed by the PR (excluding deletions), or None if the PR is
    too large to enumerate cheaply (caller then falls back to whole-repo scan)."""
    files, page = [], 1
    while page <= max_pages:
        r = requests.get(f"{API_BASE}/repos/{repo}/pulls/{pr}/files",
                         headers=PR_HEADERS, params={"per_page": 100, "page": page},
                         timeout=15)
        r.raise_for_status()
        batch = r.json()
        files.extend(batch)
        if len(batch) < 100:
            return [f["filename"] for f in files if f.get("status") != "removed"]
        page += 1
    print("[INFO] PR too large to enumerate changed files — full scan fallback.")
    return None

# ── 1) BUILD (auto-detect, change-aware) ──────────────────────────────────────

def detect_pm():
    if os.path.exists("pnpm-lock.yaml"):
        return "pnpm"
    if os.path.exists("yarn.lock"):
        return "yarn"
    return "npm"

def read_pkg_scripts():
    try:
        with open("package.json", encoding="utf-8") as f:
            return (json.load(f).get("scripts") or {})
    except Exception:
        return {}

def _node_relevant(changed):
    if changed is None:
        return True
    for c in changed:
        base = os.path.basename(c)
        if c.lower().endswith(NODE_TRIGGERS) or base in LOCKFILES or base == "package.json":
            return True
    return False

def section_build(changed):
    try:
        node_present = os.path.exists("package.json")
        py_present   = has_files("**/*.py")

        if node_present:
            if not _node_relevant(changed):
                return {"status": "➖ No Node-relevant changes — build skipped",
                        "ok": True, "ran": False, "detail": ""}
            pm = detect_pm()
            installs = {
                "npm":  ["npm", "ci", "--prefer-offline", "--no-audit", "--no-fund"],
                "yarn": ["yarn", "install", "--frozen-lockfile", "--prefer-offline"],
                "pnpm": ["pnpm", "install", "--frozen-lockfile", "--prefer-offline"],
            }
            rc, out, err = run(installs[pm])
            if rc != 0 and pm == "npm":
                rc, out, err = run(["npm", "install", "--prefer-offline",
                                    "--no-audit", "--no-fund"])
            if rc != 0:
                return {"status": f"❌ `{pm}` install failed", "ok": False,
                        "ran": True, "detail": tail(err or out)}

            scripts = read_pkg_scripts()
            if "build" in scripts:
                bc = {"npm": ["npm", "run", "build"],
                      "yarn": ["yarn", "build"],
                      "pnpm": ["pnpm", "run", "build"]}[pm]
                rc, out, err = run(bc)
                if rc == 0:
                    return {"status": f"✅ `{pm} run build` passed", "ok": True,
                            "ran": True, "detail": ""}
                return {"status": f"❌ `{pm} run build` failed (exit {rc})", "ok": False,
                        "ran": True, "detail": tail(err or out)}
            return {"status": "➖ No `build` script — deps install OK, nothing to build",
                    "ok": True, "ran": False, "detail": ""}

        if py_present:
            if changed is None:
                targets = ["."]
            else:
                targets = [c for c in changed if c.endswith(".py") and os.path.exists(c)]
            if not targets:
                return {"status": "➖ No changed Python files — build skipped",
                        "ok": True, "ran": False, "detail": ""}
            rc, out, err = run(["python", "-m", "compileall", "-q", *targets])
            if rc == 0:
                return {"status": "✅ `python -m compileall` passed", "ok": True,
                        "ran": True, "detail": ""}
            return {"status": f"❌ Python compile failed (exit {rc})", "ok": False,
                    "ran": True, "detail": tail(err or out)}

        return {"status": "➖ No Node/Python project detected — build skipped",
                "ok": True, "ran": False, "detail": ""}
    except Exception as e:
        return {"status": f"⚠️ Build check errored: {e}", "ok": True,
                "ran": False, "detail": ""}

# ── 2) LINT (changed files only) ──────────────────────────────────────────────

def section_lint(changed):
    parts, details = [], []
    errors = warnings = 0
    ran = False

    # ESLint on changed JS/TS (uses the repo's own eslint from node_modules)
    if os.path.exists("package.json"):
        targets = (["."] if changed is None
                   else [c for c in changed
                         if c.lower().endswith(LINT_EXT_JS) and os.path.exists(c)])
        if targets:
            rc, out, err = run(["npx", "--no-install", "eslint", *targets, "-f", "json"])
            try:
                results = json.loads(out) if out.strip().startswith("[") else None
            except json.JSONDecodeError:
                results = None
            if results is not None:
                ran = True
                e = sum(r.get("errorCount", 0) for r in results)
                w = sum(r.get("warningCount", 0) for r in results)
                errors += e; warnings += w
                parts.append(f"ESLint: **{e}** error(s), {w} warning(s)")
                top = [f"`{r['filePath'].split('/')[-1]}` — "
                       f"{r.get('errorCount',0)}E/{r.get('warningCount',0)}W"
                       for r in results if r.get("errorCount") or r.get("warningCount")][:10]
                if top:
                    details.append("**ESLint (top files)**\n" + "\n".join(f"- {t}" for t in top))
            else:
                parts.append("ESLint: not configured / skipped")
        else:
            parts.append("ESLint: no changed JS/TS files")

    # Ruff on changed Python (Ruff is fast even repo-wide, but scope it anyway)
    if has_files("**/*.py"):
        targets = (["."] if changed is None
                   else [c for c in changed if c.endswith(".py") and os.path.exists(c)])
        if targets:
            rc, out, err = run(["ruff", "check", *targets, "--output-format=json"])
            try:
                issues = json.loads(out) if out.strip().startswith("[") else None
            except json.JSONDecodeError:
                issues = None
            if issues is not None:
                ran = True
                errors += len(issues)
                parts.append(f"Ruff: **{len(issues)}** issue(s)")
                top = defaultdict(int)
                for i in issues:
                    top[i.get("code", "?")] += 1
                if top:
                    ranked = sorted(top.items(), key=lambda kv: -kv[1])[:10]
                    details.append("**Ruff (top rules)**\n" +
                                   "\n".join(f"- `{c}` × {n}" for c, n in ranked))
            else:
                parts.append("Ruff: not runnable / skipped")
        else:
            parts.append("Ruff: no changed Python files")

    if not ran and not parts:
        return {"status": "➖ No lint targets detected", "errors": 0,
                "warnings": 0, "detail": "", "ran": False}

    icon = "❌" if errors else ("⚠️" if warnings else "✅")
    return {"status": f"{icon} " + " · ".join(parts), "errors": errors,
            "warnings": warnings, "detail": "\n\n".join(details), "ran": ran}

# ── 3) VULNS (Trivy — runs first, lockfiles only, fail-closed) ────────────────

def fetch_trivy_counts(scan_path=SCAN_PATH):
    print(f"[INFO] Trivy scan path={scan_path}")
    rc, out, err = run(
        ["trivy", "fs", "--scanners", "vuln", "--format", "json",
         "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--no-progress", "--quiet",
         "--skip-dirs", TRIVY_SKIP_DIRS, scan_path],
        timeout=900,
    )
    if rc != 0:
        raise RuntimeError(f"Trivy exited {rc}. stderr: {tail(err, 20)}")
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse Trivy JSON: {e}")

    counts, blocking_alerts, seen = defaultdict(int), [], set()
    for result in data.get("Results", []) or []:
        eco = result.get("Type", "")
        for v in result.get("Vulnerabilities", []) or []:
            vid       = v.get("VulnerabilityID", "—")
            pkg       = v.get("PkgName", "—")
            installed = v.get("InstalledVersion", "")
            key = (vid, pkg, installed)
            if key in seen:
                continue
            seen.add(key)
            sev = SEVERITY_MAP.get((v.get("Severity") or "UNKNOWN").upper(), "LOW")
            counts[sev] += 1
            if sev in BLOCK_ON:
                blocking_alerts.append({
                    "severity": sev,
                    "pkg": f"{pkg} ({eco})" if eco else pkg,
                    "vuln_id": vid,
                    "title": (v.get("Title") or v.get("Description") or "No summary")[:80],
                    "fixed_ver": v.get("FixedVersion") or "—",
                    "alert_url": v.get("PrimaryURL") or "",
                })
    blocking_alerts.sort(key=lambda a: SEVERITY_ORDER.index(a["severity"]))
    print(f"[INFO] Vuln counts: {dict(counts)}")
    return dict(counts), blocking_alerts[:10]

# ── Combined comment body ─────────────────────────────────────────────────────

def _gate_tag(is_gate):
    return " _(merge gate)_" if is_gate else " _(advisory)_"

def build_body(build, lint, counts, top_alerts, blockers, noted):
    ts = datetime.now(IST).strftime("%Y-%m-%d %H:%M IST")

    if blockers:
        banner = ("🚨 **Merge blocked by: " + ", ".join(blockers) +
                  ". Fix the issue(s), or resolve this conversation to override.**")
    else:
        banner = "✅ **All gated checks passed — merge unblocked.**"

    note = (f"\n> ⚠️ Non-gating issues in **{', '.join(noted)}** — shown below, not blocking."
            if noted else "")

    build_detail = (f"\n<details><summary>Build output (tail)</summary>\n\n```\n"
                    f"{build['detail']}\n```\n</details>\n" if build.get("detail") else "")
    build_sec = f"### 🏗️ Build{_gate_tag(BLOCK_ON_BUILD)}\n{build['status']}\n{build_detail}"

    lint_detail = (f"\n<details><summary>Lint details</summary>\n\n{lint['detail']}\n</details>\n"
                   if lint.get("detail") else "")
    lint_sec = f"### 🧹 Lint{_gate_tag(BLOCK_ON_LINT)}\n{lint['status']}\n{lint_detail}"

    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    rows = "".join(
        f"| {SEVERITY_EMOJI.get(s,'⚪')} **{s}** | `{counts[s]}` |\n"
        for s in SEVERITY_ORDER if counts.get(s, 0) > 0
    )
    table = (f"| Severity | Count |\n|:---------|------:|\n{rows}| **TOTAL** | **`{total}`** |"
             if total else "No vulnerabilities detected. ✅")

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
            f"{rows2}\n\n</details>\n"
        )
    vuln_sec = f"### 🛡️ Vulnerabilities{_gate_tag(BLOCK_ON_VULN)}\n\n{table}\n{detail}"

    return (
        f"{MARKER}\n"
        f"## 🚦 PR Quality Gate\n\n{banner}{note}\n\n"
        f"{build_sec}\n{lint_sec}\n{vuln_sec}\n"
        f"---\n"
        f"> 🌿 Branch `{PR_BRANCH or PR_HEAD_SHA[:8]}` · 📅 {ts} · commit `{PR_HEAD_SHA[:8]}`\n"
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
    owner, name = repo.split("/", 1)
    q = """
    query($owner:String!,$name:String!,$pr:Int!){
      repository(owner:$owner,name:$name){
        pullRequest(number:$pr){
          reviewThreads(first:100){
            nodes{ id isResolved
              comments(first:1){ nodes{ databaseId body author{login} } } }
          }
        }
      }
    }"""
    data = gql(q, {"owner": owner, "name": name, "pr": int(pr)})
    for t in data["repository"]["pullRequest"]["reviewThreads"]["nodes"]:
        comments = t["comments"]["nodes"]
        if not comments:
            continue
        c = comments[0]
        login = (c.get("author") or {}).get("login", "")
        body  = c.get("body") or ""
        if "github-actions" in login and (MARKER in body or LEGACY_MARKER in body):
            return {"thread_id": t["id"], "resolved": t["isResolved"],
                    "comment_id": c["databaseId"]}
    return None

def resolve_thread(tid):
    gql("mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}", {"id": tid})
    print("[INFO] Thread resolved.")

def unresolve_thread(tid):
    gql("mutation($id:ID!){unresolveReviewThread(input:{threadId:$id}){thread{isResolved}}}", {"id": tid})
    print("[INFO] Thread re-opened.")

# ── REST (create / update review comment, diff anchor) ─────────────────────────

def find_diff_anchor(repo, pr):
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
    return None, None

def create_resolvable_thread(repo, pr, body, path, line):
    r = requests.post(f"{API_BASE}/repos/{repo}/pulls/{pr}/comments", headers=PR_HEADERS,
                      json={"body": body, "commit_id": PR_HEAD_SHA,
                            "path": path, "line": line, "side": "RIGHT"}, timeout=15)
    if not r.ok:
        print(f"[ERROR] create thread failed {r.status_code}: {r.text[:200]}")
    r.raise_for_status()
    print(f"[INFO] ✅ Thread created id={r.json().get('id')} at {path}:{line}")

def update_thread_comment(repo, comment_id, body):
    r = requests.patch(f"{API_BASE}/repos/{repo}/pulls/comments/{comment_id}",
                       headers=PR_HEADERS, json={"body": body}, timeout=15)
    r.raise_for_status()
    print(f"[INFO] Thread comment #{comment_id} updated.")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60); print("[START] PR Quality Gate"); print("=" * 60)

    changed = get_changed_files(REPO, PR_NUMBER)
    print(f"[INFO] changed_files={'ALL (fallback)' if changed is None else len(changed)}")

    # Trivy first: node_modules not yet installed -> lockfile-only, fast. Fail-closed.
    counts, top_alerts = fetch_trivy_counts(SCAN_PATH)
    build = section_build(changed)
    print(f"[INFO] build={build['status']}")
    lint = section_lint(changed)
    print(f"[INFO] lint={lint['status']}")

    vuln_bad  = any(counts.get(s, 0) > 0 for s in BLOCK_ON)
    build_bad = not build["ok"]
    lint_bad  = lint.get("errors", 0) > 0

    blockers, noted = [], []
    for gate, bad, label in (
        (BLOCK_ON_BUILD, build_bad, "build"),
        (BLOCK_ON_LINT,  lint_bad,  "lint"),
        (BLOCK_ON_VULN,  vuln_bad,  "vulnerabilities"),
    ):
        if bad and gate:
            blockers.append(label)
        elif bad and not gate:
            noted.append(label)

    blocking = bool(blockers)
    print(f"[INFO] blockers={blockers} noted={noted} overall_blocking={blocking}")

    body = build_body(build, lint, counts, top_alerts, blockers, noted)
    existing = find_bot_thread(REPO, PR_NUMBER)
    print(f"[INFO] existing_thread={existing}")

    if existing:
        update_thread_comment(REPO, existing["comment_id"], body)
        if blocking and existing["resolved"]:
            unresolve_thread(existing["thread_id"])
        elif not blocking and not existing["resolved"]:
            resolve_thread(existing["thread_id"])
    else:
        path, line = find_diff_anchor(REPO, PR_NUMBER)
        if not path:
            if blocking:
                raise RuntimeError(
                    "Blocking issues present but no commentable diff line to anchor "
                    "the resolvable thread. Failing closed.")
            print("[INFO] Clean + no anchorable line — skipping comment.")
        else:
            create_resolvable_thread(REPO, PR_NUMBER, body, path, line)
            if not blocking:
                fresh = find_bot_thread(REPO, PR_NUMBER)
                if fresh and not fresh["resolved"]:
                    resolve_thread(fresh["thread_id"])

    print("=" * 60); print("[DONE]"); print("=" * 60)
    sys.exit(0)

if __name__ == "__main__":
    main()
