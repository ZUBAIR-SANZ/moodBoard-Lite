#!/usr/bin/env python3
"""
lint_report.py
==============

Turns lint output into a single "sticky" PR comment that shows a green tick
(or a red cross) in front of three high-level categories:

    - Common programming mistakes      (correctness bugs)
    - Code quality / maintainability   (complexity, magic numbers, any, ...)
    - Style / consistency              (naming, import order, formatting, ...)

This mirrors the vulnerability-report pattern: one comment per PR, found via a
hidden HTML marker and updated in place on every push (no comment spam).

Inputs
------
    --eslint  path/to/eslint-report.json   (from: eslint -f json -o ...)
    --ruff    path/to/ruff-report.json     (from: ruff check --output-format json)
(You may pass either, both, or the same flag multiple times for monorepos.)

Auth / context
--------------
    GITHUB_TOKEN         repo-scoped token (Actions provides this automatically)
    GITHUB_REPOSITORY    "owner/repo"      (auto in Actions)
    GITHUB_EVENT_PATH    event payload      (auto in Actions; used to find PR #)
Any of these can be overridden with --repo / --pr.

Exit code
---------
Default: always 0 (comment only, like the vuln report).
Use --fail-on errors|any to turn it into a merge gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Iterable

# --------------------------------------------------------------------------- #
# Categories
# --------------------------------------------------------------------------- #
CAT_MISTAKES = "Common programming mistakes"
CAT_QUALITY = "Code quality / maintainability"
CAT_STYLE = "Style / consistency"
CATEGORY_ORDER = [CAT_MISTAKES, CAT_QUALITY, CAT_STYLE]

MARKER = "<!-- traya-lint-report-bot -->"  # used to find & update our comment

# --------------------------------------------------------------------------- #
# ESLint rule -> category
#
# Anything not listed here falls back to prefix/heuristic rules in
# classify_eslint_rule(). Tune freely.
# --------------------------------------------------------------------------- #
ESLINT_RULE_CATEGORY = {
    # --- Common programming mistakes (correctness) ---
    "no-unused-vars": CAT_MISTAKES,
    "no-undef": CAT_MISTAKES,
    "no-unreachable": CAT_MISTAKES,
    "no-fallthrough": CAT_MISTAKES,
    "no-dupe-keys": CAT_MISTAKES,
    "no-dupe-args": CAT_MISTAKES,
    "no-dupe-class-members": CAT_MISTAKES,
    "no-duplicate-case": CAT_MISTAKES,
    "no-cond-assign": CAT_MISTAKES,
    "no-constant-condition": CAT_MISTAKES,
    "no-self-assign": CAT_MISTAKES,
    "no-self-compare": CAT_MISTAKES,
    "use-isnan": CAT_MISTAKES,
    "valid-typeof": CAT_MISTAKES,
    "eqeqeq": CAT_MISTAKES,
    "consistent-return": CAT_MISTAKES,
    "no-await-in-loop": CAT_MISTAKES,
    "no-return-await": CAT_MISTAKES,
    "require-atomic-updates": CAT_MISTAKES,
    "array-callback-return": CAT_MISTAKES,
    "no-unsafe-negation": CAT_MISTAKES,
    "no-unsafe-optional-chaining": CAT_MISTAKES,
    "no-throw-literal": CAT_MISTAKES,
    "@typescript-eslint/no-floating-promises": CAT_MISTAKES,
    "@typescript-eslint/no-misused-promises": CAT_MISTAKES,
    "@typescript-eslint/await-thenable": CAT_MISTAKES,
    "@typescript-eslint/no-unused-vars": CAT_MISTAKES,
    "@typescript-eslint/no-unnecessary-condition": CAT_MISTAKES,
    "@typescript-eslint/switch-exhaustiveness-check": CAT_MISTAKES,
    "@typescript-eslint/no-unsafe-assignment": CAT_MISTAKES,
    "@typescript-eslint/no-unsafe-call": CAT_MISTAKES,
    "@typescript-eslint/no-unsafe-member-access": CAT_MISTAKES,
    "@typescript-eslint/no-unsafe-return": CAT_MISTAKES,
    "@typescript-eslint/no-unsafe-argument": CAT_MISTAKES,

    # --- Code quality / maintainability ---
    "complexity": CAT_QUALITY,
    "max-depth": CAT_QUALITY,
    "max-nested-callbacks": CAT_QUALITY,
    "max-lines": CAT_QUALITY,
    "max-lines-per-function": CAT_QUALITY,
    "max-params": CAT_QUALITY,
    "max-statements": CAT_QUALITY,
    "no-magic-numbers": CAT_QUALITY,
    "no-nested-ternary": CAT_QUALITY,
    "no-else-return": CAT_QUALITY,
    "prefer-const": CAT_QUALITY,
    "no-var": CAT_QUALITY,
    "no-param-reassign": CAT_QUALITY,
    "no-duplicate-imports": CAT_QUALITY,
    "prefer-destructuring": CAT_QUALITY,
    "no-lonely-if": CAT_QUALITY,
    "@typescript-eslint/no-explicit-any": CAT_QUALITY,
    "@typescript-eslint/no-non-null-assertion": CAT_QUALITY,
    "@typescript-eslint/prefer-nullish-coalescing": CAT_QUALITY,
    "@typescript-eslint/prefer-optional-chain": CAT_QUALITY,
    "@typescript-eslint/no-inferrable-types": CAT_QUALITY,

    # --- Style / consistency ---
    "camelcase": CAT_STYLE,
    "quotes": CAT_STYLE,
    "semi": CAT_STYLE,
    "indent": CAT_STYLE,
    "comma-dangle": CAT_STYLE,
    "object-curly-spacing": CAT_STYLE,
    "eol-last": CAT_STYLE,
    "no-multiple-empty-lines": CAT_STYLE,
    "spaced-comment": CAT_STYLE,
    "@typescript-eslint/naming-convention": CAT_STYLE,
    "@typescript-eslint/consistent-type-imports": CAT_STYLE,
    "@typescript-eslint/consistent-type-definitions": CAT_STYLE,
    "@typescript-eslint/member-ordering": CAT_STYLE,
    "import/order": CAT_STYLE,
    "import/newline-after-import": CAT_STYLE,
    "sort-imports": CAT_STYLE,
    # production hygiene lands under style here; move to CAT_MISTAKES if you
    # want a stray console.log to flip the correctness tick.
    "no-console": CAT_STYLE,
    "no-debugger": CAT_STYLE,
}


def classify_eslint_rule(rule_id: str | None) -> str:
    """Map an ESLint rule id to one of the three categories."""
    if not rule_id:
        # Parser/syntax errors report a null ruleId -> treat as a real bug.
        return CAT_MISTAKES
    if rule_id in ESLINT_RULE_CATEGORY:
        return ESLINT_RULE_CATEGORY[rule_id]

    # Heuristic fallbacks for rules we didn't enumerate.
    if "no-unsafe" in rule_id or "no-misused" in rule_id or "floating" in rule_id:
        return CAT_MISTAKES
    if rule_id.startswith(("max-", "no-magic", "complexity")):
        return CAT_QUALITY
    if any(k in rule_id for k in ("naming", "import", "quotes", "indent", "spacing", "consistent-type")):
        return CAT_STYLE
    # Unknown TS/ESLint rule: default to quality so it's visible but not a false bug.
    return CAT_QUALITY


# --------------------------------------------------------------------------- #
# Ruff code -> category  (prefix based; Ruff has hundreds of codes)
# --------------------------------------------------------------------------- #
def classify_ruff_code(code: str | None) -> str:
    if not code:
        return CAT_MISTAKES
    c = code.upper()
    # Order matters: check the more specific prefixes first.
    if c.startswith(("E9", "F", "B", "A", "ARG", "PLE", "PLW", "RUF100")):
        return CAT_MISTAKES
    if c.startswith(("C90", "C4", "UP", "SIM", "PLC", "PLR", "TRY", "ANN", "RUF")):
        return CAT_QUALITY
    if c.startswith(("E", "W", "I", "N", "D", "Q", "COM", "PT", "ERA")):
        return CAT_STYLE
    return CAT_QUALITY


# --------------------------------------------------------------------------- #
# Loaders  -> normalized issue dicts
# --------------------------------------------------------------------------- #
def _read_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return []
    return json.loads(text)


def load_eslint(path: str) -> list[dict]:
    issues: list[dict] = []
    for file_entry in _read_json(path) or []:
        fp = file_entry.get("filePath", "")
        for m in file_entry.get("messages", []):
            rule = m.get("ruleId")
            issues.append(
                {
                    "category": classify_eslint_rule(rule),
                    "severity": "error" if m.get("severity") == 2 else "warning",
                    "file": fp,
                    "line": m.get("line", 0),
                    "rule": rule or "syntax-error",
                    "message": (m.get("message") or "").strip(),
                }
            )
    return issues


def load_ruff(path: str, treat_as_warnings: bool = False) -> list[dict]:
    issues: list[dict] = []
    for m in _read_json(path) or []:
        code = m.get("code")
        loc = m.get("location") or {}
        issues.append(
            {
                "category": classify_ruff_code(code),
                "severity": "warning" if treat_as_warnings else "error",
                "file": m.get("filename", ""),
                "line": loc.get("row", 0),
                "rule": code or "ruff",
                "message": (m.get("message") or "").strip(),
            }
        )
    return issues


# --------------------------------------------------------------------------- #
# Summary + comment rendering
# --------------------------------------------------------------------------- #
def summarize(issues: Iterable[dict]) -> dict[str, dict]:
    summary = {
        cat: {"errors": 0, "warnings": 0, "items": []} for cat in CATEGORY_ORDER
    }
    for iss in issues:
        bucket = summary[iss["category"]]
        bucket["errors" if iss["severity"] == "error" else "warnings"] += 1
        bucket["items"].append(iss)
    return summary


def _rel(path: str) -> str:
    """Strip the CI workspace prefix so file paths are readable in the comment."""
    ws = os.environ.get("GITHUB_WORKSPACE", "")
    if ws and path.startswith(ws):
        return path[len(ws):].lstrip("/")
    return path


def build_comment(summary: dict[str, dict], top_n: int = 15) -> str:
    lines = ["## 🧹 Lint Report", ""]

    # Headline checklist — the green tick in front of each category.
    for cat in CATEGORY_ORDER:
        b = summary[cat]
        tick = "✅" if b["errors"] == 0 else "❌"
        detail = "no issues" if (b["errors"] == 0 and b["warnings"] == 0) else \
            f'{b["errors"]} error(s)' + (f', {b["warnings"]} warning(s)' if b["warnings"] else "")
        lines.append(f"- {tick} **{cat}** — {detail}")

    total_err = sum(b["errors"] for b in summary.values())
    total_warn = sum(b["warnings"] for b in summary.values())
    lines += ["", f"**Total:** {total_err} error(s), {total_warn} warning(s)"]

    # Collapsible per-category breakdown of the actual violations.
    for cat in CATEGORY_ORDER:
        items = summary[cat]["items"]
        if not items:
            continue
        # errors first, then warnings, both by file/line
        items = sorted(items, key=lambda i: (i["severity"] != "error", i["file"], i["line"]))
        lines += ["", f"<details><summary>{cat} ({len(items)})</summary>", ""]
        lines.append("| | File | Line | Rule | Message |")
        lines.append("|---|---|---|---|---|")
        for i in items[:top_n]:
            icon = "🔴" if i["severity"] == "error" else "🟡"
            msg = i["message"].replace("|", "\\|")[:120]
            lines.append(f'| {icon} | `{_rel(i["file"])}` | {i["line"]} | `{i["rule"]}` | {msg} |')
        if len(items) > top_n:
            lines.append(f"| | _…and {len(items) - top_n} more_ | | | |")
        lines += ["", "</details>"]

    lines += ["", MARKER]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# GitHub API (stdlib only)
# --------------------------------------------------------------------------- #
def _api(method: str, url: str, token: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode()
        return json.loads(body) if body else {}


def resolve_pr_number(explicit: int | None) -> int | None:
    if explicit:
        return explicit
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, encoding="utf-8") as fh:
                event = json.load(fh)
            if "pull_request" in event:
                return event["pull_request"]["number"]
            if event.get("issue", {}).get("pull_request"):
                return event["issue"]["number"]
        except (json.JSONDecodeError, KeyError):
            pass
    ref = os.environ.get("GITHUB_REF", "")  # refs/pull/123/merge
    if ref.startswith("refs/pull/"):
        try:
            return int(ref.split("/")[2])
        except (IndexError, ValueError):
            pass
    return None


def post_or_update_comment(repo: str, pr: int, token: str, body: str) -> None:
    base = f"https://api.github.com/repos/{repo}"
    # Find our existing sticky comment.
    existing_id = None
    page = 1
    while True:
        comments = _api("GET", f"{base}/issues/{pr}/comments?per_page=100&page={page}", token)
        if not comments:
            break
        for c in comments:
            if MARKER in (c.get("body") or ""):
                existing_id = c["id"]
                break
        if existing_id or len(comments) < 100:
            break
        page += 1

    if existing_id:
        _api("PATCH", f"{base}/issues/comments/{existing_id}", token, {"body": body})
        print(f"Updated existing lint comment #{existing_id}")
    else:
        _api("POST", f"{base}/issues/{pr}/comments", token, {"body": body})
        print("Created new lint comment")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Post a categorized lint report to a PR.")
    ap.add_argument("--eslint", action="append", default=[], help="ESLint JSON report (repeatable)")
    ap.add_argument("--ruff", action="append", default=[], help="Ruff JSON report (repeatable)")
    ap.add_argument("--ruff-as-warnings", action="store_true",
                    help="Count Ruff findings as warnings (won't flip a tick to ❌)")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="owner/repo")
    ap.add_argument("--pr", type=int, default=None, help="PR number (auto-detected in Actions)")
    ap.add_argument("--fail-on", choices=["none", "errors", "any"], default="none",
                    help="Exit non-zero to gate merges (default: none)")
    ap.add_argument("--top-n", type=int, default=15, help="Max rows shown per category")
    ap.add_argument("--dry-run", action="store_true", help="Print the comment instead of posting")
    args = ap.parse_args()

    issues: list[dict] = []
    for p in args.eslint:
        if os.path.exists(p):
            issues += load_eslint(p)
        else:
            print(f"warning: ESLint report not found: {p}", file=sys.stderr)
    for p in args.ruff:
        if os.path.exists(p):
            issues += load_ruff(p, treat_as_warnings=args.ruff_as_warnings)
        else:
            print(f"warning: Ruff report not found: {p}", file=sys.stderr)

    summary = summarize(issues)
    body = build_comment(summary, top_n=args.top_n)

    if args.dry_run:
        print(body)
    else:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            print("error: GITHUB_TOKEN not set", file=sys.stderr)
            return 2
        if not args.repo:
            print("error: --repo / GITHUB_REPOSITORY not set", file=sys.stderr)
            return 2
        pr = resolve_pr_number(args.pr)
        if not pr:
            print("No PR context found — nothing to comment on. Skipping.")
            return 0
        try:
            post_or_update_comment(args.repo, pr, token, body)
        except urllib.error.HTTPError as e:
            print(f"error: GitHub API {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
            return 2

    total_err = sum(b["errors"] for b in summary.values())
    total_all = total_err + sum(b["warnings"] for b in summary.values())
    if args.fail_on == "errors" and total_err > 0:
        return 1
    if args.fail_on == "any" and total_all > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
