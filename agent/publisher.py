"""
Publishes scan results, reports, and events to GitHub Artifacts.

Inside GitHub Actions:
  - Scan JSON and report Markdown are written to OUTPUT_DIR (uploaded as an
    artifact by the workflow YAML via actions/upload-artifact).
  - Progress is appended to $GITHUB_STEP_SUMMARY so it appears in the Actions UI.

Outside GitHub Actions / in k8s:
  - Same files are written to OUTPUT_DIR.
  - If GITHUB_TOKEN + GITHUB_REPO are set, a GitHub Release is created at the
    end of the run and all output files are attached as release assets via the
    GitHub REST API (no gh CLI required — works inside Docker/k8s).
  - Progress is printed to stdout.
"""

import json
import os
import logging
import mimetypes
from pathlib import Path
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "output"))
_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")

_GH_API = "https://api.github.com"
_GH_UPLOAD = "https://uploads.github.com"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _md(text: str) -> None:
    """Append Markdown to the GitHub Actions step summary (no-op outside Actions)."""
    if _STEP_SUMMARY:
        with open(_STEP_SUMMARY, "a") as fh:
            fh.write(text + "\n")


def _log(event_type: str, message: str, data: dict | None = None) -> None:
    icons = {
        "pipeline_start":    "🚀",
        "scan_start":        "🔍",
        "scan_complete":     "🔍",
        "report_start":      "📋",
        "report_complete":   "📋",
        "patch_start":       "🔧",
        "patch_generated":   "🔧",
        "build_start":       "🏗️",
        "build_complete":    "🏗️",
        "improvement":       "✅",
        "no_improvement":    "⚠️",
        "pipeline_complete": "🏁",
        "error":             "❌",
    }
    icon = icons.get(event_type, "ℹ️")
    print(f"{icon}  [{event_type}] {message}", flush=True)
    if data:
        logger.debug("event data: %s", json.dumps(data))


def _normalize_repo(repo: str) -> str:
    """Accept 'owner/repo', 'https://github.com/owner/repo', or '.git' URLs."""
    repo = repo.rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo.startswith("https://github.com/"):
        repo = repo[len("https://github.com/"):]
    return repo


# ── public API ───────────────────────────────────────────────────────────────

def publish_scan(
    image_ref: str,
    iteration: int,
    scan_target: str,
    vulnerabilities: list[dict],
) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    crit = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")

    data = {
        "image_ref": image_ref,
        "scan_target": scan_target,
        "iteration": iteration,
        "vulnerabilities": vulnerabilities,
        "critical_count": crit,
        "high_count": high,
        "timestamp": _now(),
    }
    path = OUTPUT_DIR / f"scan-iter-{iteration}.json"
    path.write_text(json.dumps(data, indent=2))
    logger.info(f"Scan saved → {path}")

    _md(f"\n### 🔍 Scan — Iteration {iteration} (`{scan_target}`)\n")
    _md(f"| Severity | Count |\n|----------|-------|\n| CRITICAL | {crit} |\n| HIGH | {high} |\n| Total | {len(vulnerabilities)} |\n")
    if vulnerabilities:
        _md("| Severity | CVE ID | Package | Installed | Fix Available |")
        _md("|----------|--------|---------|-----------|---------------|")
        for v in sorted(vulnerabilities, key=lambda x: (x["severity"] != "CRITICAL", x["id"])):
            fix = f"`{v['fixed']}`" if v.get("fixed") else "—"
            _md(f"| **{v['severity']}** | `{v['id']}` | `{v['package']}` | {v['installed']} | {fix} |")


def publish_report(image_ref: str, iteration: int, content: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"report-iter-{iteration}.md"
    path.write_text(
        f"# Remediation Report — Iteration {iteration}\n\n"
        f"> Image: `{image_ref}`\n\n{content}"
    )
    logger.info(f"Report saved → {path}")
    _md(f"\n<details><summary>📋 Recovery Report — Iteration {iteration}</summary>\n\n{content}\n\n</details>\n")


def publish_event(event_type: str, message: str, data: dict | None = None) -> None:
    _log(event_type, message, data)
    _md(f"\n> {message}\n")


def create_github_release(tag: str | None = None) -> None:
    """
    Create a GitHub Release via REST API and upload all output files as assets.

    Works anywhere (local, Docker, k8s) — no gh CLI required.
    No-op when:
      - Running inside GitHub Actions (workflow uses actions/upload-artifact instead)
      - GITHUB_TOKEN or GITHUB_REPO env vars are missing
    """
    if os.environ.get("GITHUB_ACTIONS"):
        return

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = _normalize_repo(os.environ.get("GITHUB_REPO", ""))
    if not token or not repo:
        logger.info("GITHUB_TOKEN/GITHUB_REPO not set — skipping GitHub Release")
        return

    files = [f for f in OUTPUT_DIR.glob("*") if f.is_file()]
    if not files:
        logger.info("No output files to attach — skipping GitHub Release")
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    release_tag = tag or f"vuln-remediation-{ts}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    logger.info(f"Creating GitHub Release {release_tag} in {repo} ...")
    with httpx.Client(timeout=30.0) as client:
        # 1. Create the release
        resp = client.post(
            f"{_GH_API}/repos/{repo}/releases",
            headers=headers,
            json={
                "tag_name": release_tag,
                "name": f"Vulnerability Remediation — {ts}",
                "body": (
                    "## Automated vulnerability remediation results\n\n"
                    "### Attached artifacts\n"
                    "- `scan-iter-N.json` — Trivy JSON output per iteration\n"
                    "- `report-iter-N.md` — Claude Opus 4.8 remediation report per iteration\n"
                    "- `dockerfile-iter-N` — Generated patch Dockerfile per iteration\n"
                ),
                "draft": False,
                "prerelease": True,
            },
        )
        if resp.status_code not in (200, 201):
            logger.warning(f"Failed to create release: {resp.status_code} {resp.text[:300]}")
            return

        release = resp.json()
        release_url = release.get("html_url", "")
        upload_url = release["upload_url"].split("{")[0]  # strip "{?name,label}"
        logger.info(f"Release created: {release_url}")

        # 2. Upload each file as a release asset
        upload_headers = {**headers, "Content-Type": "application/octet-stream"}
        for f in sorted(files):
            ct, _ = mimetypes.guess_type(f.name)
            if ct:
                upload_headers["Content-Type"] = ct

            data = f.read_bytes()
            up = client.post(
                f"{upload_url}?name={f.name}",
                headers=upload_headers,
                content=data,
                timeout=60.0,
            )
            if up.status_code in (200, 201):
                logger.info(f"  Uploaded asset: {f.name} ({len(data)} bytes)")
            else:
                logger.warning(f"  Asset upload failed for {f.name}: {up.status_code}")
