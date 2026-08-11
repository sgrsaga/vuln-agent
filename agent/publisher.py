"""
Publishes scan results, reports, and events to GitHub Artifacts.

Inside GitHub Actions:
  - Scan JSON and report Markdown are written to OUTPUT_DIR (uploaded as an
    artifact by the workflow YAML with actions/upload-artifact).
  - Progress is appended to $GITHUB_STEP_SUMMARY so it appears in the Actions UI.

Outside GitHub Actions (local run):
  - Same files are written to OUTPUT_DIR.
  - If GITHUB_TOKEN + GITHUB_REPO are set, a GitHub Release is created at the
    end of the run and all output files are attached as release assets.
  - Progress is printed to stdout.
"""

import json
import os
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "output"))
_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _md(text: str) -> None:
    """Append text to the GitHub Actions step summary (no-op when not in Actions)."""
    if _STEP_SUMMARY:
        with open(_STEP_SUMMARY, "a") as fh:
            fh.write(text + "\n")


def _log(event_type: str, message: str, data: dict | None = None) -> None:
    icons = {
        "pipeline_start": "🚀",
        "scan_start":     "🔍",
        "scan_complete":  "🔍",
        "report_start":   "📋",
        "report_complete":"📋",
        "patch_start":    "🔧",
        "patch_generated":"🔧",
        "build_start":    "🏗️",
        "build_complete": "🏗️",
        "improvement":    "✅",
        "no_improvement": "⚠️",
        "pipeline_complete": "🏁",
        "error":          "❌",
    }
    icon = icons.get(event_type, "ℹ️")
    print(f"{icon}  [{event_type}] {message}", flush=True)
    if data:
        logger.debug("event data: %s", json.dumps(data))


# ── public API ──────────────────────────────────────────────────────────────

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

    # Step summary table
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
    path.write_text(f"# Remediation Report — Iteration {iteration}\n\n> Image: `{image_ref}`\n\n{content}")
    logger.info(f"Report saved → {path}")

    _md(f"\n<details><summary>📋 Recovery Report — Iteration {iteration}</summary>\n\n{content}\n\n</details>\n")


def publish_event(event_type: str, message: str, data: dict | None = None) -> None:
    _log(event_type, message, data)
    _md(f"\n> {message}\n")


def create_github_release(tag: str | None = None) -> None:
    """
    Create a GitHub Release and attach all output files as assets.
    Requires GITHUB_TOKEN and GITHUB_REPO env vars, and the `gh` CLI.
    Only called at the end of a run when not already inside GitHub Actions.
    """
    if os.environ.get("GITHUB_ACTIONS"):
        return  # Actions workflow handles artifact upload via actions/upload-artifact

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPO")
    if not (token and repo):
        logger.info("GITHUB_TOKEN/GITHUB_REPO not set — skipping release creation")
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    release_tag = tag or f"vuln-remediation-{ts}"
    files = list(OUTPUT_DIR.glob("*"))
    if not files:
        return

    file_args = [str(f) for f in files]
    env = {**os.environ, "GH_TOKEN": token}

    logger.info(f"Creating GitHub Release {release_tag} in {repo}...")
    result = subprocess.run(
        [
            "gh", "release", "create", release_tag,
            "--repo", repo,
            "--title", f"Vulnerability Remediation — {ts}",
            "--notes", "Automated remediation results — see attached scan JSON and Markdown reports.",
            *file_args,
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logger.info(f"Release created: {result.stdout.strip()}")
    else:
        logger.warning(f"gh release create failed: {result.stderr.strip()}")
