"""
Publishes scan results, reports, and events to GitHub Artifacts.

Inside GitHub Actions:
  - Files are written to OUTPUT_DIR; the workflow uploads them with
    actions/upload-artifact.
  - Progress is appended to $GITHUB_STEP_SUMMARY.

Outside GitHub Actions / in k8s:
  - Files are written to OUTPUT_DIR (per-image subdirectory in discovery mode).
  - A GitHub Release is created via the REST API at the end of the run;
    all output files are attached as release assets (no gh CLI required).
  - Progress is printed to stdout.
"""

import json
import logging
import mimetypes
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# ── Mutable output directory (call set_output_dir() before each image run) ──
_output_dir: Path = Path(os.environ.get("OUTPUT_DIR", "output"))

_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")
_GH_API = "https://api.github.com"


# ── Output dir management ────────────────────────────────────────────────────

def set_output_dir(path: str | Path) -> None:
    global _output_dir
    _output_dir = Path(path)
    _output_dir.mkdir(parents=True, exist_ok=True)


def get_output_dir() -> Path:
    return _output_dir


# ── Internal helpers ─────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _md(text: str) -> None:
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
        "discover_start":    "🔎",
        "discover_complete": "🔎",
    }
    icon = icons.get(event_type, "ℹ️")
    print(f"{icon}  [{event_type}] {message}", flush=True)
    if data:
        logger.debug("event data: %s", json.dumps(data))


def _normalize_repo(repo: str) -> str:
    repo = repo.rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo.startswith("https://github.com/"):
        repo = repo[len("https://github.com/"):]
    return repo


# ── Public API ───────────────────────────────────────────────────────────────

def publish_scan(
    image_ref: str,
    iteration: int,
    scan_target: str,
    vulnerabilities: list[dict],
) -> None:
    out = get_output_dir()
    out.mkdir(parents=True, exist_ok=True)
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
    path = out / f"scan-iter-{iteration}.json"
    path.write_text(json.dumps(data, indent=2))
    logger.info(f"Scan saved → {path}")

    _md(f"\n### 🔍 Scan — Iteration {iteration} (`{scan_target}`)\n")
    _md(f"| Severity | Count |\n|----------|-------|\n"
        f"| CRITICAL | {crit} |\n| HIGH | {high} |\n| Total | {len(vulnerabilities)} |\n")
    if vulnerabilities:
        _md("| Severity | CVE ID | Package | Installed | Fix Available |")
        _md("|----------|--------|---------|-----------|---------------|")
        for v in sorted(vulnerabilities, key=lambda x: (x["severity"] != "CRITICAL", x["id"])):
            fix = f"`{v['fixed']}`" if v.get("fixed") else "—"
            _md(f"| **{v['severity']}** | `{v['id']}` | `{v['package']}` | {v['installed']} | {fix} |")


def publish_report(image_ref: str, iteration: int, content: str) -> None:
    out = get_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"report-iter-{iteration}.md"
    path.write_text(
        f"# Remediation Report — Iteration {iteration}\n\n"
        f"> Image: `{image_ref}`\n\n{content}"
    )
    logger.info(f"Report saved → {path}")
    _md(f"\n<details><summary>📋 Recovery Report — Iteration {iteration}</summary>\n\n{content}\n\n</details>\n")


def publish_event(event_type: str, message: str, data: dict | None = None) -> None:
    _log(event_type, message, data)
    _md(f"\n> {message}\n")


def create_github_release(base_dir: Path | None = None, tag: str | None = None) -> None:
    """
    Create a GitHub Release via REST API and upload all output files as assets.

    In discovery mode pass base_dir as the parent of all per-image subdirs so
    that every image's artifacts are included. In single-image mode it defaults
    to get_output_dir().

    Works anywhere (local, Docker, k8s) — no gh CLI required.
    No-op when GITHUB_ACTIONS is set (workflow uses actions/upload-artifact).
    """
    if os.environ.get("GITHUB_ACTIONS"):
        return

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = _normalize_repo(os.environ.get("GITHUB_REPO", ""))
    if not token or not repo:
        logger.info("GITHUB_TOKEN/GITHUB_REPO not set — skipping GitHub Release")
        return

    search_root = base_dir or get_output_dir()
    files = [f for f in search_root.rglob("*") if f.is_file()]
    if not files:
        logger.info("No output files found — skipping GitHub Release")
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    release_tag = tag or f"vuln-remediation-{ts}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    logger.info(f"Creating GitHub Release {release_tag} in {repo} with {len(files)} assets...")
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            f"{_GH_API}/repos/{repo}/releases",
            headers=headers,
            json={
                "tag_name": release_tag,
                "name": f"Vulnerability Remediation — {ts}",
                "body": (
                    "## Automated vulnerability remediation results\n\n"
                    "### Attached artifacts\n"
                    "- `<image>--scan-iter-N.json` — Trivy JSON per iteration\n"
                    "- `<image>--report-iter-N.md` — Claude Opus 4.8 report per iteration\n"
                    "- `<image>--dockerfile-iter-N` — Applied patch Dockerfile\n"
                ),
                "draft": False,
                "prerelease": True,
            },
        )
        if resp.status_code not in (200, 201):
            logger.warning(f"Failed to create release: {resp.status_code} {resp.text[:300]}")
            return

        release = resp.json()
        upload_url = release["upload_url"].split("{")[0]
        logger.info(f"Release created: {release.get('html_url', '')}")

        upload_headers = dict(headers)
        for f in sorted(files):
            # Flatten subdirectory path into asset name using "--" as separator
            try:
                rel = f.relative_to(search_root)
                asset_name = str(rel).replace("/", "--").replace("\\", "--").replace(" ", "_")
            except ValueError:
                asset_name = f.name

            ct, _ = mimetypes.guess_type(f.name)
            upload_headers["Content-Type"] = ct or "application/octet-stream"

            data_bytes = f.read_bytes()
            up = client.post(
                f"{upload_url}?name={asset_name}",
                headers=upload_headers,
                content=data_bytes,
                timeout=60.0,
            )
            if up.status_code in (200, 201):
                logger.info(f"  ✓ {asset_name} ({len(data_bytes):,} bytes)")
            else:
                logger.warning(f"  ✗ {asset_name}: {up.status_code}")
