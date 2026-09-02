"""
Tracks per-image scan state across discovery-mode runs so a recurring CronJob
doesn't re-run the full remediation pipeline on images that haven't changed.

State lives in one JSON file under the discovery run's root output directory
(the `output` PVC in k8s — durable across CronJob ticks), keyed by the exact
image reference discover_images() returns:

    {
      "ghcr.io/argoproj/argocd:v2.9.3": {
        "digest": "sha256:...",
        "status": "no_further_patches",
        "final_image": "ghcr.io/me/argocd:v2.9.3-optimized",
        "iterations": 3,
        "remaining_vulns": 5,
        "last_scanned": "2026-08-25T04:00:12+00:00"
      }
    }

Scoped to discovery mode only — a direct `python main.py <image>` invocation is
always an explicit request and always runs regardless of this state.
"""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_DIR_NAME = ".vuln-agent-state"
STATE_FILENAME = "tracked-images.json"

DEFAULT_TTL_DAYS = 7

# Statuses that mean the pipeline never actually completed an assessment —
# always worth retrying on the next run regardless of digest/TTL.
ERROR_STATUSES = {"scan_error", "patch_error", "build_error", "push_error"}


def _state_path(base_output_dir: Path) -> Path:
    return Path(base_output_dir) / STATE_DIR_NAME / STATE_FILENAME


def resolve_digest(image_ref: str) -> str | None:
    """
    Resolve the digest an image tag currently points to via `crane digest`.
    Returns None on any failure — callers must treat that as "can't verify,
    must scan", never as a reason to skip.
    """
    try:
        result = subprocess.run(
            ["crane", "digest", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        logger.debug(f"crane digest failed for {image_ref}: {exc}")
        return None

    if result.returncode != 0:
        logger.debug(f"crane digest {image_ref} exited {result.returncode}: {result.stderr[:300]}")
        return None

    digest = result.stdout.strip()
    return digest or None


def load_state(base_output_dir: Path) -> dict:
    path = _state_path(base_output_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        logger.warning(f"Could not read tracked-image state at {path} (starting fresh): {exc}")
        return {}


def save_state(base_output_dir: Path, state: dict) -> None:
    path = _state_path(base_output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(state, indent=2))
    os.replace(tmp_path, path)


def should_scan(entry: dict | None, digest: str | None, ttl_days: int = DEFAULT_TTL_DAYS) -> bool:
    """
    Decide whether an image needs a fresh scan this run.

    True when: never seen before, the digest couldn't be resolved, the digest
    changed, the last attempt errored out, or the last scan is older than
    ttl_days (so unchanged images still get periodically rechecked against
    newly-disclosed CVEs). False only when the digest matches a prior
    successfully-assessed entry within the TTL window.
    """
    if entry is None or digest is None:
        return True
    if entry.get("digest") != digest:
        return True
    if entry.get("status") in ERROR_STATUSES:
        return True

    last_scanned = entry.get("last_scanned")
    if not last_scanned:
        return True
    try:
        last_dt = datetime.fromisoformat(last_scanned)
    except ValueError:
        return True

    age_days = (datetime.now(timezone.utc) - last_dt).total_seconds() / 86400
    return age_days > ttl_days


def record_result(state: dict, image_ref: str, digest: str | None, result: dict) -> None:
    state[image_ref] = {
        "digest": digest,
        "status": result.get("status"),
        "final_image": result.get("final_image"),
        "iterations": result.get("iterations"),
        "remaining_vulns": result.get("remaining_vulns"),
        "last_scanned": datetime.now(timezone.utc).isoformat(),
    }
