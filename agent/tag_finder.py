"""
Finds a newer upstream tag of the current image that already fixes CVEs, so the
orchestrator can adopt it directly instead of layering an OS-package patch.

Uses crane (already a dependency, daemon-less) to
list tags directly from the registry — no docker daemon required.

Only strict numeric version tags are considered (optionally `v`-prefixed,
`X.Y` or `X.Y.Z`). This deliberately excludes suffixed tags such as `-alpine`,
`-patched-iter1` (the agent's own pushed images share the source repo name),
and cosign attestation tags like `sha256-<hex>.sig`.
"""

import logging
import re
import subprocess

from .scanner import scan_image, extract_vulnerabilities

logger = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")

MAX_CANDIDATES = 5


def _parse_version(tag: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.match(tag)
    if not m:
        return None
    major, minor, patch = m.groups()
    return (int(major), int(minor), int(patch or 0))


def split_ref(image_ref: str) -> tuple[str, str] | None:
    """
    Split an image reference into (repo_ref, tag).

    Returns None when there is no usable tag to bump from — digest-only refs
    (`repo@sha256:...`) or bare refs with no tag at all (implicit `latest`).
    """
    if "@sha256:" in image_ref:
        return None
    last_segment = image_ref.split("/")[-1]
    if ":" not in last_segment:
        return None
    repo_ref, tag = image_ref.rsplit(":", 1)
    return repo_ref, tag


def repo_name(repo_ref: str) -> str:
    """Bare repository name from a tag-less repo ref, e.g. 'ghcr.io/org/argocd' -> 'argocd'."""
    return repo_ref.split("/")[-1]


def list_tags(repo_ref: str) -> list[str]:
    """
    List all tags published for repo_ref via `crane ls`.

    Any failure (private repo with no list permission, network error, rate
    limit, crane not installed) is treated as "feature unavailable this run" —
    never fatal to the remediation pipeline.
    """
    try:
        result = subprocess.run(
            ["crane", "ls", repo_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        logger.debug(f"crane ls failed for {repo_ref}: {exc}")
        return []

    if result.returncode != 0:
        logger.debug(f"crane ls {repo_ref} exited {result.returncode}: {result.stderr[:300]}")
        return []

    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def find_better_tag(
    repo_ref: str,
    current_tag: str,
    current_vuln_count: int,
    allow_major: bool = False,
    max_candidates: int = MAX_CANDIDATES,
) -> dict | None:
    """
    Look for the nearest newer tag of repo_ref that has strictly fewer HIGH/CRITICAL
    vulnerabilities than current_vuln_count.

    Returns {"tag": ..., "vulns": [...], "count": n} for the first improving
    candidate (ascending, nearest bump first), or None if none improve or no
    current-version baseline could be parsed.
    """
    current_version = _parse_version(current_tag)
    if current_version is None:
        logger.debug(f"Current tag {current_tag!r} is not a plain semver tag — skipping tag-bump search")
        return None

    candidates: list[tuple[tuple[int, int, int], str]] = []
    for tag in list_tags(repo_ref):
        version = _parse_version(tag)
        if version is None or version <= current_version:
            continue
        if not allow_major and version[0] != current_version[0]:
            continue
        candidates.append((version, tag))

    candidates.sort(key=lambda vt: vt[0])
    candidates = candidates[:max_candidates]

    for _, tag in candidates:
        target_ref = f"{repo_ref}:{tag}"
        logger.info(f"Trying candidate tag {target_ref} ...")
        try:
            raw_scan = scan_image(target_ref)
        except Exception as exc:
            logger.warning(f"Scan of candidate tag {target_ref} failed: {exc}")
            continue

        vulns = extract_vulnerabilities(raw_scan)
        if len(vulns) < current_vuln_count:
            return {"tag": tag, "vulns": vulns, "count": len(vulns)}

    return None
