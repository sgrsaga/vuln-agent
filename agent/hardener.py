"""
Golden base image hardening — for OWNED application images only, never for
third-party/vendor images (see README's "Base image hardening" section for why:
without the app's own test suite there's no way to have confidence a rebuilt
image still works, and rebuilding someone else's software forfeits their
provenance/support guarantees).

Ownership is established upstream by main.py via a k8s label selector
(agent/discoverer.py: discover_owned_images) — this module only ever runs for
images already confirmed owned, with an explicit per-image config entry telling
it where the source lives and how to run that repo's real tests.

Flow per image: clone the app's own source, then find a candidate replacement
base in two tiers —
  Tier 1 (deterministic, no LLM): is there just a newer tag of the SAME base
    repo? Reuses agent/tag_finder.py's Trivy-verified tag-bump logic — zero
    ambiguity, no reason to ask a model something a registry+scanner call can
    already answer.
  Tier 2 (Claude, only reached if tier 1 found nothing or it didn't actually
    pass validation): suggest alternative base images from a *different*
    family/vendor — the one genuinely ambiguous, judgment-requiring step,
    since "which minimal/distroless bases exist and are plausible for this
    runtime" isn't derivable from scan data alone.
For every candidate from either tier: swap the base, run the app's real test
suite, and only adopt the first one that both passes tests and reduces
vulnerabilities.
"""

import json
import logging
import os
import re
import subprocess
import tempfile

import anthropic

from .builder import build_from_context, run_isolated, tag_local_image, push_image
from .scanner import scan_image, extract_vulnerabilities
from . import tag_finder

logger = logging.getLogger(__name__)
_client = None

GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")
ALLOW_MAJOR_TAG_BUMP = os.environ.get("ALLOW_MAJOR_TAG_BUMP", "false").lower() == "true"

_FROM_RE = re.compile(r"^(FROM\s+)(\S+)(.*)$", re.IGNORECASE)


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def load_hardening_config() -> dict[str, dict]:
    """Parse HARDENING_CONFIG (a JSON list) into a dict keyed by bare repo name."""
    raw = os.environ.get("HARDENING_CONFIG", "")
    if not raw.strip():
        return {}
    try:
        entries = json.loads(raw)
        return {e["repo"]: e for e in entries if e.get("repo")}
    except Exception as exc:
        logger.warning(f"Could not parse HARDENING_CONFIG (hardening disabled): {exc}")
        return {}


def suggest_base_images(
    os_family: str, os_version: str, vulns: list[dict], max_candidates: int = 3,
    current_base: str = "",
) -> list[str]:
    """
    Tier 2 — ask Claude for candidate replacement base images from a different
    family/vendor than current_base. Only called once tier 1 (a same-repo
    newer tag, via tag_finder.find_better_tag) has already been tried and
    ruled out by the caller — the prompt tells Claude that explicitly so it
    doesn't waste a suggestion re-proposing what's already been checked.

    Returns [] (never raises) on any failure to get or parse a usable
    response — callers must treat that as "nothing to try", not an error.
    """
    if not vulns:
        return []

    crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")

    prompt = f"""You are a container security engineer choosing a hardened base image.

Current base image: {current_base or "unknown"}
Detected OS: {os_family or "unknown"} {os_version or ""}
Vulnerabilities attributable to this base: {len(vulns)} total (CRITICAL: {crit}, HIGH: {high})

A newer tag of this exact same base repo has already been checked and either
doesn't exist or didn't pan out — do not suggest that. Suggest up to
{max_candidates} alternative base image references from a genuinely DIFFERENT
image family or vendor, likely to reduce or eliminate these vulnerabilities
while remaining a plausible drop-in replacement for the same language/runtime —
e.g. a minimal/alpine equivalent, or a distroless/chainguard image for the same
runtime. Order from most to least likely to be a safe drop-in replacement.

Respond with ONLY a JSON array of image reference strings, nothing else, e.g.:
["python:3.12-alpine", "cgr.dev/chainguard/python:latest"]
If nothing reasonable applies, respond with []."""

    try:
        client = _get_client()
        response = client.messages.create(
            model="claude-opus-4-8", max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = "".join(b.text for b in response.content if b.type == "text").strip()
    except Exception as exc:
        logger.warning(f"Base-image suggestion request failed: {exc}")
        return []

    try:
        candidates = json.loads(raw)
        if not isinstance(candidates, list):
            raise ValueError("response was not a JSON array")
        return [str(c) for c in candidates][:max_candidates]
    except Exception as exc:
        logger.warning(f"Could not parse base-image suggestions ({exc}); raw response: {raw[:200]!r}")
        return []


def _clone_repo(source_repo: str, token: str, workdir: str) -> str:
    url = (f"https://x-access-token:{token}@github.com/{source_repo}.git" if token
           else f"https://github.com/{source_repo}.git")
    dest = os.path.join(workdir, "src")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        stderr = result.stderr.replace(token, "***") if token else result.stderr
        raise RuntimeError(f"git clone failed for {source_repo}: {stderr[-1000:]}")
    return dest


_AS_RE = re.compile(r"\s+AS\s+(\S+)", re.IGNORECASE)


def _parse_stages(dockerfile_text: str) -> list[dict]:
    """Every FROM line as {line_index, base, stage_name}, in file order."""
    stages = []
    for i, line in enumerate(dockerfile_text.splitlines()):
        m = _FROM_RE.match(line.strip())
        if not m:
            continue
        as_match = _AS_RE.match(m.group(3))
        stages.append({
            "line_index": i,
            "base": m.group(2),
            "stage_name": as_match.group(1) if as_match else None,
        })
    return stages


def _resolve_final_base_stage(stages: list[dict]) -> dict | None:
    """
    A plain `docker build` (no --target) produces the LAST stage in the file —
    that's the one that actually ships and whose base determines the deployed
    image's vulnerabilities. But that stage's own `FROM` may just be an alias
    to an earlier stage's name (`FROM base AS runtime`) rather than a real
    image, e.g. in a builder+runtime Dockerfile where `builder`'s base
    (golang, node, ...) never ships and is irrelevant to what Trivy reports on
    the built image. Walk backwards through `AS` aliases from the last stage
    until landing on a `base` that isn't itself a known stage name — that's
    the real external image to patch.
    """
    if not stages:
        return None
    by_name = {s["stage_name"]: s for s in stages if s["stage_name"]}
    current = stages[-1]
    seen: set[str] = set()
    while current["base"] in by_name and current["base"] not in seen:
        seen.add(current["base"])
        current = by_name[current["base"]]
    return current


def _patch_dockerfile_base(dockerfile_path: str, candidate_base: str) -> str | None:
    """
    Replace the image reference on the FROM line that actually determines the
    final built image's base (see _resolve_final_base_stage) — preserving any
    trailing `AS <stage>`. Returns the old base image reference, or None if
    the Dockerfile has no FROM line at all (nothing to patch).
    """
    with open(dockerfile_path) as fh:
        lines = fh.readlines()

    target = _resolve_final_base_stage(_parse_stages("".join(lines)))
    if target is None:
        return None

    i = target["line_index"]
    m = _FROM_RE.match(lines[i].strip())
    old_base = m.group(2)
    lines[i] = f"{m.group(1)}{candidate_base}{m.group(3)}\n"

    with open(dockerfile_path, "w") as fh:
        fh.writelines(lines)
    return old_base


def _try_candidate(
    candidate: str,
    idx: int,
    repo_dir: str,
    df_path: str,
    test_stage: str | None,
    test_command: str | None,
    current_vulns: list[dict],
    repo_name: str,
) -> tuple[dict, dict | None]:
    """
    Patch, build, test, and rescan one candidate base image. Returns
    (attempt_record, win) — win is {"candidate_tag", "new_vulns"} if this
    candidate passed tests and reduced vulnerabilities, else (attempt, None).
    Shared by both tiers so the actual validation logic exists exactly once.
    """
    attempt = {"base": candidate}
    candidate_tag = f"vuln-agent-harden/{repo_name}:{idx}"

    old_base = _patch_dockerfile_base(df_path, candidate)
    if old_base is None:
        attempt["outcome"] = "no FROM line found in Dockerfile"
        return attempt, None

    try:
        if test_stage:
            build_from_context(repo_dir, f"{candidate_tag}-test", target=test_stage)
        else:
            build_from_context(repo_dir, candidate_tag)
            rc = run_isolated(candidate_tag, test_command)
            if rc != 0:
                attempt["outcome"] = f"tests failed (exit {rc})"
                return attempt, None
    except Exception as exc:
        attempt["outcome"] = f"build/test failed: {exc}"
        return attempt, None

    try:
        build_from_context(repo_dir, candidate_tag)  # final runtime image
        raw_scan = scan_image(candidate_tag)
    except Exception as exc:
        attempt["outcome"] = f"final build/rescan failed: {exc}"
        return attempt, None

    new_vulns = extract_vulnerabilities(raw_scan)
    if len(new_vulns) >= len(current_vulns):
        attempt["outcome"] = f"no improvement ({len(current_vulns)} -> {len(new_vulns)})"
        return attempt, None

    attempt["outcome"] = f"passed, {len(current_vulns)} -> {len(new_vulns)} vulns"
    return attempt, {"candidate_tag": candidate_tag, "new_vulns": new_vulns}


def _adopt(
    image_ref: str, original_tag: str, repo_name: str,
    candidate: str, current_vulns: list[dict], win: dict, attempts: list[dict],
) -> dict:
    final_tag = f"{original_tag}-golden"
    final_ref = (f"{GHCR_NAMESPACE}/{repo_name}:{final_tag}" if GHCR_NAMESPACE
                 else f"{repo_name}:{final_tag}")
    tag_local_image(win["candidate_tag"], final_ref)
    if GHCR_NAMESPACE:
        push_image(final_ref)

    logger.info(f"Hardened {image_ref}: -> {candidate} ({final_ref})")
    return {
        "golden_image": final_ref,
        "base_used": candidate,
        "vulns_before": len(current_vulns),
        "vulns_after": len(win["new_vulns"]),
        "attempts": attempts,
    }


def harden_image(
    image_ref: str,
    config_entry: dict,
    current_vulns: list[dict],
    os_info: dict,
    max_candidates: int = 3,
) -> dict | None:
    """
    Attempt to harden image_ref's base image. Returns
    {"golden_image", "base_used", "vulns_before", "vulns_after", "attempts"} on
    success, or None (with every attempt logged) if nothing viable was found.
    """
    split = tag_finder.split_ref(image_ref)
    if split is None:
        logger.warning(f"Cannot harden {image_ref} — no plain tag to derive a -golden tag from")
        return None
    origin_repo, original_tag = split
    repo_name = tag_finder.repo_name(origin_repo)

    source_repo = config_entry.get("sourceRepo")
    dockerfile_path = config_entry.get("dockerfilePath", "Dockerfile")
    test_stage = config_entry.get("testStage")
    test_command = config_entry.get("testCommand")
    if not source_repo or not (test_stage or test_command):
        logger.warning(f"Incomplete hardening config for {repo_name} — skipping")
        return None

    token = os.environ.get("GITOPS_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    attempts: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="vuln-harden-") as tmpdir:
        try:
            repo_dir = _clone_repo(source_repo, token, tmpdir)
        except Exception as exc:
            logger.warning(str(exc))
            return None

        df_path = os.path.join(repo_dir, dockerfile_path)

        with open(df_path) as fh:
            base_stage = _resolve_final_base_stage(_parse_stages(fh.read()))
        if base_stage is None:
            logger.warning(f"No FROM line found in {dockerfile_path} for {repo_name} — cannot harden")
            return None
        current_base = base_stage["base"]

        # ── Tier 1: deterministic — a newer tag of the SAME base repo, verified
        # by an actual Trivy scan (agent/tag_finder.py, already used by the main
        # remediation loop). No LLM call happens if this alone works out.
        tier1_candidates: list[str] = []
        base_split = tag_finder.split_ref(current_base)
        if base_split:
            base_repo, base_tag = base_split
            try:
                tier1 = tag_finder.find_better_tag(
                    base_repo, base_tag, len(current_vulns), allow_major=ALLOW_MAJOR_TAG_BUMP,
                )
            except Exception as exc:
                logger.debug(f"Tier-1 tag lookup failed for {current_base}: {exc}")
                tier1 = None
            if tier1:
                tier1_candidates.append(f"{base_repo}:{tier1['tag']}")

        idx = 0
        for candidate in tier1_candidates:
            idx += 1
            attempt, win = _try_candidate(
                candidate, idx, repo_dir, df_path, test_stage, test_command, current_vulns, repo_name,
            )
            attempts.append(attempt)
            if win:
                return _adopt(image_ref, original_tag, repo_name, candidate, current_vulns, win, attempts)

        # ── Tier 2: Claude — only reached if tier 1 found nothing to try, or
        # its candidate didn't actually pass validation.
        tier2_candidates = suggest_base_images(
            os_info.get("family", ""), os_info.get("version", ""), current_vulns, max_candidates,
            current_base=current_base,
        )
        for candidate in tier2_candidates:
            idx += 1
            attempt, win = _try_candidate(
                candidate, idx, repo_dir, df_path, test_stage, test_command, current_vulns, repo_name,
            )
            attempts.append(attempt)
            if win:
                return _adopt(image_ref, original_tag, repo_name, candidate, current_vulns, win, attempts)

    logger.info(f"No viable hardened base found for {image_ref}. Attempts: {attempts}")
    return None
