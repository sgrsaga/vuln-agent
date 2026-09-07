"""
Internal-image remediation — for OWNED application images only, never for
third-party/vendor images (no test authority = no confidence a rebuild didn't
break anything; see README's "Base image hardening" section).

Phased, bounded loops (spec 2.1–2.8), all inside one source clone, every
adoption gated by rebuild → the app's REAL test suite → rescan with
severity-ordered improvement ((CRITICAL, HIGH) tuple), and rolled back
byte-for-byte on failure. Unlike earlier versions, failing attempts are
RETAINED as candidate states (image tag, test result, vuln snapshot) so the
final adjudication can weigh vulnerability impact against test breakage.

  Phase A (2.1–2.5) — base ladder with LLM recursion:
    outer loop (≤ LLM_BASE_MAX_ROUNDS): tag-bump ratchet → OS-patch injection →
    if CVEs remain, Claude picks a new base FROM THE APPLICATION CODE CONTEXT
    (Dockerfile + dependency manifests), excluding bases already tried, and the
    ladder re-runs on it. The winning base is also published standalone as
    {base}:{tag}-golden-base (zero CVEs) or -optimized-base.
  Phase B (2.6–2.7) — dependency loop: only the vulns the APP layer introduced
    (app scan minus the base's own standalone scan) are chased, via
    dep_upgrader, up to DEP_UPGRADE_MAX_ITERATIONS passes.
  Phase C (2.8) — zero total CVEs + tests pass → golden-base-app (strict
    golden). Otherwise judge_best_candidate(): Claude weighs every retained
    state (vulns × test failures) and picks the best-balanced image, with
    justification and code-fix suggestions when the security-best option
    breaks the app. Deployability is decided by the actual test result, never
    by the model.

A global INTERNAL_MAX_ATTEMPTS budget caps total build/test/scan cycles.
Promotion/naming of the APP artifact is orchestrator._finish()'s job; this
module only publishes the standalone BASE artifact (it owns that build).
"""

import json
import logging
import os
import re
import subprocess
import tempfile

import anthropic

from .builder import (
    build_from_context, run_isolated, docker_available,
    tag_local_image, push_image,
)
from .scanner import scan_image, extract_vulnerabilities, severity_key
from . import dep_upgrader
from . import patcher
from . import tag_finder

logger = logging.getLogger(__name__)
_client = None

GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")
ALLOW_MAJOR_TAG_BUMP = os.environ.get("ALLOW_MAJOR_TAG_BUMP", "false").lower() == "true"
LLM_BASE_MAX_ROUNDS = int(os.environ.get("LLM_BASE_MAX_ROUNDS", "5"))
TAG_BUMP_MAX_LOOPS = int(os.environ.get("TAG_BUMP_MAX_LOOPS", "5"))
OS_PATCH_MAX_LOOPS = int(os.environ.get("OS_PATCH_MAX_LOOPS", "5"))
DEP_UPGRADE_MAX_ITERATIONS = int(os.environ.get("DEP_UPGRADE_MAX_ITERATIONS", "5"))
INTERNAL_MAX_ATTEMPTS = int(os.environ.get("INTERNAL_MAX_ATTEMPTS", "20"))

_FROM_RE = re.compile(r"^(FROM\s+)(\S+)(.*)$", re.IGNORECASE)
_AS_RE = re.compile(r"\s+AS\s+(\S+)", re.IGNORECASE)

# Manifest files the dep loop may edit and the LLM reads as code context.
_MANIFEST_FILES = ("requirements.txt", "package.json", "go.mod", "go.sum", "pom.xml")
_CONTEXT_CAP = 2000  # chars per file fed to the LLM as code context


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


# ── Dockerfile structure helpers ──────────────────────────────────────────────

def _parse_stages(dockerfile_text: str) -> list[dict]:
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
    A plain `docker build` produces the LAST stage — the one that ships. Its
    FROM may alias an earlier stage (`FROM base AS runtime`); walk the alias
    chain back to the real external image, leaving build-only stages alone.
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


def _current_base(df_path: str) -> str | None:
    with open(df_path) as fh:
        stage = _resolve_final_base_stage(_parse_stages(fh.read()))
    return stage["base"] if stage else None


def _snapshot_base(df_text: str) -> str | None:
    """Final-stage base of a Dockerfile given as text (trail labels only)."""
    stage = _resolve_final_base_stage(_parse_stages(df_text))
    return stage["base"] if stage else None


def _patch_dockerfile_base(dockerfile_path: str, candidate_base: str) -> str | None:
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


def _inject_os_upgrade(dockerfile_path: str, upgrade: list[str]) -> bool:
    if not upgrade:
        return False
    with open(dockerfile_path) as fh:
        lines = fh.readlines()
    target = _resolve_final_base_stage(_parse_stages("".join(lines)))
    if target is None:
        return False
    insert_at = target["line_index"] + 1
    lines[insert_at:insert_at] = [l + "\n" for l in upgrade]
    with open(dockerfile_path, "w") as fh:
        fh.writelines(lines)
    return True


def _strip_injected_upgrade(df_path: str) -> None:
    """Remove previously-injected OS-upgrade RUN lines before a cross-family base swap."""
    with open(df_path) as fh:
        lines = fh.readlines()
    known_cmds = set(patcher._UPGRADE_COMMANDS.values())
    kept = [
        l for l in lines
        if not (l.strip().startswith("RUN ") and l.strip()[4:] in known_cmds)
    ]
    if len(kept) != len(lines):
        with open(df_path, "w") as fh:
            fh.writelines(kept)


def _dominant_family(vulns: list[dict]) -> str:
    """The OS package-manager family currently reported by Trivy (post-swap aware)."""
    counts: dict[str, int] = {}
    for v in vulns:
        t = v.get("type", "")
        if t in patcher._UPGRADE_COMMANDS:
            counts[t] = counts.get(t, 0) + 1
    return max(counts, key=counts.get) if counts else ""


# ── Snapshot/rollback ─────────────────────────────────────────────────────────

def _snapshot(repo_dir: str, df_path: str) -> dict[str, str]:
    snap = {}
    for path in [df_path] + [os.path.join(repo_dir, f) for f in _MANIFEST_FILES]:
        if os.path.exists(path):
            with open(path) as fh:
                snap[path] = fh.read()
    return snap


def _restore(snap: dict[str, str]) -> None:
    for path, content in snap.items():
        with open(path, "w") as fh:
            fh.write(content)


# ── Clone + code context ──────────────────────────────────────────────────────

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


def _code_context(repo_dir: str, dockerfile_path: str) -> str:
    """Dockerfile + dependency manifests (size-capped) — the application-code
    signal the LLM uses to determine a suitable base image scope."""
    parts = []
    df = os.path.join(repo_dir, dockerfile_path)
    if os.path.exists(df):
        with open(df) as fh:
            parts.append(f"--- Dockerfile ---\n{fh.read()[:_CONTEXT_CAP]}")
    for name in _MANIFEST_FILES:
        p = os.path.join(repo_dir, name)
        if os.path.exists(p):
            with open(p) as fh:
                parts.append(f"--- {name} ---\n{fh.read()[:_CONTEXT_CAP]}")
    return "\n\n".join(parts)


# ── LLM call 1: base determination from application code context (2.3) ───────

def suggest_base_images(
    current_base: str,
    vulns: list[dict],
    code_context: str,
    tried: list[str],
    max_candidates: int = 3,
) -> list[str]:
    """
    Ask Claude for replacement base images chosen from the APPLICATION CODE
    CONTEXT (Dockerfile + dependency manifests), not just OS metadata. Bases in
    `tried` are excluded explicitly so the outer loop cannot cycle.
    Returns [] (never raises) on any failure — "nothing to try", not an error.
    """
    if not vulns:
        return []
    crit, high = severity_key(vulns)

    prompt = f"""You are a container security engineer choosing a hardened base image for a
specific application. Study the application context below and pick bases that
actually fit how this app is built and run (language, package manager, build
steps, native deps implied by the manifests).

## Application context
{code_context or "(no context available)"}

## Current situation
- Current final-stage base image: {current_base}
- Vulnerabilities remaining: CRITICAL: {crit}, HIGH: {high}
- Already tried (do NOT suggest these or trivial variants of them): {", ".join(tried) or "(none)"}
- Deterministic fixes (newer tag of the same base, blanket OS-package upgrade)
  have already been applied where possible and these vulnerabilities remain.

Suggest up to {max_candidates} alternative base image references from genuinely
different families/vendors that this application could realistically build and
run on (consider whether it needs a shell, a package manager, build tools at
image-build time — the Dockerfile above shows what it uses). Order from most to
least likely to be a safe drop-in.

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
        return [str(c) for c in candidates if str(c) not in tried][:max_candidates]
    except Exception as exc:
        logger.warning(f"Could not parse base-image suggestions ({exc}); raw: {raw[:200]!r}")
        return []


# ── LLM call 2: balanced adjudication over retained states (2.8) ─────────────

def judge_best_candidate(states: list[dict], baseline_key: tuple[int, int]) -> dict | None:
    """
    Given every retained candidate state (vuln severity profile, top CVEs, test
    result, what changed), ask Claude for the best-BALANCED pick: weigh
    vulnerability impact against test breakage / code impact, in the spirit of
    "is fixing a low-impact CVE worth breaking tests?" and "is a critical fix
    worth a code change?". Returns {chosen_index, justification, code_fixes} or
    None (caller falls back to the deterministic severity-best passing state).
    Deployability is NOT taken from the model — the actual test result decides.
    """
    scored = [s for s in states if s.get("vulns") is not None]
    if not scored:
        return None

    lines = []
    for i, s in enumerate(scored):
        crit, high = severity_key(s["vulns"])
        top = ", ".join(f"{v['id']}({v['package']},{v['severity']})" for v in s["vulns"][:5]) or "(none)"
        lines.append(
            f"[{i}] step={s['step']} change={s['detail']!r} tests_passed={s['tests_passed']} "
            f"CRITICAL={crit} HIGH={high} top_cves=[{top}] outcome={s['outcome']!r}"
        )

    prompt = f"""You are a senior container security engineer adjudicating between candidate
images produced by an automated remediation run. The original image scored
CRITICAL={baseline_key[0]}, HIGH={baseline_key[1]}. Candidates:

{chr(10).join(lines)}

Pick the best-BALANCED candidate. Weigh the *nature and impact* of the
vulnerabilities against test failures and implied code impact — e.g. fixing a
low-impact vulnerability is not worth breaking tests or forcing major code
changes; fixing a genuinely critical, reachable vulnerability may be worth code
changes, in which case say so and suggest the code-level fixes or direct the
developers, with justification.

Respond with ONLY a JSON object, nothing else:
{{"chosen": <candidate index>, "justification": "<2-4 sentences>",
  "code_fixes": ["<concrete suggestion>", ...]}}
code_fixes may be [] when the chosen candidate passes tests cleanly."""

    try:
        client = _get_client()
        response = client.messages.create(
            model="claude-opus-4-8", max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = "".join(b.text for b in response.content if b.type == "text").strip()
        verdict = json.loads(raw)
        idx = int(verdict["chosen"])
        if not (0 <= idx < len(scored)):
            raise ValueError(f"chosen index {idx} out of range")
        return {
            "state": scored[idx],
            "justification": str(verdict.get("justification", "")),
            "code_fixes": [str(f) for f in verdict.get("code_fixes", [])],
        }
    except Exception as exc:
        logger.warning(f"Adjudication failed ({exc}) — falling back to deterministic pick")
        return None


# ── Validation core ───────────────────────────────────────────────────────────

# A candidate that failed because the base lacks BUILD tooling (no shell, no
# pip/apt — the distroless/chainguard signature) is not unusable: the build can
# happen in a stage that HAS the tooling, with artifacts copied into the
# minimal runtime. These signatures gate the restructure attempt; genuine test
# failures never match.
_TOOLING_FAILURE_RE = re.compile(
    r"/bin/sh[^\n]*(no such file|not found|stat /bin/sh)"
    r"|stat /bin/sh: no such file"
    r"|\b(pip|pip3|apt-get|apk|yum|sh)\b[^\n]{0,40}?\b(not found|no such file)"
    r"|executable file not found",
    re.IGNORECASE,
)


def _is_tooling_failure(outcome: str) -> bool:
    return bool(_TOOLING_FAILURE_RE.search(outcome or ""))


def propose_restructure(
    dockerfile_text: str,
    runtime_base: str,
    builder_base: str,
    test_stage: str | None,
    code_context: str,
) -> dict | None:
    """
    LLM call site 5 — Dockerfile restructuring. When a low/zero-CVE runtime
    candidate fails ONLY because it lacks build tooling, ask Claude to rewrite
    the Dockerfile into the builder/runtime pattern: dependencies built in a
    stage based on the current WORKING base (which has the tooling), artifacts
    copied into the minimal candidate as the final runtime stage. Returns
    {"dockerfile": str, "smoke_command": [argv...]} or None. The proposal is
    only ever ADOPTED after the standard gates (rebuild + tests + rescan) plus
    a runtime smoke check — because tests now run on the builder lineage, the
    smoke run is what proves the copied artifacts actually load on the
    shell-less runtime base.
    """
    test_note = (f'The test stage MUST keep its exact name "{test_stage}" and MUST be based '
                 f"on the builder stage (the runtime base has no shell to run tests in)."
                 if test_stage else
                 "There is no dedicated test stage; keep the build runnable as before.")
    prompt = f"""You are restructuring a Dockerfile so a minimal, low-vulnerability base can be
used at RUNTIME even though it lacks build tooling (no shell/pip/apt).

Current Dockerfile:
```dockerfile
{dockerfile_text}
```

Application context (dependency manifests, truncated):
{code_context}

Rewrite it as a multi-stage build:
- A stage named "builder" based on `{builder_base}` performing ALL dependency
  installation and build steps (it has a shell and package tooling).
- {test_note}
- The FINAL stage (last in the file — what a plain `docker build` produces)
  based on `{runtime_base}`, which has NO shell: it may only COPY artifacts
  (from the builder and the source tree) and set metadata. Use exec-form
  CMD/ENTRYPOINT valid without a shell, with interpreter paths that exist in
  `{runtime_base}`. Ensure interpreter/library versions match between builder
  and runtime (pin the builder accordingly if needed).

Also provide a smoke command: an argv list to run as
`docker run <image> <argv...>` against the final image that verifies the
application's entry module actually loads on the minimal base and exits 0
within a few seconds (an import/--version style check, NOT starting a server).
If `{runtime_base}` defines an ENTRYPOINT, the argv must be valid as its
arguments; otherwise include the absolute interpreter path.

Respond with ONLY a JSON object, nothing else:
{{"dockerfile": "<full new Dockerfile text>", "smoke_command": ["<argv>", ...]}}"""

    try:
        client = _get_client()
        response = client.messages.create(
            model="claude-opus-4-8", max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = "".join(b.text for b in response.content if b.type == "text").strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.DOTALL)
        try:
            proposal = json.loads(raw)
        except json.JSONDecodeError:
            # Models sometimes wrap the object in prose despite instructions —
            # recover the outermost JSON object before giving up.
            start, end = raw.find("{"), raw.rfind("}")
            if start < 0 or end <= start:
                raise
            proposal = json.loads(raw[start:end + 1])
        df = proposal.get("dockerfile", "")
        smoke = proposal.get("smoke_command")
        if not df.strip() or not _FROM_RE.search(df.splitlines()[0].strip()) and "FROM" not in df:
            raise ValueError("proposal has no usable Dockerfile")
        if not (isinstance(smoke, list) and smoke and all(isinstance(a, str) for a in smoke)):
            raise ValueError("proposal has no usable smoke_command")
        # The candidate must actually be the FINAL stage's base, or the rewrite
        # didn't do what was asked.
        final = _resolve_final_base_stage(_parse_stages(df))
        if not final or final["base"] != runtime_base:
            raise ValueError(f"final stage base is {final and final['base']}, expected {runtime_base}")
        return {"dockerfile": df, "smoke_command": smoke}
    except Exception as exc:
        logger.warning(f"Restructure proposal failed ({exc}) — candidate stays rejected")
        return None


def _runtime_smoke(tag: str, smoke_command: list[str], timeout: int = 60) -> int:
    """Run the proposal's smoke argv against the final image, network-denied."""
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", tag, *smoke_command],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        logger.debug(f"runtime smoke failed ({result.returncode}): {result.stderr[-500:]}")
    return result.returncode


def _build_test_scan(
    app_dir: str,
    tag: str,
    test_stage: str | None,
    test_command: str | None,
    baseline_key: tuple[int, int],
    smoke_command: list[str] | None = None,
) -> dict:
    """
    Build + run the app's real tests + rescan. Unlike earlier versions, a
    test-failing candidate is still fully built and scanned so it can be
    retained as an adjudication candidate. `improved` requires tests passing
    AND a strictly better severity key. When `smoke_command` is given (a
    restructured builder/runtime candidate — tests ran on the BUILDER lineage),
    the final image must additionally pass the runtime smoke run, since only
    that proves the artifacts load on the shell-less runtime base.
    """
    result: dict = {"tag": tag, "tests_passed": False, "vulns": None,
                    "improved": False, "outcome": ""}
    try:
        if test_stage:
            build_from_context(app_dir, f"{tag}-test", target=test_stage)
            result["tests_passed"] = True
        else:
            build_from_context(app_dir, tag)
            rc = run_isolated(tag, test_command)
            result["tests_passed"] = rc == 0
            if rc != 0:
                result["outcome"] = f"tests failed (exit {rc})"
    except Exception as exc:
        result["outcome"] = f"build/test failed: {exc}"

    try:
        build_from_context(app_dir, tag)  # final runtime image
        raw_scan = scan_image(tag)
        result["vulns"] = extract_vulnerabilities(raw_scan)
    except Exception as exc:
        result["outcome"] = result["outcome"] or f"final build/rescan failed: {exc}"
        return result

    if result["tests_passed"] and smoke_command:
        try:
            rc = _runtime_smoke(tag, smoke_command)
        except Exception as exc:
            rc = -1
            logger.debug(f"runtime smoke errored: {exc}")
        if rc != 0:
            result["tests_passed"] = False
            result["outcome"] = f"runtime smoke failed (exit {rc}) — artifacts don't load on the minimal base"

    key = severity_key(result["vulns"])
    if result["tests_passed"]:
        if key < baseline_key:
            result["improved"] = True
            result["outcome"] = f"passed, (C,H) {baseline_key} -> {key}"
        else:
            result["outcome"] = f"no improvement ((C,H) {baseline_key} -> {key})"
    return result


# ── Base artifact publication (2.5) ──────────────────────────────────────────

def _base_artifact_name(base_repo: str) -> str:
    """
    Vendor-qualified artifact repo name for a base ref, so curated bases from
    different vendors never collide under GHCR_NAMESPACE: the bare last path
    component would map both `python` and `cgr.dev/chainguard/python` onto
    `python:...`. Drops the registry host and Docker Hub's implicit `library/`,
    then joins the remaining path with '-':
      python                        -> python
      docker.io/library/python      -> python
      cgr.dev/chainguard/python     -> chainguard-python
      gcr.io/distroless/python3-... -> distroless-python3-...
    """
    parts = base_repo.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        parts = parts[1:]   # registry host
    if len(parts) > 1 and parts[0] == "library":
        parts = parts[1:]   # Docker Hub's implicit namespace
    return "-".join(parts) or base_repo


def _publish_base_artifact(df_path: str, base_changed: bool) -> dict:
    """
    Scan the winning state's resolved base standalone (always — Phase B needs
    its vuln IDs for the app-introduced delta), and, when Phase A actually
    changed something, publish it as a vendor-qualified
    {artifact-name}:{tag}-golden-base (zero CVEs) or -optimized-base under
    GHCR_NAMESPACE (see _base_artifact_name).
    """
    base_ref = _current_base(df_path)
    out: dict = {"base_ref": base_ref, "published": None, "vuln_ids": set()}
    if not base_ref:
        return out

    # Does the winning Dockerfile carry an injected OS-upgrade layer?
    with open(df_path) as fh:
        df_text = fh.read()
    upgrade = [
        l.strip() for l in df_text.splitlines()
        if l.strip().startswith("RUN ") and l.strip()[4:] in set(patcher._UPGRADE_COMMANDS.values())
    ]

    with tempfile.TemporaryDirectory(prefix="vuln-base-") as tmpdir:
        with open(os.path.join(tmpdir, "Dockerfile"), "w") as fh:
            fh.write("\n".join([f"FROM {base_ref}"] + upgrade) + "\n")
        local_tag = "vuln-agent-base:candidate"
        try:
            build_from_context(tmpdir, local_tag)
            raw = scan_image(local_tag)
        except Exception as exc:
            logger.warning(f"Base artifact build/scan failed: {exc}")
            return out

    base_vulns = extract_vulnerabilities(raw)
    out["vuln_ids"] = {v["id"] for v in base_vulns}
    out["severity"] = severity_key(base_vulns)

    if not base_changed:
        return out  # nothing improved at the base level — nothing to publish

    split = tag_finder.split_ref(base_ref)
    if split is None:
        return out
    base_repo, base_tag = split
    suffix = "golden-base" if severity_key(base_vulns) == (0, 0) else "optimized-base"
    artifact_repo = _base_artifact_name(base_repo)
    dest = (f"{GHCR_NAMESPACE}/{artifact_repo}:{base_tag}-{suffix}"
            if GHCR_NAMESPACE else f"{artifact_repo}:{base_tag}-{suffix}")
    try:
        tag_local_image(local_tag, dest)
        if GHCR_NAMESPACE:
            push_image(dest)
        out["published"] = dest
        logger.info(f"Published base artifact: {dest}")
    except Exception as exc:
        logger.warning(f"Base artifact publication failed: {exc}")
    return out


def _cleanup_images(tags: list[str], keep: str | None) -> None:
    for t in tags:
        if t == keep:
            continue
        subprocess.run(["docker", "rmi", t, f"{t}-test"], capture_output=True, timeout=60)


# ── The internal pipeline ─────────────────────────────────────────────────────

def remediate_internal(
    image_ref: str,
    config_entry: dict,
    current_vulns: list[dict],
    os_info: dict,
    max_candidates: int = 3,
) -> dict:
    """
    Phased internal remediation (spec 2.1–2.8). Returns
    {final_tag, final_vulns, deployable, trail, base_artifact, judgment} —
    final_tag None means nothing improved.
    """
    no_change = {"final_tag": None, "final_vulns": current_vulns, "deployable": True,
                 "trail": [], "base_artifact": None, "judgment": None}

    split = tag_finder.split_ref(image_ref)
    if split is None:
        logger.warning(f"Cannot remediate {image_ref} — no plain tag to name a result from")
        return no_change
    origin_repo, _ = split
    repo_name = tag_finder.repo_name(origin_repo)

    source_repo = config_entry.get("sourceRepo")
    dockerfile_path = config_entry.get("dockerfilePath", "Dockerfile")
    test_stage = config_entry.get("testStage")
    test_command = config_entry.get("testCommand")
    if not source_repo or not (test_stage or test_command):
        logger.warning(f"Incomplete hardening config for {repo_name} — skipping")
        return no_change
    if not docker_available():
        logger.warning(f"Docker daemon unavailable — internal remediation for {repo_name} skipped")
        return no_change

    token = os.environ.get("GITOPS_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    states: list[dict] = []          # every candidate, pass or fail (for 2.8 + report)
    best_tag: str | None = None
    best_vulns = current_vulns
    best_key = severity_key(current_vulns)
    baseline_key = best_key
    attempt_n = 0

    with tempfile.TemporaryDirectory(prefix="vuln-harden-") as tmpdir:
        try:
            repo_dir = _clone_repo(source_repo, token, tmpdir)
        except Exception as exc:
            logger.warning(str(exc))
            return no_change

        # The app root is the directory holding the Dockerfile — the repo root
        # for a single-app repo, or a subdirectory when dockerfile-path points
        # into a monorepo (e.g. "python-app/Dockerfile"). Build context, test
        # runs, and dependency-manifest edits all happen there.
        df_path = os.path.normpath(os.path.join(repo_dir, dockerfile_path))
        app_dir = os.path.dirname(df_path)
        if not (app_dir == repo_dir or app_dir.startswith(repo_dir + os.sep)):
            logger.warning(f"dockerfilePath {dockerfile_path!r} escapes the clone for "
                           f"{repo_name} — cannot remediate")
            return no_change
        original_base = _current_base(df_path)
        if original_base is None:
            logger.warning(f"No FROM line in {dockerfile_path} for {repo_name} — cannot remediate")
            return no_change

        code_ctx = _code_context(app_dir, os.path.basename(df_path))
        tried_bases: set[str] = {original_base}
        restructured: set[str] = set()   # candidates already given their one restructure shot

        def budget_left() -> bool:
            return attempt_n < INTERNAL_MAX_ATTEMPTS

        def attempt(step: str, detail: str, smoke_command: list[str] | None = None) -> bool:
            """Validate current repo state; adopt on improvement; always retain the state."""
            nonlocal best_tag, best_vulns, best_key, attempt_n
            attempt_n += 1
            tag = f"vuln-agent-harden/{repo_name}:{attempt_n}"
            r = _build_test_scan(app_dir, tag, test_stage, test_command, best_key,
                                 smoke_command=smoke_command)
            states.append({"step": step, "detail": detail, **r})
            if r["improved"]:
                best_tag, best_vulns, best_key = tag, r["vulns"], severity_key(r["vulns"])
                return True
            return False

        # ═══ Phase A: base ladder with LLM recursion (2.1–2.4) ═══
        for round_n in range(LLM_BASE_MAX_ROUNDS):
            # 2.1 — tag-bump ratchet on the current base
            for _ in range(TAG_BUMP_MAX_LOOPS):
                if not budget_left() or best_key == (0, 0):
                    break
                base = _current_base(df_path)
                base_split = tag_finder.split_ref(base)
                if not base_split:
                    break
                try:
                    t = tag_finder.find_better_tag(
                        base_split[0], base_split[1], len(best_vulns),
                        allow_major=ALLOW_MAJOR_TAG_BUMP,
                    )
                except Exception as exc:
                    logger.debug(f"Tag lookup failed for {base}: {exc}")
                    t = None
                if not t:
                    break
                candidate = f"{base_split[0]}:{t['tag']}"
                tried_bases.add(candidate)
                snap = _snapshot(app_dir, df_path)
                _patch_dockerfile_base(df_path, candidate)
                if not attempt("base-tag-bump", candidate):
                    _restore(snap)
                    break

            # 2.2 — OS-patch injection loop
            for _ in range(OS_PATCH_MAX_LOOPS):
                if not budget_left() or best_key == (0, 0):
                    break
                family = _dominant_family(best_vulns) or os_info.get("family", "")
                upgrade = patcher.upgrade_lines(_current_base(df_path), [family])
                if not upgrade:
                    break
                snap = _snapshot(app_dir, df_path)
                if not _inject_os_upgrade(df_path, upgrade):
                    break
                if not attempt("os-patch", f"{family} blanket upgrade in base stage"):
                    _restore(snap)
                    break

            if best_key == (0, 0) or not budget_left():
                break

            # 2.3 — LLM base determination from application code context
            candidates = suggest_base_images(
                _current_base(df_path), best_vulns, code_ctx,
                sorted(tried_bases), max_candidates,
            )
            if not candidates:
                break

            # 2.4 — swap to the first viable candidate, then re-run the ladder on it
            swapped = False
            for candidate in candidates:
                if not budget_left():
                    break
                tried_bases.add(candidate)
                snap = _snapshot(app_dir, df_path)
                _strip_injected_upgrade(df_path)  # other family's upgrade breaks a new base
                _patch_dockerfile_base(df_path, candidate)
                if attempt("llm-base", candidate):
                    swapped = True
                    break
                _restore(snap)

                # 2.4b — builder/runtime restructure (LLM call site 5): a
                # candidate rejected only because it LACKS BUILD TOOLING (the
                # distroless/chainguard "/bin/sh missing" signature) can still
                # serve as the RUNTIME base — build in a stage on the current
                # working base, copy artifacts in. Gated like everything else
                # (rebuild + tests on the builder lineage + rescan) PLUS a
                # runtime smoke run proving the artifacts load on the minimal
                # base. One restructure attempt per candidate, on budget.
                if (candidate not in restructured
                        and _is_tooling_failure(states[-1]["outcome"])
                        and budget_left()):
                    restructured.add(candidate)
                    with open(df_path) as fh:
                        working_df = fh.read()
                    proposal = propose_restructure(
                        working_df, candidate, _current_base(df_path),
                        test_stage, code_ctx,
                    )
                    if proposal:
                        snap2 = _snapshot(app_dir, df_path)
                        with open(df_path, "w") as fh:
                            fh.write(proposal["dockerfile"])
                        if attempt("restructure",
                                   f"builder({_snapshot_base(working_df)}) + runtime({candidate})",
                                   smoke_command=proposal["smoke_command"]):
                            swapped = True
                            break
                        _restore(snap2)
            if not swapped:
                break

        # ═══ 2.5: standalone base artifact + base vuln IDs for the delta ═══
        base_changed = any(
            s["improved"] and s["step"] in ("base-tag-bump", "os-patch", "llm-base", "restructure")
            for s in states
        )
        base_artifact = _publish_base_artifact(df_path, base_changed)

        # ═══ Phase B: dependency loop on the app-introduced delta (2.6–2.7) ═══
        base_ids = base_artifact.get("vuln_ids", set())
        for i in range(DEP_UPGRADE_MAX_ITERATIONS):
            if not budget_left() or best_key == (0, 0):
                break
            delta = [v for v in best_vulns if v["id"] not in base_ids]
            if not delta:
                break
            snap = _snapshot(app_dir, df_path)
            bumps = dep_upgrader.apply(app_dir, delta, _current_base(df_path))
            if not bumps:
                break
            if not attempt(f"dep-bump#{i + 1}", ", ".join(bumps)):
                _restore(snap)
                break

        # ═══ Phase C: outcome (2.8) ═══
        judgment = None
        if best_tag and best_key == (0, 0):
            pass  # strict golden — orchestrator names it golden-base-app
        elif states:
            verdict = judge_best_candidate(states, baseline_key)
            if verdict is None:
                # Deterministic fallback: severity-best among test-passing states
                passing = [s for s in states if s["tests_passed"] and s.get("vulns") is not None]
                if passing:
                    best_state = min(passing, key=lambda s: severity_key(s["vulns"]))
                    if severity_key(best_state["vulns"]) < baseline_key:
                        best_tag, best_vulns = best_state["tag"], best_state["vulns"]
                        best_key = severity_key(best_vulns)
            else:
                s = verdict["state"]
                # Adopt the balanced pick only if it actually improves on the
                # baseline (possibly with failing tests — that's the point of a
                # balanced pick, and deployability is flagged separately below).
                if severity_key(s["vulns"]) < baseline_key:
                    best_tag, best_vulns = s["tag"], s["vulns"]
                    best_key = severity_key(best_vulns)
                judgment = {"justification": verdict["justification"],
                            "code_fixes": verdict["code_fixes"]}

        final_state = next((s for s in states if s["tag"] == best_tag), None)
        deployable = bool(final_state and final_state["tests_passed"]) if best_tag else True

        _cleanup_images([s["tag"] for s in states], keep=best_tag)

    trail = [
        {"step": s["step"], "detail": s["detail"], "outcome": s["outcome"],
         "tests_passed": s["tests_passed"],
         "critical": severity_key(s["vulns"])[0] if s.get("vulns") is not None else None,
         "high": severity_key(s["vulns"])[1] if s.get("vulns") is not None else None}
        for s in states
    ]
    return {
        "final_tag": best_tag,
        "final_vulns": best_vulns,
        "deployable": deployable,
        "trail": trail,
        "base_artifact": {"ref": base_artifact.get("base_ref"),
                          "published": base_artifact.get("published")} if states else None,
        "judgment": judgment,
    }
