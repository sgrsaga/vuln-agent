"""
Main agentic remediation loop.

Per iteration:
  1. Scan current image with Trivy              → iteration 1 only: save scan-baseline.json
  1b. govulncheck binary analysis (iter 1 only) → cached, folded into the final summary
  1c. Check upstream for a newer tag that already fixes CVEs; adopt it via
      crane copy and restart the loop if one improves on the current image
      (no Docker daemon required, so this runs even without one available)
  2. Build a deterministic OS-package-upgrade Dockerfile (agent/patcher.py, no
     LLM — Trivy already gives the exact package manager + fixed versions)
  3. Build patched image LOCALLY (no push yet)
  4. Rescan locally built image                 → compare CVE counts
  5. Adopt locally if improved (still not pushed); else discard and stop
  6. Continue if improved; stop otherwise

Termination conditions (first one wins):
  A. Zero HIGH/CRITICAL effective vulnerabilities remaining
  B. No OS-fixable vulnerabilities remain (patcher.generate_patch returns None)
  C. Patched image showed no CVE reduction — not adopted
  D. MAX_ITERATIONS reached

Whatever state the loop ends in, exactly one epilogue runs afterward: it promotes
the final image (if warranted — see _promote_final_image) to
`<original-tag>-optimized` and generates the one before/after summary report.
No per-iteration artifacts are kept; only the baseline scan and the final summary
are persisted (see agent/publisher.py).
"""

import logging
import os

from .scanner import scan_image, extract_vulnerabilities
from .reporter import generate_summary_report
from .patcher import generate_patch
from .builder import build_image, push_image, copy_image, tag_local_image, docker_available
from .go_analyzer import analyze_go_vulns, summary_line as go_summary
from . import tag_finder
from . import promoter
from . import publisher
from .publisher import publish_scan, publish_summary, publish_event, publish_go_analysis

logger = logging.getLogger(__name__)

MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "5"))
ALLOW_MAJOR_TAG_BUMP = os.environ.get("ALLOW_MAJOR_TAG_BUMP", "false").lower() == "true"
GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")

# Higher-environment promotion (PR-bot) — unset GITOPS_REPO disables it entirely.
GITOPS_REPO = os.environ.get("GITOPS_REPO", "")
GITOPS_TOKEN = os.environ.get("GITOPS_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
GITOPS_BASE_BRANCH = os.environ.get("GITOPS_BASE_BRANCH", "main")
GITOPS_IMAGE_PATH_TEMPLATE = os.environ.get("GITOPS_IMAGE_PATH_TEMPLATE", "")


def run(image_ref: str, create_release: bool = True) -> dict:
    """
    Drive the full remediation pipeline for a single image.

    Args:
        image_ref:       Full image reference to remediate.
        create_release:  If True, call create_github_release() at the end.
                         Set to False in discovery/multi-image mode so the
                         caller can create one combined release after all images.

    Returns a summary dict with keys: status, final_image, iterations, remaining_vulns.
    """
    output_dir = publisher.get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    current_image = image_ref
    iteration = 0
    unbuilt_dockerfile: str | None = None

    # go_analysis is computed once on the original image and reused for all
    # iterations — Go binaries don't change when OS packages are patched.
    # (Invalidated on a tag bump — see below.)
    go_analysis: dict | None = None

    # "original" | "tag_bump" | "local_build" — how current_image was last adopted.
    # Determines which mechanism promotes it to <original-tag>-optimized at the end:
    # a local_build image only exists in the local Docker daemon (docker tag/push),
    # a tag_bump image is a registry-only ref (crane copy).
    current_image_source = "original"

    # Tag-bump lookups always target the ORIGINAL upstream repo, never
    # current_image — once an OS-layer patch is adopted, current_image points into
    # GHCR_NAMESPACE (a different repo holding our own patched artifacts, not
    # upstream releases). original_tag is fixed (used for the final -optimized
    # name); baseline_tag is a ratchet that advances on each adopted tag bump
    # (used only as the tag-bump search's "current version" baseline).
    origin_split = tag_finder.split_ref(image_ref)
    origin_repo, original_tag = origin_split if origin_split else (None, None)
    baseline_tag = original_tag

    baseline_vulns: list[dict] | None = None
    final_vulns: list[dict] = []
    status = "unknown"

    publish_event("pipeline_start", f"Starting remediation for `{image_ref}`", {
        "image": image_ref,
        "max_iterations": MAX_ITERATIONS,
    })

    while iteration < MAX_ITERATIONS:
        iteration += 1
        logger.info("=" * 60)
        logger.info(f"ITERATION {iteration}: scanning {current_image}")
        publish_event("scan_start", f"Iteration {iteration}: scanning `{current_image}`")

        # ── 1. Scan ───────────────────────────────────────────────────────────
        try:
            raw_scan = scan_image(current_image)
        except Exception as exc:
            publish_event("error", f"Scan failed: {exc}")
            if baseline_vulns is None:
                # Nothing to promote or summarize yet — bail out immediately.
                return _done("scan_error", current_image, iteration, 0, create_release)
            status = "scan_error"
            break

        vulns = extract_vulnerabilities(raw_scan)
        final_vulns = vulns
        if baseline_vulns is None:
            baseline_vulns = vulns
            publish_scan(image_ref, current_image, vulns)

        crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high = sum(1 for v in vulns if v["severity"] == "HIGH")
        publish_event("scan_complete",
            f"Found {len(vulns)} vulnerabilities (CRITICAL: {crit}, HIGH: {high})",
            {"total": len(vulns), "critical": crit, "high": high})

        if not vulns:
            publish_event("pipeline_complete",
                f"✅ `{current_image}` is clean — no HIGH/CRITICAL CVEs!",
                {"final_image": current_image, "iterations": iteration})
            status = "clean"
            break

        # ── 1b. Go binary analysis (first iteration only) ─────────────────────
        # Run govulncheck on each affected binary to classify Go CVEs precisely.
        # Results are cached — the binaries don't change between OS-layer patches.
        go_vulns = [v for v in vulns if v["type"] == "gobinary"]
        if go_vulns and go_analysis is None:
            publish_event(
                "go_analysis_start",
                f"Running govulncheck on {len(go_vulns)} Go binary CVE(s) to identify "
                "false positives and unreachable call paths …",
            )
            try:
                go_analysis = analyze_go_vulns(current_image, go_vulns)
                publish_go_analysis(image_ref, iteration, go_analysis)
                publish_event(
                    "go_analysis_complete",
                    f"Go binary analysis: {go_summary(go_analysis)}",
                    {
                        "false_positives": len(go_analysis["false_positives"]),
                        "unexploitable": len(go_analysis["unexploitable"]),
                        "confirmed": len(go_analysis["confirmed"]),
                        "skipped": len(go_analysis["skipped"]),
                    },
                )
            except Exception as exc:
                publish_event("error", f"Go binary analysis failed (non-fatal): {exc}")
                go_analysis = {}  # empty dict — analysis unavailable but don't block

        # ── 1c. Base image tag bump ─────────────────────────────────────────────
        # Check upstream for a newer tag that already fixes CVEs before generating
        # a patch for an image we might be about to replace outright. Uses
        # crane copy — no Docker daemon required, so this runs even in no_docker
        # environments. Compared with raw vuln count, not effective_vulns: a
        # different upstream tag likely has different (rebuilt) binaries, so the
        # cached go_analysis false-positive suppression doesn't apply to it.
        if baseline_tag:
            candidate = tag_finder.find_better_tag(
                origin_repo, baseline_tag, len(vulns), allow_major=ALLOW_MAJOR_TAG_BUMP,
            )
            if candidate:
                target_ref = f"{origin_repo}:{candidate['tag']}"
                publish_event(
                    "tag_bump_found",
                    f"🏷️  Newer upstream tag found: `{target_ref}` "
                    f"({len(vulns)} → {candidate['count']} vulns)",
                    {"from_tag": baseline_tag, "to_tag": candidate["tag"],
                     "before": len(vulns), "after": candidate["count"]},
                )
                if GHCR_NAMESPACE:
                    new_image = f"{GHCR_NAMESPACE}/{tag_finder.repo_name(origin_repo)}:{candidate['tag']}"
                    try:
                        copy_image(target_ref, new_image)
                    except Exception as exc:
                        publish_event("error", f"Tag-bump copy failed: {exc}")
                        new_image = None
                else:
                    new_image = target_ref

                if new_image:
                    publish_event(
                        "tag_bump",
                        f"✅ Adopting `{new_image}` in place of `{current_image}`",
                        {"image": new_image},
                    )
                    current_image = new_image
                    current_image_source = "tag_bump"
                    baseline_tag = candidate["tag"]
                    final_vulns = candidate["vulns"]
                    go_analysis = None  # binaries differ in the new tag — drop stale cache
                    continue
            else:
                publish_event("tag_bump_unavailable",
                    "No newer upstream tag improves on current CVEs")

        # Effective vuln count excludes govulncheck-confirmed false positives
        fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
        effective_vulns = [v for v in vulns if v["id"] not in fp_ids]
        if fp_ids:
            publish_event(
                "false_positives_suppressed",
                f"Suppressing {len(fp_ids)} govulncheck false positive(s) — "
                f"effective vulnerability count: {len(effective_vulns)}",
            )

        # ── 2. Generate patch Dockerfile (deterministic, no LLM) ────────────────
        publish_event("patch_start", "Generating OS-package-upgrade Dockerfile ...")
        try:
            dockerfile = generate_patch(current_image, iteration, vulns, go_analysis or None)
        except Exception as exc:
            publish_event("error", f"Patch generation failed: {exc}")
            status = "patch_error"
            break

        if dockerfile is None:
            # Distinguish why we stopped: govulncheck may have reclassified most Go vulns
            confirmed_go = len((go_analysis or {}).get("confirmed", []))
            unexploitable_go = len((go_analysis or {}).get("unexploitable", []))
            fp_go = len((go_analysis or {}).get("false_positives", []))
            stop_msg = (
                "🏁 No further Dockerfile patches possible. "
                f"Remaining: {len(effective_vulns)} effective CVEs"
            )
            if go_analysis:
                stop_msg += (
                    f" ({confirmed_go} confirmed Go CVEs need source rebuild, "
                    f"{unexploitable_go} unexploitable / risk-accepted, "
                    f"{fp_go} Trivy false positives suppressed)"
                )
            else:
                stop_msg += " (remaining CVEs require source rebuild)"
            publish_event("pipeline_complete", stop_msg, {
                "final_image": current_image,
                "remaining_vulns": len(effective_vulns),
                "iterations": iteration,
            })
            status = "no_further_patches"
            break

        publish_event("patch_generated",
            f"Patch Dockerfile generated ({len(dockerfile.splitlines())} lines)")

        # ── 3. Build (only when Docker daemon is available) ───────────────────
        if not docker_available():
            unbuilt_dockerfile = dockerfile
            publish_event(
                "build_skipped",
                "⚠️  Docker daemon not available — skipping build in this environment. "
                "The generated patch is included in the summary report for manual use. "
                "Go binary CVEs require source rebuilds; see the summary for instructions.",
                {"remaining_vulns": len(effective_vulns)},
            )
            status = "no_docker"
            break

        publish_event("build_start",
            f"Building patched image locally (iteration {iteration}) — "
            "will adopt only if CVEs improve ...")
        try:
            new_image = build_image(dockerfile, current_image, iteration)
        except Exception as exc:
            publish_event("error", f"Build failed: {exc}")
            status = "build_error"
            break

        publish_event("build_local",
            f"Local build ready: `{new_image}` — rescanning before adopting ...")

        # ── 4. Rescan locally built image ─────────────────────────────────────
        publish_event("scan_start", f"Rescanning `{new_image}` ...")
        try:
            new_raw = scan_image(new_image)
        except Exception as exc:
            publish_event("error", f"Rescan failed: {exc}")
            status = "scan_error"
            break

        new_vulns = extract_vulnerabilities(new_raw)
        # Compare using effective counts (false positives excluded)
        new_fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
        new_effective = [v for v in new_vulns if v["id"] not in new_fp_ids]
        improvement = len(effective_vulns) - len(new_effective)

        if improvement <= 0:
            publish_event("no_improvement",
                f"⚠️  Patch gave no CVE reduction ({len(effective_vulns)} → {len(new_effective)}) — "
                "discarding this build.",
                {"before": len(effective_vulns), "after": len(new_effective)})
            status = "no_improvement"
            break

        # ── 5. Adopt locally — pushing is deferred to the final promotion step ─
        publish_event("improvement",
            f"✅ Reduced by {improvement}: {len(effective_vulns)} → {len(new_effective)} effective CVEs",
            {"before": len(effective_vulns), "after": len(new_effective), "fixed": improvement})

        current_image = new_image
        current_image_source = "local_build"
        final_vulns = new_vulns

    else:
        publish_event("pipeline_complete",
            f"Reached max iterations ({MAX_ITERATIONS}). Final: `{current_image}`")
        status = "max_iterations"

    return _finish(
        status, image_ref, current_image, current_image_source,
        origin_repo, original_tag, iteration,
        baseline_vulns, final_vulns, go_analysis, unbuilt_dockerfile, create_release,
    )


def _finish(
    status: str,
    image_ref: str,
    current_image: str,
    current_image_source: str,
    origin_repo: str | None,
    original_tag: str | None,
    iteration: int,
    baseline_vulns: list[dict] | None,
    final_vulns: list[dict],
    go_analysis: dict | None,
    unbuilt_dockerfile: str | None,
    create_release: bool,
) -> dict:
    """
    Single epilogue for every loop exit: promote the final image (if warranted)
    to <original-tag>-optimized, generate the one before/after summary report,
    and create the GitHub Release.
    """
    final_image = current_image
    is_clean = not final_vulns

    # A tag bump alone reaching fully clean needs no promotion — it's already a
    # public, referenceable upstream tag, so duplicating it adds nothing. Every
    # other case where something actually changed does get promoted: an OS patch
    # always produces content that only exists in our own local build, and a tag
    # bump that didn't fully clear vulnerabilities is worth a stable reference.
    should_promote = current_image_source == "local_build" or (
        current_image_source == "tag_bump" and not is_clean
    )

    if should_promote and origin_repo and original_tag:
        repo = tag_finder.repo_name(origin_repo)
        final_tag = f"{original_tag}-optimized"
        try:
            if current_image_source == "local_build":
                final_ref = (f"{GHCR_NAMESPACE}/{repo}:{final_tag}" if GHCR_NAMESPACE
                             else f"{repo}:{final_tag}")
                tag_local_image(current_image, final_ref)
                if GHCR_NAMESPACE:
                    push_image(final_ref)
                final_image = final_ref
                publish_event("final_image", f"✅ Final optimized image: `{final_ref}`",
                    {"image": final_ref})
            elif GHCR_NAMESPACE:  # tag_bump, not fully clean
                final_ref = f"{GHCR_NAMESPACE}/{repo}:{final_tag}"
                copy_image(current_image, final_ref)
                final_image = final_ref
                publish_event("final_image", f"✅ Final optimized image: `{final_ref}`",
                    {"image": final_ref})
            # tag_bump with no GHCR_NAMESPACE: nothing to rename into (can't push a
            # new tag into someone else's upstream repo) — final_image stays the
            # adopted upstream ref, reported as-is in the summary.
        except Exception as exc:
            publish_event("error", f"Failed to promote final image: {exc}")

    # ── Higher-environment promotion (PR-bot) ───────────────────────────────────
    # Opens a reviewable PR against a separate GitOps repo bumping the image
    # reference — never auto-merges. Independent of the lower-environment path
    # (ArgoCD Image Updater polls the registry directly, no hook needed here).
    if GITOPS_REPO and GITOPS_IMAGE_PATH_TEMPLATE and origin_repo and final_image != image_ref:
        repo = tag_finder.repo_name(origin_repo)
        try:
            pr_url = promoter.open_promotion_pr(
                GITOPS_REPO, GITOPS_TOKEN, GITOPS_BASE_BRANCH,
                GITOPS_IMAGE_PATH_TEMPLATE.format(repo_name=repo), repo, final_image,
            )
            if pr_url:
                publish_event("promotion_pr", f"📬 Opened promotion PR: {pr_url}", {"pr_url": pr_url})
        except Exception as exc:
            publish_event("error", f"Failed to open promotion PR: {exc}")

    if baseline_vulns is not None:
        publish_event("summary_start", "Generating before/after summary report with Claude Opus 4.8 ...")
        try:
            summary = generate_summary_report(
                image_ref, final_image, status, iteration,
                baseline_vulns, final_vulns, go_analysis or None, unbuilt_dockerfile,
            )
        except Exception as exc:
            publish_event("error", f"Summary report generation failed: {exc}")
            summary = f"*Summary report generation failed: {exc}*"
        publish_summary(image_ref, final_image, status, summary)

    fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
    remaining = len([v for v in final_vulns if v["id"] not in fp_ids])

    return _done(status, final_image, iteration, remaining, create_release)


def _done(status: str, image: str, iterations: int, remaining: int, create_release: bool) -> dict:
    if create_release:
        try:
            publisher.create_github_release()
        except Exception as exc:
            logger.warning(f"Could not create GitHub release: {exc}")
    return {
        "status": status,
        "final_image": image,
        "iterations": iterations,
        "remaining_vulns": remaining,
    }
