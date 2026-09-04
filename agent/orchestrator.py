"""
Main agentic remediation loop.

Per iteration:
  1. Scan current image with Trivy              → iteration 1 only: save scan-baseline.json
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

from .scanner import scan_image, extract_vulnerabilities, extract_os_info, severity_key
from .reporter import generate_summary_report
from .patcher import generate_patch
from .builder import build_image, push_image, copy_image, tag_local_image, docker_available
from . import hardener
from . import tag_finder
from . import promoter
from . import publisher
from .publisher import publish_scan, publish_summary, publish_event

logger = logging.getLogger(__name__)

MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "5"))
ALLOW_MAJOR_TAG_BUMP = os.environ.get("ALLOW_MAJOR_TAG_BUMP", "false").lower() == "true"
GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")

# External images: keep a patched copy in the private registry at all? Spec
# guidance is that keeping third-party images is discouraged (upstream will
# eventually ship the fix) but it's the team's call — default ON preserves
# existing behavior.
KEEP_EXTERNAL_IMAGES = os.environ.get("KEEP_EXTERNAL_IMAGES", "true").lower() == "true"
HARDENING_MAX_CANDIDATES = int(os.environ.get("HARDENING_MAX_CANDIDATES", "3"))

# Higher-environment promotion (PR-bot) — unset GITOPS_REPO disables it entirely.
GITOPS_REPO = os.environ.get("GITOPS_REPO", "")
GITOPS_TOKEN = os.environ.get("GITOPS_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
GITOPS_BASE_BRANCH = os.environ.get("GITOPS_BASE_BRANCH", "main")
GITOPS_IMAGE_PATH_TEMPLATE = os.environ.get("GITOPS_IMAGE_PATH_TEMPLATE", "")

# File the adjudication's code-fix suggestions as an issue on the app's own
# source repo when a balanced pick is non-deployable (tests failed).
CODE_FIX_ISSUES = os.environ.get("CODE_FIX_ISSUES", "true").lower() == "true"


def run(image_ref: str, create_release: bool = True, internal_config: dict | None = None) -> dict:
    """
    Drive the full remediation pipeline for a single image.

    Args:
        image_ref:       Full image reference to remediate.
        create_release:  If True, call create_github_release() at the end.
                         Set to False in discovery/multi-image mode so the
                         caller can create one combined release after all images.
        internal_config: When set, this is an OWNED image — skip the external
                         image-layer remediation entirely (its OS patches are
                         never test-verified) and run the internal
                         rebuild-from-source pipeline instead
                         (hardener.remediate_internal: base ladder + dependency
                         loop, every step test-gated).

    Returns a summary dict with keys: status, final_image, iterations, remaining_vulns.
    """
    output_dir = publisher.get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    current_image = image_ref
    iteration = 0
    unbuilt_dockerfile: str | None = None

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
    trail: list[dict] = []
    deployable = True
    judgment: dict | None = None
    base_artifact: dict | None = None
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

        # ── Internal (owned) image: rebuild-from-source pipeline ───────────────
        # Everything test-gated: base ladder (tag bump → OS patch → LLM base)
        # then the dependency loop. No image-layer patching — an owned app never
        # ships a change its own test suite didn't pass.
        if internal_config is not None:
            publish_event("internal_start",
                f"🏗️  Internal remediation for `{image_ref}` — base ladder + dependency loop, "
                "every step rebuild/test/rescan-gated")
            result = hardener.remediate_internal(
                image_ref, internal_config, vulns, extract_os_info(raw_scan),
                HARDENING_MAX_CANDIDATES,
            )
            trail = result["trail"]
            for t in trail:
                publish_event("internal_step", f"  [{t['step']}] {t['detail']} → {t['outcome']}")
            deployable = result["deployable"]
            judgment = result["judgment"]
            base_artifact = result["base_artifact"]
            if base_artifact and base_artifact.get("published"):
                publish_event("base_artifact",
                    f"🧱 Base artifact published: `{base_artifact['published']}`")
            if result["final_tag"]:
                current_image = result["final_tag"]
                current_image_source = "internal_build"
                final_vulns = result["final_vulns"]
                # Strict golden: zero total CVEs AND tests passing; anything
                # else that improved is the balanced pick.
                status = ("golden_base_app"
                          if severity_key(final_vulns) == (0, 0) and deployable
                          else "optimized_app")
            else:
                status = "no_improvement"
            break

        # ── 1c. Base image tag bump ─────────────────────────────────────────────
        # Check upstream for a newer tag that already fixes CVEs before generating
        # a patch for an image we might be about to replace outright. Uses
        # crane copy — no Docker daemon required, so this runs even in no_docker
        # environments.
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
                    continue
            else:
                publish_event("tag_bump_unavailable",
                    "No newer upstream tag improves on current CVEs")

        # ── 2. Generate patch Dockerfile (deterministic, no LLM) ────────────────
        publish_event("patch_start", "Generating OS-package-upgrade Dockerfile ...")
        try:
            dockerfile = generate_patch(current_image, iteration, vulns)
        except Exception as exc:
            publish_event("error", f"Patch generation failed: {exc}")
            status = "patch_error"
            break

        if dockerfile is None:
            publish_event("pipeline_complete",
                "🏁 No further Dockerfile patches possible. "
                f"Remaining: {len(vulns)} CVEs (remaining CVEs are not OS-fixable — "
                "e.g. compiled-in dependencies needing a source rebuild)", {
                "final_image": current_image,
                "remaining_vulns": len(vulns),
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
                "The generated patch is included in the summary report for manual use.",
                {"remaining_vulns": len(vulns)},
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

        if severity_key(new_vulns) >= severity_key(vulns):
            publish_event("no_improvement",
                f"⚠️  Patch gave no severity reduction ((C,H) {severity_key(vulns)} → "
                f"{severity_key(new_vulns)}) — discarding this build.",
                {"before": len(vulns), "after": len(new_vulns)})
            status = "no_improvement"
            break

        # ── 5. Adopt locally — pushing is deferred to the final promotion step ─
        publish_event("improvement",
            f"✅ Severity reduced: (C,H) {severity_key(vulns)} → {severity_key(new_vulns)}",
            {"before": len(vulns), "after": len(new_vulns)})

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
        baseline_vulns, final_vulns, unbuilt_dockerfile, trail,
        deployable, judgment, base_artifact, create_release,
        internal_source_repo=(internal_config or {}).get("sourceRepo"),
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
    unbuilt_dockerfile: str | None,
    trail: list[dict],
    deployable: bool,
    judgment: dict | None,
    base_artifact: dict | None,
    create_release: bool,
    internal_source_repo: str | None = None,
) -> dict:
    """
    Single epilogue for every loop exit: name and push the final image per the
    two-scope model, generate the one before/after summary report, and create
    the GitHub Release.

    Naming: internal (test-verified rebuild) → `-golden-base-app` (strict
    golden: zero total CVEs, tests passing) or `-optimized-app` (best balanced
    pick; may be marked non-deployable when it carries test failures — the
    GitOps PR never fires for those). External → `-optimized-ext` for any real
    improvement — including a tag bump alone reaching zero (spec 1.1) — gated
    by KEEP_EXTERNAL_IMAGES. The standalone base artifact
    (`-golden-base`/`-optimized-base`) is published by hardener, not here.
    """
    final_image = current_image

    if origin_repo and original_tag and current_image_source != "original":
        repo = tag_finder.repo_name(origin_repo)
        try:
            if current_image_source == "internal_build":
                golden = status == "golden_base_app"
                suffix = "golden-base-app" if golden else "optimized-app"
                final_ref = (f"{GHCR_NAMESPACE}/{repo}:{original_tag}-{suffix}" if GHCR_NAMESPACE
                             else f"{repo}:{original_tag}-{suffix}")
                tag_local_image(current_image, final_ref)
                if GHCR_NAMESPACE:
                    push_image(final_ref)
                final_image = final_ref
                marker = "🏆" if golden else ("📦" if deployable else "⚠️ NON-DEPLOYABLE")
                publish_event("final_image",
                    f"{marker} Final image: `{final_ref}`",
                    {"image": final_ref, "deployable": deployable})
            elif not KEEP_EXTERNAL_IMAGES:
                publish_event("external_not_kept",
                    "External image improved, but KEEP_EXTERNAL_IMAGES=false — "
                    "verified result discarded per policy, details in the summary report")
            elif current_image_source == "local_build":
                final_ref = (f"{GHCR_NAMESPACE}/{repo}:{original_tag}-optimized-ext" if GHCR_NAMESPACE
                             else f"{repo}:{original_tag}-optimized-ext")
                tag_local_image(current_image, final_ref)
                if GHCR_NAMESPACE:
                    push_image(final_ref)
                final_image = final_ref
                publish_event("final_image", f"📦 Final optimized image: `{final_ref}`",
                    {"image": final_ref})
            elif current_image_source == "tag_bump" and GHCR_NAMESPACE:
                # Includes the fully-clean tag-bump case (spec 1.1: "if new
                # image has zero vulnerabilities keep it").
                final_ref = f"{GHCR_NAMESPACE}/{repo}:{original_tag}-optimized-ext"
                copy_image(current_image, final_ref)
                final_image = final_ref
                publish_event("final_image", f"📦 Final optimized image: `{final_ref}`",
                    {"image": final_ref})
            # tag_bump with no GHCR_NAMESPACE: nothing to rename into —
            # final_image stays the adopted upstream ref.
        except Exception as exc:
            publish_event("error", f"Failed to promote final image: {exc}")

    # ── Summary report (generated first — the PR body and reports repo reuse it) ─
    full_report: str | None = None
    if baseline_vulns is not None:
        publish_event("summary_start", "Generating before/after summary report with Claude Opus 4.8 ...")
        try:
            summary = generate_summary_report(
                image_ref, final_image, status, iteration,
                baseline_vulns, final_vulns, unbuilt_dockerfile,
                trail or None, deployable, judgment, base_artifact,
            )
        except Exception as exc:
            publish_event("error", f"Summary report generation failed: {exc}")
            summary = f"*Summary report generation failed: {exc}*"
        full_report = publish_summary(image_ref, final_image, status, summary)

        # Commit to the reports repo (REPORTS_REPO — no-op when unset): dated
        # record + stable latest.md, so developers can read/diff/deep-link the
        # report instead of downloading release assets.
        if origin_repo and original_tag:
            try:
                report_url = publisher.push_summary_reports(
                    tag_finder.repo_name(origin_repo), original_tag, full_report,
                )
                if report_url:
                    publish_event("report_published", f"📚 Report committed: {report_url}",
                                  {"url": report_url})
            except Exception as exc:
                publish_event("error", f"Reports-repo push failed: {exc}")

    # ── Higher-environment promotion (PR-bot) ───────────────────────────────────
    # Opens a reviewable PR against a separate GitOps repo bumping the image
    # reference — never auto-merges. Independent of the lower-environment path
    # (ArgoCD Image Updater polls the registry directly, no hook needed here).
    # The summary report rides along in the PR body so reviewers see the
    # security story exactly where they approve the change.
    if GITOPS_REPO and GITOPS_IMAGE_PATH_TEMPLATE and origin_repo and final_image != image_ref and deployable:
        repo = tag_finder.repo_name(origin_repo)
        try:
            pr_url = promoter.open_promotion_pr(
                GITOPS_REPO, GITOPS_TOKEN, GITOPS_BASE_BRANCH,
                GITOPS_IMAGE_PATH_TEMPLATE.format(repo_name=repo), repo, final_image,
                summary=full_report,
            )
            if pr_url:
                publish_event("promotion_pr", f"📬 Opened promotion PR: {pr_url}", {"pr_url": pr_url})
        except Exception as exc:
            publish_event("error", f"Failed to open promotion PR: {exc}")

    # ── Non-deployable balanced pick → code-fix issue on the app's source repo ──
    # The adjudication's code_fixes are developer action items; an issue puts
    # them in the team's normal triage flow instead of a report nobody opens.
    if (CODE_FIX_ISSUES and not deployable and judgment and internal_source_repo
            and os.environ.get("GITHUB_TOKEN")):
        crit, high = severity_key(final_vulns)
        try:
            issue_url = promoter.open_code_fix_issue(
                internal_source_repo, os.environ["GITHUB_TOKEN"],
                image_ref, final_image, judgment, crit, high,
            )
            if issue_url:
                publish_event("code_fix_issue", f"🐛 Code-fix issue filed: {issue_url}",
                              {"url": issue_url})
        except Exception as exc:
            publish_event("error", f"Failed to open code-fix issue: {exc}")

    remaining = len(final_vulns)

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
