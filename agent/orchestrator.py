"""
Main agentic remediation loop.

Per iteration:
  1. Scan current image with Trivy              → save scan-iter-N.json
  1b. govulncheck binary analysis (iter 1 only) → save go-analysis-iter-1.json
  2. Generate Claude recovery report            → save report-iter-N.md
  3. Ask Claude to patch the image              → save dockerfile-iter-N
  4. Build patched image LOCALLY (no push yet)
  5. Rescan locally built image                 → compare CVE counts
  6. If improved: push to registry; else: skip push (keeps repo clean)
  7. Continue if improved; stop otherwise

Termination conditions (first one wins):
  A. Zero HIGH/CRITICAL effective vulnerabilities remaining
  B. Claude returns CANNOT_PATCH_FURTHER
  C. Patched image showed no CVE reduction — not pushed
  D. MAX_ITERATIONS reached
"""

import logging
import os

from .scanner import scan_image, extract_vulnerabilities
from .reporter import generate_report
from .patcher import generate_patch
from .builder import build_image, push_image
from .go_analyzer import analyze_go_vulns, summary_line as go_summary
from . import publisher
from .publisher import publish_scan, publish_report, publish_event, publish_go_analysis

logger = logging.getLogger(__name__)

MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "5"))


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
    previous_dockerfiles: list[str] = []

    # go_analysis is computed once on the original image and reused for all
    # iterations — Go binaries don't change when OS packages are patched.
    go_analysis: dict | None = None

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
            return _done("scan_error", current_image, iteration, 0, create_release)

        vulns = extract_vulnerabilities(raw_scan)
        crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high = sum(1 for v in vulns if v["severity"] == "HIGH")

        publish_scan(image_ref, iteration, current_image, vulns)
        publish_event("scan_complete",
            f"Found {len(vulns)} vulnerabilities (CRITICAL: {crit}, HIGH: {high})",
            {"total": len(vulns), "critical": crit, "high": high})

        if not vulns:
            publish_event("pipeline_complete",
                f"✅ `{current_image}` is clean — no HIGH/CRITICAL CVEs!",
                {"final_image": current_image, "iterations": iteration})
            return _done("clean", current_image, iteration, 0, create_release)

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

        # Effective vuln count excludes govulncheck-confirmed false positives
        fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
        effective_vulns = [v for v in vulns if v["id"] not in fp_ids]
        if fp_ids:
            publish_event(
                "false_positives_suppressed",
                f"Suppressing {len(fp_ids)} govulncheck false positive(s) — "
                f"effective vulnerability count: {len(effective_vulns)}",
            )

        # ── 2. Generate report ────────────────────────────────────────────────
        publish_event("report_start", "Generating recovery report with Claude Opus 4.8 ...")
        try:
            report = generate_report(image_ref, iteration, vulns, go_analysis or None)
        except Exception as exc:
            publish_event("error", f"Report generation failed: {exc}")
            report = f"*Report generation failed: {exc}*"

        publish_report(image_ref, iteration, report)
        publish_event("report_complete",
            f"Report saved → {publisher.get_output_dir()}/report-iter-{iteration}.md")

        # ── 3. Generate patch Dockerfile ──────────────────────────────────────
        publish_event("patch_start", "Asking Claude to generate a patch Dockerfile ...")
        try:
            dockerfile = generate_patch(
                current_image, iteration, vulns, previous_dockerfiles, go_analysis or None
            )
        except Exception as exc:
            publish_event("error", f"Patch generation failed: {exc}")
            return _done("patch_error", current_image, iteration, len(effective_vulns), create_release)

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
            return _done("no_further_patches", current_image, iteration, len(effective_vulns), create_release)

        df_path = publisher.get_output_dir() / f"dockerfile-iter-{iteration}"
        df_path.write_text(dockerfile)
        previous_dockerfiles.append(dockerfile)
        publish_event("patch_generated",
            f"Dockerfile saved → {df_path.name} ({len(dockerfile.splitlines())} lines)")

        # ── 4. Build locally (push deferred until improvement confirmed) ──────
        publish_event("build_start",
            f"Building patched image locally (iteration {iteration}) — "
            "will push only if CVEs improve ...")
        try:
            new_image = build_image(dockerfile, current_image, iteration)
        except Exception as exc:
            publish_event("error", f"Build failed: {exc}")
            return _done("build_error", current_image, iteration, len(effective_vulns), create_release)

        publish_event("build_local",
            f"Local build ready: `{new_image}` — rescanning before push ...")

        # ── 5. Rescan locally built image ─────────────────────────────────────
        publish_event("scan_start", f"Rescanning `{new_image}` ...")
        try:
            new_raw = scan_image(new_image)
        except Exception as exc:
            publish_event("error", f"Rescan failed: {exc}")
            break

        new_vulns = extract_vulnerabilities(new_raw)
        # Compare using effective counts (false positives excluded)
        new_fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
        new_effective = [v for v in new_vulns if v["id"] not in new_fp_ids]
        improvement = len(effective_vulns) - len(new_effective)

        if improvement <= 0:
            publish_event("no_improvement",
                f"⚠️  Patch gave no CVE reduction ({len(effective_vulns)} → {len(new_effective)}) — "
                "skipping registry push to keep repo clean.",
                {"before": len(effective_vulns), "after": len(new_effective)})
            return _done("no_improvement", current_image, iteration, len(new_effective), create_release)

        # ── 6. Push — only now that improvement is confirmed ──────────────────
        publish_event("build_start",
            f"CVEs reduced by {improvement} ({len(effective_vulns)} → {len(new_effective)}) — "
            f"pushing `{new_image}` to registry ...")
        try:
            push_image(new_image)
        except Exception as exc:
            publish_event("error", f"Push failed: {exc}")
            return _done("push_error", current_image, iteration, len(new_effective), create_release)

        publish_event("build_complete",
            f"✅ Pushed: `{new_image}` ({improvement} fewer CVEs)",
            {"image": new_image, "improvement": improvement})

        publish_event("improvement",
            f"✅ Reduced by {improvement}: {len(effective_vulns)} → {len(new_effective)} effective CVEs",
            {"before": len(effective_vulns), "after": len(new_effective), "fixed": improvement})

        current_image = new_image

    publish_event("pipeline_complete",
        f"Reached max iterations ({MAX_ITERATIONS}). Final: `{current_image}`")
    return _done("max_iterations", current_image, iteration, -1, create_release)


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
