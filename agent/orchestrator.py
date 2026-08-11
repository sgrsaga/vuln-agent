"""
Main agentic remediation loop.

Per iteration:
  1. Scan current image with Trivy       → save scan-iter-N.json
  2. Generate Claude recovery report     → save report-iter-N.md
  3. Ask Claude to patch the image       → save dockerfile-iter-N
  4. Build + push to private registry    → new image tag
  5. Rescan the new image                → compare CVE counts
  6. Continue if improved; stop otherwise

Termination conditions (first one wins):
  A. Zero HIGH/CRITICAL vulnerabilities remaining
  B. Claude returns CANNOT_PATCH_FURTHER
  C. New patch did not reduce the CVE count
  D. MAX_ITERATIONS reached
"""

import logging
import os

from .scanner import scan_image, extract_vulnerabilities
from .reporter import generate_report
from .patcher import generate_patch
from .builder import build_and_push
from . import publisher
from .publisher import publish_scan, publish_report, publish_event

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

        # ── 2. Generate report ────────────────────────────────────────────────
        publish_event("report_start", "Generating recovery report with Claude Opus 4.8 ...")
        try:
            report = generate_report(image_ref, iteration, vulns)
        except Exception as exc:
            publish_event("error", f"Report generation failed: {exc}")
            report = f"*Report generation failed: {exc}*"

        publish_report(image_ref, iteration, report)
        publish_event("report_complete",
            f"Report saved → {publisher.get_output_dir()}/report-iter-{iteration}.md")

        # ── 3. Generate patch Dockerfile ──────────────────────────────────────
        publish_event("patch_start", "Asking Claude to generate a patch Dockerfile ...")
        try:
            dockerfile = generate_patch(current_image, iteration, vulns, previous_dockerfiles)
        except Exception as exc:
            publish_event("error", f"Patch generation failed: {exc}")
            return _done("patch_error", current_image, iteration, len(vulns), create_release)

        if dockerfile is None:
            publish_event("pipeline_complete",
                "🏁 No further Dockerfile patches possible — remaining CVEs require source rebuild.",
                {"final_image": current_image, "remaining_vulns": len(vulns), "iterations": iteration})
            return _done("no_further_patches", current_image, iteration, len(vulns), create_release)

        df_path = publisher.get_output_dir() / f"dockerfile-iter-{iteration}"
        df_path.write_text(dockerfile)
        previous_dockerfiles.append(dockerfile)
        publish_event("patch_generated",
            f"Dockerfile saved → {df_path.name} ({len(dockerfile.splitlines())} lines)")

        # ── 4. Build + push ───────────────────────────────────────────────────
        publish_event("build_start", f"Building patched image (iteration {iteration}) ...")
        try:
            new_image = build_and_push(dockerfile, current_image, iteration)
        except Exception as exc:
            publish_event("error", f"Build failed: {exc}")
            return _done("build_error", current_image, iteration, len(vulns), create_release)

        publish_event("build_complete", f"Built and pushed: `{new_image}`", {"image": new_image})

        # ── 5. Rescan ─────────────────────────────────────────────────────────
        publish_event("scan_start", f"Rescanning patched image `{new_image}` ...")
        try:
            new_raw = scan_image(new_image)
        except Exception as exc:
            publish_event("error", f"Rescan failed: {exc}")
            break

        new_vulns = extract_vulnerabilities(new_raw)
        improvement = len(vulns) - len(new_vulns)

        if improvement <= 0:
            publish_event("no_improvement",
                f"⚠️  Patch did not reduce vulnerabilities ({len(vulns)} → {len(new_vulns)}). Stopping.",
                {"before": len(vulns), "after": len(new_vulns)})
            return _done("no_improvement", new_image, iteration, len(new_vulns), create_release)

        publish_event("improvement",
            f"✅ Reduced by {improvement}: {len(vulns)} → {len(new_vulns)} CVEs",
            {"before": len(vulns), "after": len(new_vulns), "fixed": improvement})

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
