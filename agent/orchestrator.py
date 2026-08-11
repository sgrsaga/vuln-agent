"""
Main agentic remediation loop.

Per iteration:
  1. Scan current image with Trivy         → save scan JSON artifact
  2. Generate Claude recovery report       → save report Markdown artifact
  3. Ask Claude to patch the image         → generate Dockerfile
  4. Build the patched image               → push to GHCR if configured
  5. Rescan the new image                  → compare vulnerability counts
  6. Continue if improved; stop otherwise

Termination conditions (first one hit wins):
  A. Zero HIGH/CRITICAL vulnerabilities remaining
  B. Claude determines no further Dockerfile patches are possible
  C. A new patch did not reduce the vulnerability count
  D. MAX_ITERATIONS reached
"""

import logging
import os
from pathlib import Path

from .scanner import scan_image, extract_vulnerabilities
from .reporter import generate_report
from .patcher import generate_patch
from .builder import build_and_push
from .publisher import publish_scan, publish_report, publish_event, create_github_release

logger = logging.getLogger(__name__)

MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "5"))
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "output"))


def run(image_ref: str) -> dict:
    """
    Drive the full remediation pipeline and return a summary dict.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

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

        # ── 1. Scan ─────────────────────────────────────────────────────────
        try:
            raw_scan = scan_image(current_image)
        except Exception as exc:
            publish_event("error", f"Scan failed: {exc}")
            return _result("scan_error", current_image, iteration, 0)

        vulns = extract_vulnerabilities(raw_scan)
        crit = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high = sum(1 for v in vulns if v["severity"] == "HIGH")

        publish_scan(image_ref, iteration, current_image, vulns)
        publish_event("scan_complete", f"Found {len(vulns)} vulnerabilities (CRITICAL: {crit}, HIGH: {high})", {
            "total": len(vulns), "critical": crit, "high": high,
        })

        if not vulns:
            publish_event("pipeline_complete",
                f"✅ Image `{current_image}` is clean — no HIGH/CRITICAL CVEs!",
                {"final_image": current_image, "iterations": iteration})
            _finish(image_ref)
            return _result("clean", current_image, iteration, 0)

        # ── 2. Generate report ───────────────────────────────────────────────
        publish_event("report_start", "Generating recovery report with Claude Opus 4.8 ...")
        try:
            report = generate_report(image_ref, iteration, vulns)
        except Exception as exc:
            publish_event("error", f"Report generation failed: {exc}")
            report = f"*Report generation failed: {exc}*"

        publish_report(image_ref, iteration, report)
        publish_event("report_complete", f"Report saved → output/report-iter-{iteration}.md")

        # ── 3. Generate patch Dockerfile ─────────────────────────────────────
        publish_event("patch_start", "Asking Claude to generate a patch Dockerfile ...")
        try:
            dockerfile = generate_patch(current_image, iteration, vulns, previous_dockerfiles)
        except Exception as exc:
            publish_event("error", f"Patch generation failed: {exc}")
            _finish(image_ref)
            return _result("patch_error", current_image, iteration, len(vulns))

        if dockerfile is None:
            publish_event("pipeline_complete",
                "🏁 No further Dockerfile patches possible — remaining CVEs are in Go binaries "
                "or have no upstream fix yet.",
                {"final_image": current_image, "remaining_vulns": len(vulns), "iterations": iteration})
            _finish(image_ref)
            return _result("no_further_patches", current_image, iteration, len(vulns))

        # Save the generated Dockerfile as an artifact
        df_path = OUTPUT_DIR / f"dockerfile-iter-{iteration}"
        df_path.write_text(dockerfile)
        previous_dockerfiles.append(dockerfile)
        publish_event("patch_generated",
            f"Dockerfile saved → output/dockerfile-iter-{iteration} ({len(dockerfile.splitlines())} lines)")

        # ── 4. Build patched image ───────────────────────────────────────────
        publish_event("build_start", f"Building patched image (iteration {iteration}) ...")
        try:
            new_image = build_and_push(dockerfile, current_image, iteration)
        except Exception as exc:
            publish_event("error", f"Build failed: {exc}")
            _finish(image_ref)
            return _result("build_error", current_image, iteration, len(vulns))

        publish_event("build_complete", f"Built and pushed: `{new_image}`", {"image": new_image})

        # ── 5. Rescan to verify improvement ─────────────────────────────────
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
            _finish(image_ref)
            return _result("no_improvement", new_image, iteration, len(new_vulns))

        publish_event("improvement",
            f"✅ Reduced by {improvement}: {len(vulns)} → {len(new_vulns)} CVEs",
            {"before": len(vulns), "after": len(new_vulns), "fixed": improvement})

        current_image = new_image

    # MAX_ITERATIONS reached
    publish_event("pipeline_complete",
        f"Reached max iterations ({MAX_ITERATIONS}). Final image: `{current_image}`")
    _finish(image_ref)
    return _result("max_iterations", current_image, iteration, -1)


def _result(status: str, image: str, iterations: int, remaining: int) -> dict:
    return {
        "status": status,
        "final_image": image,
        "iterations": iterations,
        "remaining_vulns": remaining,
    }


def _finish(image_ref: str) -> None:
    """Post-run cleanup: create GitHub Release when running outside Actions."""
    try:
        create_github_release()
    except Exception as exc:
        logger.warning(f"Could not create GitHub release: {exc}")
