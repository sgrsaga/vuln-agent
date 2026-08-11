#!/usr/bin/env python3
"""
vuln-agent — Agentic Docker image vulnerability remediator

Single image:
    python main.py ghcr.io/dexidp/dex:v2.45.1

Auto-discover all images in cluster (k8s mode):
    python main.py --discover

Exclude namespaces from discovery:
    python main.py --discover --exclude-namespaces kube-system,monitoring,logging
"""

import argparse
import logging
import os
import re
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vuln-agent")


def _check_deps(need_docker: bool = True) -> bool:
    ok = True
    if not shutil.which("trivy"):
        logger.error("Required command not found: trivy")
        ok = False
    if need_docker and not shutil.which("docker"):
        logger.error("Required command not found: docker")
        ok = False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY is not set")
        ok = False
    return ok


def _slugify(image_ref: str) -> str:
    """Convert an image reference to a filesystem-safe directory name."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", image_ref)[:80]


def _print_summary(results: list[tuple[str, dict]]) -> None:
    print("\n" + "=" * 60)
    print("DISCOVERY MODE — FINAL SUMMARY")
    print(f"  {'Image':<55} {'Status':<20} {'CVEs left'}")
    print(f"  {'-'*55} {'-'*20} {'-'*9}")
    for img, res in results:
        status = res.get("status", "unknown")
        remaining = res.get("remaining_vulns", "?")
        label = img if len(img) <= 55 else "..." + img[-52:]
        print(f"  {label:<55} {status:<20} {remaining}")
    print("=" * 60)


def run_single(args) -> int:
    import agent.publisher as pub
    from agent.orchestrator import run

    output_dir = Path(args.output_dir)
    pub.set_output_dir(output_dir)

    result = run(args.image, create_release=True)

    print()
    print("=" * 60)
    print("PIPELINE COMPLETE")
    print(f"  Status        : {result['status']}")
    print(f"  Final image   : {result['final_image']}")
    print(f"  Iterations    : {result['iterations']}")
    if result.get("remaining_vulns", -1) >= 0:
        print(f"  Remaining CVEs: {result['remaining_vulns']}")
    print(f"  Artifacts     : {output_dir}/")
    print("=" * 60)

    return 0 if result["status"] == "clean" else 1


def run_discovery(args) -> int:
    import agent.publisher as pub
    from agent.discoverer import discover_images
    from agent.orchestrator import run

    # Build the exclusion list from all sources
    excluded: list[str] = []
    env_excluded = os.environ.get("EXCLUDED_NAMESPACES", "")
    if env_excluded:
        excluded.extend(ns.strip() for ns in env_excluded.split(",") if ns.strip())
    if args.exclude_namespaces:
        excluded.extend(ns.strip() for ns in args.exclude_namespaces.split(",") if ns.strip())
    excluded = list(dict.fromkeys(excluded))  # deduplicate, preserve order

    include_init = os.environ.get("INCLUDE_INIT_CONTAINERS", "false").lower() == "true"

    pub.publish_event("discover_start",
        f"Discovering images (excluding: {', '.join(excluded) or 'none'})")

    images = discover_images(excluded, include_init)
    if not images:
        logger.warning("No images discovered — nothing to scan")
        return 0

    pub.publish_event("discover_complete",
        f"Found {len(images)} images to remediate",
        {"count": len(images), "images": images})

    logger.info(f"Images to scan ({len(images)}):")
    for img in images:
        logger.info(f"  {img}")

    base_output = Path(args.output_dir)
    base_output.mkdir(parents=True, exist_ok=True)

    results: list[tuple[str, dict]] = []

    for idx, image in enumerate(images, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"[{idx}/{len(images)}] Processing: {image}")

        # Each image gets its own output subdirectory
        image_output = base_output / _slugify(image)
        pub.set_output_dir(image_output)

        try:
            result = run(image, create_release=False)   # defer release to end
        except Exception as exc:
            logger.error(f"Unhandled error for {image}: {exc}", exc_info=True)
            result = {"status": "error", "final_image": image,
                      "iterations": 0, "remaining_vulns": -1}

        results.append((image, result))

    _print_summary(results)

    # One combined GitHub Release with all image artifacts
    logger.info("Creating combined GitHub Release with all artifacts...")
    pub.set_output_dir(base_output)  # reset so create_github_release logs correctly
    try:
        pub.create_github_release(base_dir=base_output)
    except Exception as exc:
        logger.warning(f"GitHub Release creation failed: {exc}")

    any_clean = any(r.get("status") == "clean" for _, r in results)
    return 0 if any_clean else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Iteratively scan and patch Docker images until no HIGH/CRITICAL CVEs remain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Mode: single image OR discover
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "image", nargs="?",
        help="Single Docker image to remediate (e.g. ghcr.io/org/app:tag)"
    )
    mode.add_argument(
        "--discover", action="store_true",
        help="Auto-discover all images running in the Kubernetes cluster"
    )

    parser.add_argument(
        "--exclude-namespaces",
        metavar="NS1,NS2",
        help="Comma-separated namespaces to skip during discovery "
             "(also reads EXCLUDED_NAMESPACES env var)"
    )
    parser.add_argument(
        "--max-iterations", type=int,
        default=int(os.environ.get("MAX_ITERATIONS", "5")),
        help="Safety cap on remediation loops per image (default: 5)"
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", "output"),
        help="Base directory for artifacts (default: output/)"
    )

    args = parser.parse_args()

    # Propagate to env so orchestrator picks them up
    os.environ["MAX_ITERATIONS"] = str(args.max_iterations)

    if not _check_deps():
        return 1

    if args.discover:
        logger.info("Mode         : cluster discovery")
        logger.info(f"Max iter/image: {args.max_iterations}")
        logger.info(f"Output dir   : {args.output_dir}/")
        if os.environ.get("GHCR_NAMESPACE"):
            logger.info(f"GHCR push    : {os.environ['GHCR_NAMESPACE']}")
        return run_discovery(args)
    else:
        logger.info(f"Mode         : single image")
        logger.info(f"Target       : {args.image}")
        logger.info(f"Max iterations: {args.max_iterations}")
        logger.info(f"Output dir   : {args.output_dir}/")
        if os.environ.get("GHCR_NAMESPACE"):
            logger.info(f"GHCR push    : {os.environ['GHCR_NAMESPACE']}")
        return run_single(args)


if __name__ == "__main__":
    sys.exit(main())
