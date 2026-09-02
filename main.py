#!/usr/bin/env python3
"""
vuln-agent — Agentic Docker image vulnerability remediator

Single image:
    python main.py ghcr.io/dexidp/dex:v2.45.1

Auto-discover all images in targeted namespaces:
    python main.py --discover --namespaces argocd,monitoring,staging

Auto-discover all images cluster-wide (minus excluded):
    python main.py --discover --exclude-namespaces kube-system,kube-public

Push policy: patched images are pushed ONLY when a Trivy rescan confirms
a net reduction in HIGH/CRITICAL CVEs.  If no improvement is detected the
locally built image is discarded and nothing reaches the registry.
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


def _maybe_harden(
    image: str,
    result: dict,
    hardening_config: dict,
    max_candidates: int,
    annotation_overrides: dict | None = None,
) -> None:
    """
    Attempt base-image hardening for an already-remediated image, if the merged
    config (HARDENING_CONFIG entry, overridden field-by-field by any
    vuln-agent.io/* annotations on the owning pod) has enough to work with and
    the image still has vulnerabilities worth trying to reduce further. No-op
    otherwise — callers don't need to pre-filter beyond ownership, this checks
    everything else itself.
    """
    import agent.publisher as pub
    import agent.hardener as hardener
    from agent.scanner import scan_image, extract_vulnerabilities, extract_os_info
    from agent import tag_finder

    if not ((result.get("remaining_vulns") or 0) > 0 and result.get("final_image")):
        return
    split = tag_finder.split_ref(image)
    repo_name = tag_finder.repo_name(split[0]) if split else None
    entry = {**hardening_config.get(repo_name, {}), **(annotation_overrides or {})}
    if not entry.get("sourceRepo"):
        return

    pub.publish_event("hardening_start", f"Attempting base-image hardening for `{image}` ...")
    try:
        raw_scan = scan_image(result["final_image"])
        current_vulns = extract_vulnerabilities(raw_scan)
        os_info = extract_os_info(raw_scan)
        harden_result = hardener.harden_image(
            image, entry, current_vulns, os_info, max_candidates,
        )
    except Exception as exc:
        logger.error(f"Hardening failed for {image}: {exc}", exc_info=True)
        pub.publish_event("error", f"Hardening failed for {image}: {exc}")
        return

    if harden_result:
        pub.publish_event(
            "hardening_complete",
            f"✅ Hardened `{image}`: {harden_result['base_used']} "
            f"({harden_result['vulns_before']} → {harden_result['vulns_after']} vulns) "
            f"→ `{harden_result['golden_image']}`",
            harden_result,
        )
    else:
        pub.publish_event("hardening_no_candidate", f"No viable hardened base found for `{image}`")


def run_single(args) -> int:
    import agent.publisher as pub
    import agent.hardener as hardener
    from agent.orchestrator import run

    output_dir = Path(args.output_dir)
    pub.set_output_dir(output_dir)

    result = run(args.image, create_release=True)

    harden_flag = getattr(args, "harden", False) or os.environ.get("HARDEN_BASE_IMAGE", "false").lower() == "true"
    if harden_flag:
        max_candidates = int(os.environ.get("HARDENING_MAX_CANDIDATES", "3"))
        _maybe_harden(args.image, result, hardener.load_hardening_config(), max_candidates)

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
    import agent.image_tracker as tracker
    import agent.hardener as hardener
    from agent.discoverer import discover_images, discover_owned_images
    from agent.orchestrator import run

    include_init = os.environ.get("INCLUDE_INIT_CONTAINERS", "false").lower() == "true"
    force_rescan = getattr(args, "force_rescan", False) or os.environ.get("FORCE_RESCAN", "false").lower() == "true"
    ttl_days = int(os.environ.get("RESCAN_INTERVAL_DAYS", str(tracker.DEFAULT_TTL_DAYS)))
    owned_label_selector = os.environ.get("OWNED_IMAGE_LABEL_SELECTOR", "")
    hardening_config = hardener.load_hardening_config()
    hardening_max_candidates = int(os.environ.get("HARDENING_MAX_CANDIDATES", "3"))

    # Target namespaces (whitelist) — takes priority over excluded list
    targets: list[str] = []
    env_targets = os.environ.get("TARGET_NAMESPACES", "")
    if env_targets:
        targets.extend(ns.strip() for ns in env_targets.split(",") if ns.strip())
    if getattr(args, "namespaces", None):
        targets.extend(ns.strip() for ns in args.namespaces.split(",") if ns.strip())
    targets = list(dict.fromkeys(targets))

    # Excluded namespaces (blacklist) — used only when no target list given
    excluded: list[str] = []
    if not targets:
        env_excluded = os.environ.get("EXCLUDED_NAMESPACES", "")
        if env_excluded:
            excluded.extend(ns.strip() for ns in env_excluded.split(",") if ns.strip())
        if getattr(args, "exclude_namespaces", None):
            excluded.extend(ns.strip() for ns in args.exclude_namespaces.split(",") if ns.strip())
        excluded = list(dict.fromkeys(excluded))

    if targets:
        pub.publish_event("discover_start",
            f"Discovering images in target namespaces: {', '.join(targets)}")
    else:
        pub.publish_event("discover_start",
            f"Discovering images (excluding: {', '.join(excluded) or 'none'})")

    images = discover_images(
        excluded_namespaces=excluded,
        include_init_containers=include_init,
        target_namespaces=targets,
    )
    if not images:
        logger.warning("No images discovered — nothing to scan")
        return 0

    pub.publish_event("discover_complete",
        f"Found {len(images)} images to remediate",
        {"count": len(images), "images": images})

    logger.info(f"Images to scan ({len(images)}):")
    for img in images:
        logger.info(f"  {img}")

    # Owned images (label-selector-matched) are eligible for base-image hardening
    # further down — never attempted for third-party/vendor images. Each maps to
    # whatever vuln-agent.io/* hardening annotations were on its pod (possibly
    # none — a HARDENING_CONFIG entry can supply the rest). Not gated on
    # hardening_config being non-empty: a repo can now be fully self-configured
    # via annotations alone, with no central config at all.
    owned_images: dict[str, dict] = {}
    if owned_label_selector:
        try:
            raw_owned = discover_owned_images(owned_label_selector)
            discovered = set(images)
            owned_images = {img: cfg for img, cfg in raw_owned.items() if img in discovered}
            if owned_images:
                pub.publish_event(
                    "owned_images_found",
                    f"{len(owned_images)} image(s) match the owned-image label selector "
                    "— eligible for base-image hardening",
                    {"count": len(owned_images)},
                )
        except Exception as exc:
            logger.warning(f"Could not determine owned images (hardening skipped this run): {exc}")

    base_output = Path(args.output_dir)
    base_output.mkdir(parents=True, exist_ok=True)

    state = tracker.load_state(base_output)
    if force_rescan:
        logger.info("FORCE_RESCAN set — ignoring tracked state, scanning everything")

    results: list[tuple[str, dict]] = []

    for idx, image in enumerate(images, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"[{idx}/{len(images)}] Processing: {image}")

        digest = tracker.resolve_digest(image)
        entry = state.get(image)
        if not force_rescan and not tracker.should_scan(entry, digest, ttl_days):
            logger.info(
                f"[{idx}/{len(images)}] Skipping {image} — unchanged since "
                f"{entry['last_scanned']} (status: {entry['status']})"
            )
            results.append((image, {
                "status": entry.get("status"),
                "final_image": entry.get("final_image"),
                "iterations": entry.get("iterations"),
                "remaining_vulns": entry.get("remaining_vulns"),
            }))
            continue

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
        tracker.record_result(state, image, digest, result)
        tracker.save_state(base_output, state)

        if image in owned_images:
            _maybe_harden(image, result, hardening_config, hardening_max_candidates, owned_images[image])

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
        "--namespaces",
        metavar="NS1,NS2",
        help="Comma-separated namespaces to scan (whitelist — overrides --exclude-namespaces). "
             "Also reads TARGET_NAMESPACES env var."
    )
    parser.add_argument(
        "--exclude-namespaces",
        metavar="NS1,NS2",
        help="Comma-separated namespaces to skip (blacklist, used when --namespaces is absent). "
             "Also reads EXCLUDED_NAMESPACES env var."
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
    parser.add_argument(
        "--force-rescan", action="store_true",
        help="Discovery mode only: ignore tracked scan state and rescan every "
             "discovered image regardless of digest/TTL. Also reads FORCE_RESCAN env var."
    )
    parser.add_argument(
        "--harden", action="store_true",
        help="Single-image mode only: attempt base-image hardening if a matching "
             "HARDENING_CONFIG entry exists for this image (discovery mode does this "
             "automatically for owned images — see OWNED_IMAGE_LABEL_SELECTOR). "
             "Also reads HARDEN_BASE_IMAGE env var."
    )

    args = parser.parse_args()

    # Propagate to env so orchestrator picks them up
    os.environ["MAX_ITERATIONS"] = str(args.max_iterations)

    if not _check_deps():
        return 1

    if args.discover:
        logger.info("Mode         : cluster discovery")
        if getattr(args, "namespaces", None) or os.environ.get("TARGET_NAMESPACES"):
            ns = args.namespaces or os.environ.get("TARGET_NAMESPACES", "")
            logger.info(f"Target ns    : {ns}")
        elif getattr(args, "exclude_namespaces", None) or os.environ.get("EXCLUDED_NAMESPACES"):
            ex = args.exclude_namespaces or os.environ.get("EXCLUDED_NAMESPACES", "")
            logger.info(f"Exclude ns   : {ex}")
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
