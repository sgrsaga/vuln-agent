#!/usr/bin/env python3
"""
vuln-agent — Agentic Docker image vulnerability remediator

Usage (local):
    export ANTHROPIC_API_KEY=sk-ant-...
    export GHCR_NAMESPACE=ghcr.io/myorg          # optional: push images
    export GITHUB_TOKEN=ghp_...                   # optional: create release
    export GITHUB_REPO=myorg/my-repo             # optional: create release
    python main.py ghcr.io/dexidp/dex:v2.45.1

Usage (GitHub Actions):
    See .github/workflows/vuln-remediate.yml — all env vars are injected
    automatically; artifacts are uploaded by actions/upload-artifact.
"""

import argparse
import logging
import os
import shutil
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vuln-agent")


def _check_deps() -> bool:
    ok = True
    for cmd in ("trivy", "docker"):
        if not shutil.which(cmd):
            logger.error(f"Required command not found: {cmd}")
            ok = False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY is not set")
        ok = False
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Iteratively scan and patch a Docker image until no HIGH/CRITICAL CVEs remain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("image", help="Docker image to remediate (e.g. ghcr.io/dexidp/dex:v2.45.1)")
    parser.add_argument(
        "--max-iterations", type=int, default=int(os.environ.get("MAX_ITERATIONS", "5")),
        help="Safety cap on remediation loops (default: 5)"
    )
    parser.add_argument(
        "--output-dir", default=os.environ.get("OUTPUT_DIR", "output"),
        help="Directory for scan JSON and report Markdown artifacts (default: output/)"
    )
    args = parser.parse_args()

    os.environ["MAX_ITERATIONS"] = str(args.max_iterations)
    os.environ["OUTPUT_DIR"] = args.output_dir

    if not _check_deps():
        return 1

    logger.info(f"Target image : {args.image}")
    logger.info(f"Max iterations: {args.max_iterations}")
    logger.info(f"Output dir   : {args.output_dir}/")
    if os.environ.get("GHCR_NAMESPACE"):
        logger.info(f"GHCR push    : {os.environ['GHCR_NAMESPACE']}")
    else:
        logger.info("GHCR push    : disabled (GHCR_NAMESPACE not set)")

    from agent.orchestrator import run
    result = run(args.image)

    print()
    print("=" * 60)
    print("PIPELINE COMPLETE")
    print(f"  Status       : {result['status']}")
    print(f"  Final image  : {result['final_image']}")
    print(f"  Iterations   : {result['iterations']}")
    if result.get("remaining_vulns", -1) >= 0:
        print(f"  Remaining CVEs: {result['remaining_vulns']}")
    print(f"  Artifacts    : {args.output_dir}/")
    print("=" * 60)

    return 0 if result["status"] == "clean" else 1


if __name__ == "__main__":
    sys.exit(main())
