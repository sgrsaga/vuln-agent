"""
Builds a patched Docker image from a Dockerfile string and optionally
pushes it to GitHub Container Registry (GHCR).

Environment variables:
  GHCR_NAMESPACE   e.g. "ghcr.io/myorg"  — if set, the image is pushed after build.
                   Leave unset for local-only builds.
"""

import os
import subprocess
import tempfile
import logging

logger = logging.getLogger(__name__)

GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")


def _image_name(image_ref: str) -> str:
    """Extract the bare repository name from a full image reference."""
    # ghcr.io/dexidp/dex:v2.45.1  →  dex
    return image_ref.split("/")[-1].split(":")[0]


def build_and_push(dockerfile_content: str, source_image: str, iteration: int) -> str:
    """
    Build a patched image from dockerfile_content and push it to GHCR.

    Tag format:
      GHCR_NAMESPACE set   →  ghcr.io/<org>/<name>:<original-tag>-patched-iter<N>
      GHCR_NAMESPACE unset →  <name>:<original-tag>-patched-iter<N>  (local only)

    Returns the full image reference of the built (and optionally pushed) image.
    """
    name = _image_name(source_image)
    original_tag = source_image.split(":")[-1] if ":" in source_image.split("/")[-1] else "latest"

    if GHCR_NAMESPACE:
        new_ref = f"{GHCR_NAMESPACE}/{name}:{original_tag}-patched-iter{iteration}"
    else:
        new_ref = f"{name}:{original_tag}-patched-iter{iteration}"

    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = os.path.join(tmpdir, "Dockerfile")
        with open(df_path, "w") as fh:
            fh.write(dockerfile_content)

        logger.info(f"Building {new_ref} ...")
        result = subprocess.run(
            ["docker", "build", "--pull", "-t", new_ref, tmpdir],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker build failed for {new_ref}:\n"
                f"--- stdout ---\n{result.stdout[-1500:]}\n"
                f"--- stderr ---\n{result.stderr[-1500:]}"
            )

    logger.info(f"Build succeeded: {new_ref}")

    if GHCR_NAMESPACE:
        logger.info(f"Pushing {new_ref} to GHCR ...")
        result = subprocess.run(
            ["docker", "push", new_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker push failed for {new_ref}:\n{result.stderr[-1500:]}"
            )
        logger.info(f"Pushed: {new_ref}")

    return new_ref
