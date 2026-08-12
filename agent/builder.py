"""
Builds a patched Docker image from a Dockerfile string and optionally
pushes it to a private registry (GHCR).

Environment variables:
  GHCR_NAMESPACE   e.g. "ghcr.io/myorg"  — if set, push_image() uploads the
                   locally built image to the registry.
                   Leave unset for local-only builds.

Push policy (enforced by orchestrator):
  Images are pushed ONLY when a Trivy rescan of the locally built image
  shows a net reduction in HIGH/CRITICAL CVEs vs the previous iteration.
  This ensures clean-only images enter the registry.

Docker availability:
  When Docker daemon is unavailable (e.g. k8s pod without socket mount),
  docker_available() returns False. The orchestrator skips building and
  only reports the generated Dockerfile for developer use.
"""

import os
import subprocess
import tempfile
import logging

logger = logging.getLogger(__name__)

GHCR_NAMESPACE = (os.environ.get("GHCR_NAMESPACE") or "").rstrip("/")


def docker_available() -> bool:
    """Return True if the Docker daemon is reachable."""
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _image_name(image_ref: str) -> str:
    """Extract the bare repository name from a full image reference."""
    return image_ref.split("/")[-1].split(":")[0]


def _patched_ref(source_image: str, iteration: int) -> str:
    """Compute the tag for a patched image."""
    name = _image_name(source_image)
    original_tag = source_image.split(":")[-1] if ":" in source_image.split("/")[-1] else "latest"
    if GHCR_NAMESPACE:
        return f"{GHCR_NAMESPACE}/{name}:{original_tag}-patched-iter{iteration}"
    return f"{name}:{original_tag}-patched-iter{iteration}"


def build_image(dockerfile_content: str, source_image: str, iteration: int) -> str:
    """
    Build a Docker image locally from dockerfile_content.
    Does NOT push — call push_image() separately only when a CVE improvement
    has been confirmed by a Trivy rescan.

    Returns the local image reference (tag).
    """
    new_ref = _patched_ref(source_image, iteration)

    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = os.path.join(tmpdir, "Dockerfile")
        with open(df_path, "w") as fh:
            fh.write(dockerfile_content)

        logger.info(f"Building {new_ref} locally …")
        result = subprocess.run(
            ["docker", "build", "--pull", "-t", new_ref, tmpdir],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker build failed:\n"
                f"--- stdout ---\n{result.stdout[-1500:]}\n"
                f"--- stderr ---\n{result.stderr[-1500:]}"
            )

    logger.info(f"Local build OK: {new_ref}")
    return new_ref


def push_image(image_ref: str) -> None:
    """
    Push a locally built image to GHCR.
    No-op when GHCR_NAMESPACE is unset (local-only mode).
    """
    if not GHCR_NAMESPACE:
        logger.info("GHCR_NAMESPACE not set — skipping push (local mode)")
        return

    logger.info(f"Pushing {image_ref} …")
    result = subprocess.run(
        ["docker", "push", image_ref],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker push failed for {image_ref}:\n{result.stderr[-1500:]}"
        )
    logger.info(f"Pushed: {image_ref}")


def build_and_push(dockerfile_content: str, source_image: str, iteration: int) -> str:
    """Convenience wrapper: build then push. Use the split functions in new code."""
    ref = build_image(dockerfile_content, source_image, iteration)
    push_image(ref)
    return ref
