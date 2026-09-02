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


def build_from_context(context_dir: str, tag: str, target: str | None = None, timeout: int = 900) -> None:
    """
    Build a Docker image from a real build context directory (e.g. a cloned repo),
    optionally targeting one stage of a multi-stage Dockerfile — used by
    agent/hardener.py to validate a candidate base image, and to run a
    Dockerfile's own `test` stage as the pass/fail signal.

    Raises RuntimeError on build (or, when target is a test stage, test) failure —
    callers use "did this raise" as the pass/fail signal, no separate check needed.
    """
    cmd = ["docker", "build", "-t", tag]
    if target:
        cmd += ["--target", target]
    cmd.append(context_dir)

    logger.info(f"Building {tag} from {context_dir}" + (f" (target: {target})" if target else "") + " …")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"docker build failed (target={target}):\n"
            f"--- stdout ---\n{result.stdout[-1500:]}\n"
            f"--- stderr ---\n{result.stderr[-1500:]}"
        )
    logger.info(f"Build OK: {tag}")


def run_isolated(image_ref: str, command: str, timeout: int = 600) -> int:
    """
    Run a command inside image_ref with no network access (`--network none`) and
    return its exit code. Used to run a test suite from a cloned, untrusted
    source repo without exposing the agent's mounted credentials to a network a
    compromised/malicious test could reach — not full sandboxing (still shares
    the docker daemon/host kernel), but a cheap, meaningful mitigation.
    """
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", image_ref, "sh", "-c", command],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.stdout:
        logger.debug(f"test output (stdout):\n{result.stdout[-2000:]}")
    if result.stderr:
        logger.debug(f"test output (stderr):\n{result.stderr[-2000:]}")
    return result.returncode


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


def tag_local_image(src_ref: str, dest_ref: str) -> None:
    """
    Retag a locally built Docker image under a new name — `docker tag`, no daemon
    round-trip to a registry. Used to promote the last local build to its final
    `<original-tag>-optimized` name before push_image() sends it out.
    """
    logger.info(f"Tagging {src_ref} -> {dest_ref} ...")
    result = subprocess.run(
        ["docker", "tag", src_ref, dest_ref],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker tag failed: {src_ref} -> {dest_ref}\n{result.stderr[-1500:]}"
        )
    logger.info(f"Tagged: {dest_ref}")


def copy_image(src_ref: str, dest_ref: str) -> None:
    """
    Registry-to-registry copy via crane — no Docker daemon required.

    Used to promote an upstream tag-bump candidate into GHCR_NAMESPACE without
    a local pull/push round-trip.
    """
    logger.info(f"Copying {src_ref} -> {dest_ref} ...")
    result = subprocess.run(
        ["crane", "copy", src_ref, dest_ref],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"crane copy failed: {src_ref} -> {dest_ref}\n{result.stderr[-1500:]}"
        )
    logger.info(f"Copied: {dest_ref}")


def build_and_push(dockerfile_content: str, source_image: str, iteration: int) -> str:
    """Convenience wrapper: build then push. Use the split functions in new code."""
    ref = build_image(dockerfile_content, source_image, iteration)
    push_image(ref)
    return ref
