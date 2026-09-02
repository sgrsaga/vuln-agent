"""
Discovers all unique container images running in a Kubernetes cluster.

Auth priority:
  1. In-cluster service account   (when running as a k8s pod)
  2. ~/.kube/config               (when running locally with kubectl context)
  3. kubectl subprocess fallback  (when the kubernetes Python client is absent)

Excluded namespaces and init-container behaviour are controlled by the caller.
"""

import json
import logging
import subprocess

logger = logging.getLogger(__name__)


def discover_images(
    excluded_namespaces: list[str] | None = None,
    include_init_containers: bool = False,
    target_namespaces: list[str] | None = None,
) -> list[str]:
    """
    Return a sorted, deduplicated list of container image references.

    Namespace selection (mutually exclusive, target takes priority):
      target_namespaces  – whitelist: scan ONLY these namespaces.
      excluded_namespaces – blacklist: scan all EXCEPT these (+ agent ns).
      If target_namespaces is non-empty, excluded_namespaces is ignored.
    """
    targets = [ns.strip() for ns in (target_namespaces or []) if ns.strip()]
    excluded = set(excluded_namespaces or [])

    if targets:
        logger.info(f"Target namespaces (whitelist): {', '.join(targets)}")
    elif excluded:
        logger.info(f"Excluded namespaces: {', '.join(sorted(excluded))}")

    try:
        return _via_client(excluded, include_init_containers, targets)
    except ImportError:
        logger.warning("kubernetes Python client not installed — falling back to kubectl")
        return _via_kubectl(excluded, include_init_containers, targets)


def _via_client(excluded: set[str], include_init: bool, targets: list[str]) -> list[str]:
    from kubernetes import client, config  # noqa: PLC0415

    try:
        config.load_incluster_config()
        logger.info("k8s auth: in-cluster service account")
    except Exception:
        config.load_kube_config()
        logger.info("k8s auth: kubeconfig")

    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces(watch=False)

    images: set[str] = set()
    skipped_ns: set[str] = set()

    for pod in pods.items:
        ns = pod.metadata.namespace
        # Whitelist mode: only scan target namespaces
        if targets and ns not in targets:
            continue
        # Blacklist mode: skip excluded namespaces
        if not targets and ns in excluded:
            skipped_ns.add(ns)
            continue
        for c in pod.spec.containers or []:
            if c.image and not _is_digest_only(c.image):
                images.add(c.image)
        if include_init:
            for c in pod.spec.init_containers or []:
                if c.image and not _is_digest_only(c.image):
                    images.add(c.image)

    if skipped_ns:
        logger.info(f"Skipped namespaces: {', '.join(sorted(skipped_ns))}")
    logger.info(f"Discovered {len(images)} unique images")
    return sorted(images)


def _via_kubectl(excluded: set[str], include_init: bool, targets: list[str]) -> list[str]:
    result = subprocess.run(
        ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"kubectl get pods failed:\n{result.stderr}")

    data = json.loads(result.stdout)
    images: set[str] = set()

    for pod in data.get("items", []):
        ns = pod["metadata"]["namespace"]
        if targets and ns not in targets:
            continue
        if not targets and ns in excluded:
            continue
        spec = pod.get("spec", {})
        for c in spec.get("containers", []):
            img = c.get("image", "")
            if img and not _is_digest_only(img):
                images.add(img)
        if include_init:
            for c in spec.get("initContainers", []):
                img = c.get("image", "")
                if img and not _is_digest_only(img):
                    images.add(img)

    logger.info(f"Discovered {len(images)} unique images via kubectl")
    return sorted(images)


def _is_digest_only(image: str) -> bool:
    """Skip bare sha256 digest references — they have no tag to patch against."""
    name = image.split("/")[-1]
    return "@sha256:" in name and ":" not in name.split("@")[0]


# Annotation keys a Deployment can set (on its pod template, which propagates to
# the actual pods) to self-service hardening config — no need to centrally
# maintain HARDENING_CONFIG for every owned app. Values here win over a matching
# HARDENING_CONFIG entry when both are present (see main.py: _maybe_harden()).
_ANNOTATION_PREFIX = "vuln-agent.io/"
_ANNOTATION_KEYS = {
    "source-repo": "sourceRepo",
    "dockerfile-path": "dockerfilePath",
    "test-stage": "testStage",
    "test-command": "testCommand",
}


def _extract_hardening_annotations(annotations: dict | None) -> dict:
    if not annotations:
        return {}
    cfg = {}
    for suffix, key in _ANNOTATION_KEYS.items():
        val = annotations.get(f"{_ANNOTATION_PREFIX}{suffix}")
        if val:
            cfg[key] = val
    return cfg


def discover_owned_images(label_selector: str) -> dict[str, dict]:
    """
    Return {image_ref: hardening_config} for pods matching label_selector,
    cluster-wide — no namespace filtering here; callers intersect the result
    with an already-namespace-filtered discover_images() list, so ownership
    can never bypass the existing namespace whitelist/blacklist.

    hardening_config holds whatever vuln-agent.io/* hardening annotations were
    present on that pod (possibly empty — a HARDENING_CONFIG entry can supply
    the rest, or the image simply isn't fully configured yet). When the same
    image appears on multiple pods, the first one found wins — real Deployments
    are internally consistent, so this is only a concern for a mid-rollout or
    misconfigured cluster.

    Used to mark which images are eligible for base-image hardening (only ever
    attempted on images the org owns and can test — never third-party images).
    """
    try:
        return _owned_via_client(label_selector)
    except ImportError:
        logger.warning("kubernetes Python client not installed — falling back to kubectl")
        return _owned_via_kubectl(label_selector)


def _owned_via_client(label_selector: str) -> dict[str, dict]:
    from kubernetes import client, config  # noqa: PLC0415

    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces(watch=False, label_selector=label_selector)

    images: dict[str, dict] = {}
    for pod in pods.items:
        cfg = _extract_hardening_annotations(pod.metadata.annotations)
        for c in pod.spec.containers or []:
            if c.image and not _is_digest_only(c.image):
                images.setdefault(c.image, cfg)

    logger.info(f"Discovered {len(images)} owned image(s) matching label selector {label_selector!r}")
    return images


def _owned_via_kubectl(label_selector: str) -> dict[str, dict]:
    result = subprocess.run(
        ["kubectl", "get", "pods", "--all-namespaces", "-l", label_selector, "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"kubectl get pods -l {label_selector} failed:\n{result.stderr}")

    data = json.loads(result.stdout)
    images: dict[str, dict] = {}
    for pod in data.get("items", []):
        cfg = _extract_hardening_annotations(pod.get("metadata", {}).get("annotations"))
        for c in pod.get("spec", {}).get("containers", []):
            img = c.get("image", "")
            if img and not _is_digest_only(img):
                images.setdefault(img, cfg)

    logger.info(f"Discovered {len(images)} owned image(s) matching label selector {label_selector!r} via kubectl")
    return images
