"""
Builds the OS/package-upgrade patch Dockerfile deterministically — no LLM call.

Trivy already reports the exact package manager (`type`) and fixed version for
each fixable CVE, and the correct fix is always the same well-known idiom for
that package manager (a blanket upgrade). There's no ambiguity here for a model
to resolve, and a template can't violate the one hard constraint (`FROM
{current_image}` as the first line) the way free-form generation theoretically
could — so this stays a lookup table + a real `crane config` read for the
image's actual USER, rather than an LLM guessing at it from general knowledge.
"""

import json
import logging
import subprocess

logger = logging.getLogger(__name__)

# Mirrors the `type` values Trivy reports for OS/distro package results.
_UPGRADE_COMMANDS = {
    "alpine": "apk upgrade --no-cache",
    "debian": "apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
    "ubuntu": "apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
    "redhat": "yum update -y && yum clean all",
    "centos": "yum update -y && yum clean all",
}


def _image_user(image_ref: str) -> str:
    """
    Return the image's configured USER via `crane config` (empty string means
    root/default). Used so USER root/<original> bracketing reflects the image's
    actual configuration instead of being guessed.
    """
    try:
        result = subprocess.run(
            ["crane", "config", image_ref],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return ""
        config = json.loads(result.stdout)
        return (config.get("config") or {}).get("User", "") or ""
    except Exception as exc:
        logger.debug(f"crane config failed for {image_ref}: {exc}")
        return ""


def upgrade_lines(image_ref: str, families: list[str]) -> list[str]:
    """
    The USER/RUN Dockerfile lines that blanket-upgrade OS packages for the given
    package-manager families, bracketed with USER root/<original> when image_ref's
    actual config runs as non-root. Shared by generate_patch() (image-layer patch
    for external images) and hardener's OS-patch rung (source-level patch for
    internal images) — one source of truth for the upgrade idiom per family.
    """
    commands = [_UPGRADE_COMMANDS[f] for f in families if f in _UPGRADE_COMMANDS]
    if not commands:
        return []

    user = _image_user(image_ref)
    needs_root = bool(user) and user not in ("root", "0")

    lines = []
    if needs_root:
        lines.append("USER root")
    lines.extend(f"RUN {cmd}" for cmd in commands)
    if needs_root:
        lines.append(f"USER {user}")
    return lines


def generate_patch(
    current_image: str,
    iteration: int,
    vulnerabilities: list[dict],
) -> str | None:
    """
    Build a Dockerfile that upgrades OS/distro packages to their fixed versions.

    Returns:
        Dockerfile string — a valid patch to apply
        None             — no OS-fixable vulnerabilities remain; nothing more
                            can be done at the image layer (the old
                            CANNOT_PATCH_FURTHER outcome)
    """
    os_fixable = [
        v for v in vulnerabilities
        if v["type"] in _UPGRADE_COMMANDS and v.get("fixed")
    ]
    if not os_fixable:
        logger.info("No OS-fixable vulnerabilities remain — nothing further to patch")
        return None

    types_present = sorted({v["type"] for v in os_fixable})
    lines = [f"FROM {current_image}"] + upgrade_lines(current_image, types_present)

    logger.info(
        f"Generated patch Dockerfile (iteration {iteration}, "
        f"package manager(s): {', '.join(types_present)})"
    )
    return "\n".join(lines)
