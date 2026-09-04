"""
Deterministic application-dependency upgrades for INTERNAL images only, driven
entirely by Trivy's own findings — each fixable vuln already carries the exact
package name and fixed version, so choosing what to bump needs no judgment
(and therefore no LLM). Only *applying* the bump differs per ecosystem.

Called from hardener's dependency loop after the base-image ladder: apply every
fixable bump at once (same blanket philosophy as the OS patch), then the caller
rebuilds, runs the app's real test suite, and rescans — an upgrade only sticks
if all of that passes and vulnerabilities actually went down.

Manifest edits are done as text/JSON/XML edits in the cloned repo rather than by
running ecosystem tooling in the agent (the agent image has no node/go/mvn — and
for npm specifically, editing package.json instead of running `npm install`
avoids executing package lifecycle scripts entirely; the app's own Dockerfile
build resolves lockfiles). The one exception is Go: after editing go.mod,
`go mod tidy` must run to fix go.sum, executed inside a container of the app's
own base image (which has the toolchain by construction) — network ON for module
download, acceptable because the command is ours, not repo-controlled (tests, by
contrast, stay --network none).
"""

import json
import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# Trivy image-scan result `type` values → ecosystem handler key.
_ECOSYSTEM_BY_TYPE = {
    "python-pkg": "python",
    "pip": "python",
    "node-pkg": "node",
    "npm": "node",
    "yarn": "node",
    "gobinary": "go",
    "gomod": "go",
    "jar": "maven",
    "pom": "maven",
}


def _fixable(vulns: list[dict]) -> dict[str, dict[str, str]]:
    """{ecosystem: {package: highest_fixed_version}} for app-level fixable vulns."""
    by_eco: dict[str, dict[str, str]] = {}
    for v in vulns:
        eco = _ECOSYSTEM_BY_TYPE.get(v.get("type", ""))
        if not eco or not v.get("fixed") or not v.get("package"):
            continue
        if eco == "go" and v["package"] == "stdlib":
            continue  # Go toolchain-level — the base ladder's job, not a go.mod bump
        # Trivy may list several fixed versions ("1.2.3, 2.0.1"); take the first.
        fixed = v["fixed"].split(",")[0].strip()
        by_eco.setdefault(eco, {})[v["package"]] = fixed
    return by_eco


# ── Python: requirements.txt ──────────────────────────────────────────────────

def _bump_requirements(repo_dir: str, bumps: dict[str, str]) -> list[str]:
    path = os.path.join(repo_dir, "requirements.txt")
    if not os.path.exists(path):
        logger.info("No requirements.txt found — skipping python bumps")
        return []
    with open(path) as fh:
        lines = fh.readlines()

    applied = []
    present: set[str] = set()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*[=<>~!]", line)
        if not m:
            continue
        pkg = m.group(1)
        for name, fixed in bumps.items():
            if pkg.lower() == name.lower():
                present.add(name)
                lines[i] = f"{pkg}=={fixed}\n"
                applied.append(f"{name}=={fixed}")
    # Transitives not listed: append a top-level pin — pip treats requirements
    # entries as authoritative, overriding transitive resolution.
    for name, fixed in bumps.items():
        if name not in present:
            lines.append(f"{name}=={fixed}\n")
            applied.append(f"{name}=={fixed} (appended, transitive)")

    with open(path, "w") as fh:
        fh.writelines(lines)
    return applied


# ── Node: package.json ────────────────────────────────────────────────────────

def _bump_package_json(repo_dir: str, bumps: dict[str, str]) -> list[str]:
    path = os.path.join(repo_dir, "package.json")
    if not os.path.exists(path):
        logger.info("No package.json found — skipping node bumps")
        return []
    with open(path) as fh:
        pkg = json.load(fh)

    applied = []
    for name, fixed in bumps.items():
        placed = False
        for section in ("dependencies", "devDependencies"):
            if name in pkg.get(section, {}):
                pkg[section][name] = fixed
                applied.append(f"{name}@{fixed}")
                placed = True
        if not placed:
            # Transitive — force it via npm's overrides field.
            pkg.setdefault("overrides", {})[name] = fixed
            applied.append(f"{name}@{fixed} (overrides, transitive)")

    with open(path, "w") as fh:
        json.dump(pkg, fh, indent=2)
        fh.write("\n")
    return applied


# ── Go: go.mod (+ go mod tidy in the app's own base image) ───────────────────

def _bump_go_mod(repo_dir: str, bumps: dict[str, str], base_ref: str) -> list[str]:
    path = os.path.join(repo_dir, "go.mod")
    if not os.path.exists(path):
        logger.info("No go.mod found — skipping go bumps")
        return []
    with open(path) as fh:
        content = fh.read()

    applied = []
    for name, fixed in bumps.items():
        version = fixed if fixed.startswith("v") else f"v{fixed}"
        pattern = re.compile(rf"^(\s*{re.escape(name)}\s+)v\S+", re.MULTILINE)
        if pattern.search(content):
            content = pattern.sub(rf"\g<1>{version}", content)
            applied.append(f"{name}@{version}")
        else:
            # Transitive: add an explicit require — go respects it after tidy.
            content = content.rstrip("\n") + f"\nrequire {name} {version}\n"
            applied.append(f"{name}@{version} (added require, transitive)")

    if not applied:
        return []
    with open(path, "w") as fh:
        fh.write(content)

    # go.sum must be reconciled — run tidy inside the app's own base image
    # (the agent has no Go toolchain; the base does, by construction).
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{repo_dir}:/w", "-w", "/w", base_ref,
         "go", "mod", "tidy"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        logger.warning(f"go mod tidy failed (bumps kept, build may fail): {result.stderr[-500:]}")
    return applied


# ── Maven: pom.xml (direct dependencies only) ────────────────────────────────

def _bump_pom(repo_dir: str, bumps: dict[str, str]) -> list[str]:
    path = os.path.join(repo_dir, "pom.xml")
    if not os.path.exists(path):
        logger.info("No pom.xml found — skipping maven bumps")
        return []
    with open(path) as fh:
        content = fh.read()

    applied = []
    for name, fixed in bumps.items():
        # Trivy reports maven packages as group:artifact — match on the artifactId.
        artifact = name.split(":")[-1]
        pattern = re.compile(
            rf"(<artifactId>{re.escape(artifact)}</artifactId>\s*<version>)([^<$]+)(</version>)",
        )
        new_content, n = pattern.subn(rf"\g<1>{fixed}\g<3>", content)
        if n:
            content = new_content
            applied.append(f"{artifact}:{fixed}")
        else:
            # Property-indirected (<version>${x.version}</version>) or transitive —
            # fragile XML surgery, deliberately skipped in v1.
            logger.info(f"pom.xml: could not bump {name} (property-indirected or transitive) — skipped")

    if applied:
        with open(path, "w") as fh:
            fh.write(content)
    return applied


def apply(repo_dir: str, vulns: list[dict], base_ref: str) -> list[str]:
    """
    Apply every fixable app-dependency bump Trivy identified, across all
    ecosystems at once. Returns the list of applied bumps ([] = nothing to do —
    the caller must not rebuild for nothing).
    """
    by_eco = _fixable(vulns)
    if not by_eco:
        return []

    applied: list[str] = []
    if "python" in by_eco:
        applied += _bump_requirements(repo_dir, by_eco["python"])
    if "node" in by_eco:
        applied += _bump_package_json(repo_dir, by_eco["node"])
    if "go" in by_eco:
        applied += _bump_go_mod(repo_dir, by_eco["go"], base_ref)
    if "maven" in by_eco:
        applied += _bump_pom(repo_dir, by_eco["maven"])

    if applied:
        logger.info(f"Applied dependency bumps: {', '.join(applied)}")
    return applied
