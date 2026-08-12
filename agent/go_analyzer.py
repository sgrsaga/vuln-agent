"""
Go binary vulnerability analyzer.

For each gobinary CVE found by Trivy, this module:
  1. Creates a stopped container from the image (docker create)
  2. Copies each affected binary out via docker cp
  3. Runs govulncheck -mode binary -json; parses the SBOM record for Go version
  4. Classifies each CVE as one of:
       false_positive  – govulncheck finds NO trace of the CVE at all
                         (binary was built with a patched toolchain/dependency)
       confirmed       – vulnerable symbol IS present in the binary
       skipped         – could not extract binary or govulncheck unavailable

Note: "unexploitable" (symbol present but call path unreachable) is only
meaningful in source mode; binary mode treats all findings as confirmed.

Returns:
    {
        "false_positives": [...vulns, each with "analysis" key],
        "unexploitable":   [],
        "confirmed":       [...vulns, each with "analysis" key],
        "skipped":         [...vulns, each with "analysis" key],
    }
"""

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Public API ─────────────────────────────────────────────────────────────────

def analyze_go_vulns(image_ref: str, go_vulns: list[dict]) -> dict:
    """Classify Go binary CVEs via govulncheck call-graph analysis."""
    result: dict = {"false_positives": [], "unexploitable": [], "confirmed": [], "skipped": []}
    if not go_vulns:
        return result

    if not _tools_available():
        logger.warning("go / govulncheck not found in PATH — skipping Go binary analysis")
        for v in go_vulns:
            v["analysis"] = {"status": "skipped", "reason": "go/govulncheck not installed in agent image"}
            result["skipped"].append(v)
        return result

    # Group CVEs by the binary path they live in
    by_target: dict[str, list[dict]] = {}
    for v in go_vulns:
        by_target.setdefault(v.get("target", ""), []).append(v)

    with tempfile.TemporaryDirectory(prefix="vuln-go-") as tmpdir:
        for target, vulns in by_target.items():
            _analyze_target(image_ref, target, vulns, tmpdir, result)

    fp = len(result["false_positives"])
    un = len(result["unexploitable"])
    co = len(result["confirmed"])
    sk = len(result["skipped"])
    logger.info(
        f"Go analysis complete: {fp} false positive(s), {un} unexploitable, "
        f"{co} confirmed, {sk} skipped"
    )
    return result


def summary_line(go_analysis: dict) -> str:
    """One-line summary suitable for a publish_event message."""
    parts = []
    for key, label in (
        ("false_positives", "false positive(s)"),
        ("unexploitable", "unexploitable"),
        ("confirmed", "confirmed"),
        ("skipped", "skipped"),
    ):
        n = len(go_analysis.get(key, []))
        if n:
            parts.append(f"{n} {label}")
    return ", ".join(parts) or "none"


# ── Tool availability ──────────────────────────────────────────────────────────

def _tools_available() -> bool:
    return shutil.which("govulncheck") is not None


# ── Binary extraction via crane (no Docker daemon required) ───────────────────

def _extract_binary(image_ref: str, binary_path: str, tmpdir: str) -> Path | None:
    """
    Extract a single binary from an OCI image using crane export.

    crane pulls the merged image filesystem as a tar stream without needing a
    Docker daemon — it speaks directly to the OCI registry. The tar is piped
    to `tar -xOf - <path>` which writes only the requested file to stdout.

    binary_path must be an absolute path inside the image (e.g. /usr/bin/argocd).
    """
    local = Path(tmpdir) / Path(binary_path).name
    path_in_tar = binary_path.lstrip("/")
    try:
        crane_proc = subprocess.Popen(
            ["crane", "export", image_ref, "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with open(local, "wb") as out_fh:
            tar_proc = subprocess.run(
                ["tar", "-xOf", "-", path_in_tar],
                stdin=crane_proc.stdout,
                stdout=out_fh,
                stderr=subprocess.PIPE,
                timeout=300,
            )
        crane_proc.stdout.close()
        crane_proc.wait(timeout=10)

        if tar_proc.returncode != 0 or not local.exists() or local.stat().st_size == 0:
            logger.debug(
                f"crane/tar extraction failed for {binary_path}: "
                f"tar rc={tar_proc.returncode}, "
                f"crane stderr={crane_proc.stderr.read(200) if crane_proc.stderr else ''}"
            )
            return None
        local.chmod(0o755)
        return local
    except Exception as exc:
        logger.debug(f"crane extraction error for {binary_path}: {exc}")
        return None


# ── govulncheck execution + parsing ───────────────────────────────────────────

def _parse_govulncheck_json(stdout: str) -> tuple[set[str], dict[str, set[str]], str]:
    """
    Parse govulncheck -json output (multi-line pretty-printed objects, NOT NDJSON).

    govulncheck v1.6.0 outputs a stream of concatenated JSON objects:
      {"config": {...}}
      {"progress": {...}}
      {"SBOM": {"go_version": "go1.26.4", "modules": [...]}}
      {"osv": {"id": "GO-XXXX", "aliases": ["CVE-XXXX"], ...}}
      {"finding": {"osv": "GO-XXXX", "trace": [...]}}

    Returns:
        found_osv_ids  – OSV IDs that appear in "finding" records
        alias_map      – maps each OSV ID to its full set of aliases (CVE IDs included)
        go_version     – embedded Go toolchain version from the SBOM record (e.g. "1.26.4")
    """
    found_osv: set[str] = set()
    alias_map: dict[str, set[str]] = {}
    go_version: str = ""

    decoder = json.JSONDecoder()
    pos = 0
    stdout = stdout.strip()
    while pos < len(stdout):
        try:
            obj, idx = decoder.raw_decode(stdout, pos)
            pos = idx
            while pos < len(stdout) and stdout[pos] in " \n\r\t":
                pos += 1
        except json.JSONDecodeError:
            pos += 1
            continue

        # SBOM record: contains the embedded Go toolchain version
        sbom = obj.get("SBOM")
        if isinstance(sbom, dict) and not go_version:
            raw_ver = sbom.get("go_version", "")
            m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:-[^\s]+)?)", raw_ver)
            if m:
                go_version = m.group(1)

        # OSV record: canonical vulnerability definition with aliases
        osv_rec = obj.get("osv")
        if isinstance(osv_rec, dict):
            osv_id = osv_rec.get("id", "")
            aliases: set[str] = set(osv_rec.get("aliases", []))
            alias_map[osv_id] = aliases | {osv_id}

        # Finding record: govulncheck detected this vulnerability in the binary
        finding = obj.get("finding")
        if isinstance(finding, dict):
            osv_id = finding.get("osv", "")
            if osv_id:
                found_osv.add(osv_id)

    return found_osv, alias_map, go_version


def _expand_ids(osv_ids: set[str], alias_map: dict[str, set[str]]) -> set[str]:
    """Expand a set of OSV IDs to include all their CVE aliases."""
    expanded: set[str] = set()
    for osv_id in osv_ids:
        expanded |= alias_map.get(osv_id, {osv_id})
    return expanded


def _run_govulncheck(binary: Path) -> tuple[set[str], set[str], str]:
    """
    Run govulncheck in binary mode and return:
        (confirmed_ids, confirmed_ids, go_version)

    go_version comes from the SBOM JSON record emitted by govulncheck itself,
    so no separate `go version <binary>` call is needed at runtime.

    In binary mode govulncheck detects whether vulnerable symbols are present.
    There is no "unexploitable" distinction — any detected CVE is "confirmed".
    """
    try:
        r = subprocess.run(
            ["govulncheck", "-mode", "binary", "-json", str(binary)],
            capture_output=True, text=True, timeout=180,
        )
        found_osv, alias_map, go_version = _parse_govulncheck_json(r.stdout)
    except Exception as exc:
        logger.warning(f"govulncheck failed on {binary.name}: {exc}")
        found_osv, alias_map, go_version = set(), {}, ""

    confirmed = _expand_ids(found_osv, alias_map)
    return confirmed, confirmed, go_version


# ── Per-target analysis ────────────────────────────────────────────────────────

def _analyze_target(
    image_ref: str,
    target: str,
    vulns: list[dict],
    tmpdir: str,
    result: dict,
) -> None:
    local_binary = _extract_binary(image_ref, target, tmpdir)
    if not local_binary:
        for v in vulns:
            v["analysis"] = {
                "status": "skipped",
                "reason": f"crane: could not extract {target} from {image_ref}",
            }
            result["skipped"].append(v)
        return

    reachable_ids, all_ids, go_ver = _run_govulncheck(local_binary)
    logger.info(f"Analyzing {target} (Go {go_ver or 'unknown'}) with govulncheck …")
    logger.debug(
        f"{target}: govulncheck reachable={len(reachable_ids)}, present={len(all_ids)}"
    )

    for v in vulns:
        cve_id = v.get("id", "")
        ver_tag = f"Go {go_ver}" if go_ver else "unknown Go version"

        if cve_id not in all_ids:
            # govulncheck found no trace of this CVE in the binary.
            # The binary was built with a toolchain or dependency version that
            # already contains the fix — Trivy version-range matching is a false
            # positive here.
            v["analysis"] = {
                "status": "false_positive",
                "go_version": go_ver,
                "reason": (
                    f"govulncheck: {cve_id} not detected in binary ({ver_tag}). "
                    "Binary was compiled with a fixed toolchain/dependency. "
                    "Suppress this finding in your scanner policy."
                ),
            }
            result["false_positives"].append(v)

        else:
            # govulncheck found the vulnerable symbol in the binary's call graph.
            # In binary mode there is no 'unexploitable' distinction — any detected
            # symbol is treated as confirmed present and potentially exploitable.
            v["analysis"] = {
                "status": "confirmed",
                "go_version": go_ver,
                "reason": (
                    f"govulncheck: {cve_id} CONFIRMED — vulnerable symbol detected "
                    f"in binary ({ver_tag}). "
                    "Requires source rebuild with patched Go toolchain or dependency. "
                    "Cannot be fixed at the image layer."
                ),
            }
            result["confirmed"].append(v)
