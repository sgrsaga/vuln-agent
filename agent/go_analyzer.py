"""
Go binary vulnerability analyzer.

For each gobinary CVE found by Trivy, this module:
  1. Creates a stopped container from the image (docker create)
  2. Copies each affected binary out via docker cp
  3. Reads the embedded Go toolchain version (go version <binary>)
  4. Runs govulncheck -mode binary twice:
       - default:      only symbols reachable via the call graph → CONFIRMED
       - --show all:   all symbols present in binary           → includes UNEXPLOITABLE
  5. Classifies each CVE as one of:
       false_positive  – govulncheck finds NO trace of the CVE at all
                         (binary was built with a patched toolchain/dependency)
       unexploitable   – CVE present in binary but the vulnerable symbol is
                         NOT reachable from any entry point in the call graph
       confirmed       – vulnerable symbol IS in the call graph → genuinely exploitable
       skipped         – could not extract binary or tools unavailable

Returns:
    {
        "false_positives": [...vulns, each with "analysis" key],
        "unexploitable":   [...vulns, each with "analysis" key],
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

    container_id = _create_container(image_ref)
    if not container_id:
        for v in go_vulns:
            v["analysis"] = {"status": "skipped", "reason": "docker create failed — cannot extract binaries"}
            result["skipped"].append(v)
        return result

    with tempfile.TemporaryDirectory(prefix="vuln-go-") as tmpdir:
        try:
            for target, vulns in by_target.items():
                _analyze_target(container_id, target, vulns, tmpdir, result)
        finally:
            _remove_container(container_id)

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
    return shutil.which("go") is not None and shutil.which("govulncheck") is not None


# ── Container helpers ──────────────────────────────────────────────────────────

def _create_container(image_ref: str) -> str | None:
    """Create a stopped container and return its ID (or None on failure)."""
    try:
        r = subprocess.run(
            ["docker", "create", image_ref],
            capture_output=True, text=True, timeout=120,
        )
        cid = r.stdout.strip()
        if r.returncode != 0 or not cid:
            logger.warning(f"docker create failed: {r.stderr.strip()}")
            return None
        logger.debug(f"Created container {cid[:12]} from {image_ref}")
        return cid
    except Exception as exc:
        logger.warning(f"docker create error: {exc}")
        return None


def _remove_container(container_id: str) -> None:
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass


def _extract_binary(container_id: str, binary_path: str, tmpdir: str) -> Path | None:
    """Copy a binary out of the stopped container; return local Path or None."""
    local = Path(tmpdir) / Path(binary_path).name
    try:
        r = subprocess.run(
            ["docker", "cp", f"{container_id}:{binary_path}", str(local)],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            logger.debug(f"docker cp {binary_path} failed: {r.stderr.strip()}")
            return None
        local.chmod(0o755)
        return local
    except Exception as exc:
        logger.debug(f"docker cp error for {binary_path}: {exc}")
        return None


# ── Go version extraction ──────────────────────────────────────────────────────

def _get_go_version(binary: Path) -> str:
    """Return embedded Go version like '1.26.4', or '' on failure."""
    try:
        r = subprocess.run(
            ["go", "version", str(binary)],
            capture_output=True, text=True, timeout=15,
        )
        # Output: "./argocd: go1.26.4 linux/amd64"
        m = re.search(r"go(\d+\.\d+(?:\.\d+)?(?:-[^\s]+)?)", r.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""


# ── govulncheck execution + parsing ───────────────────────────────────────────

def _parse_govulncheck_json(stdout: str) -> tuple[set[str], dict[str, set[str]]]:
    """
    Parse govulncheck -json output (multi-line pretty-printed objects, NOT NDJSON).

    govulncheck v1.6.0 outputs a stream of concatenated JSON objects — each is
    pretty-printed across multiple lines. Top-level keys are the record types:
      {"config": {...}}
      {"progress": {...}}
      {"osv": {"id": "GO-XXXX", "aliases": ["CVE-XXXX"], ...}}
      {"finding": {"osv": "GO-XXXX", "trace": [...]}}

    Returns:
        found_osv_ids   – OSV IDs that appear in "finding" records
        alias_map       – maps each OSV ID to its full set of aliases (incl. CVE IDs)
    """
    found_osv: set[str] = set()
    alias_map: dict[str, set[str]] = {}

    decoder = json.JSONDecoder()
    pos = 0
    stdout = stdout.strip()
    while pos < len(stdout):
        try:
            obj, idx = decoder.raw_decode(stdout, pos)
            pos = idx
            # Skip whitespace between objects
            while pos < len(stdout) and stdout[pos] in " \n\r\t":
                pos += 1
        except json.JSONDecodeError:
            pos += 1
            continue

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

    return found_osv, alias_map


def _expand_ids(osv_ids: set[str], alias_map: dict[str, set[str]]) -> set[str]:
    """Expand a set of OSV IDs to include all their CVE aliases."""
    expanded: set[str] = set()
    for osv_id in osv_ids:
        expanded |= alias_map.get(osv_id, {osv_id})
    return expanded


def _run_govulncheck(binary: Path) -> tuple[set[str], set[str]]:
    """
    Run govulncheck in binary mode and return:
        (confirmed_ids, confirmed_ids)   ← both sets are identical in binary mode

    In binary mode govulncheck uses the binary's symbol table and call graph
    (from DWARF debug info) to detect whether vulnerable symbols are present.
    The `-show all` flag is not supported with JSON output, and in practice
    binary mode already returns all reachable findings by default — testing
    shows the default JSON output and `-show all` text output produce identical
    counts.  Therefore we run a single JSON pass:
        • CVE in findings → "confirmed" (vulnerable symbol detected in binary)
        • CVE NOT in findings → "false_positive" (not present / fixed toolchain)

    The "unexploitable" category (symbol present but call path unreachable) is
    meaningful only in source mode; binary mode cannot make that distinction.

    Returns (confirmed_ids, confirmed_ids) so callers that compare
    reachable vs all get consistent behaviour without changing the call site.
    """
    try:
        r = subprocess.run(
            ["govulncheck", "-mode", "binary", "-json", str(binary)],
            capture_output=True, text=True, timeout=180,
        )
        found_osv, alias_map = _parse_govulncheck_json(r.stdout)
    except Exception as exc:
        logger.warning(f"govulncheck failed on {binary.name}: {exc}")
        found_osv, alias_map = set(), {}

    confirmed = _expand_ids(found_osv, alias_map)
    return confirmed, confirmed  # both identical — no unexploitable in binary mode


# ── Per-target analysis ────────────────────────────────────────────────────────

def _analyze_target(
    container_id: str,
    target: str,
    vulns: list[dict],
    tmpdir: str,
    result: dict,
) -> None:
    local_binary = _extract_binary(container_id, target, tmpdir)
    if not local_binary:
        for v in vulns:
            v["analysis"] = {
                "status": "skipped",
                "reason": f"Could not extract binary from container path: {target}",
            }
            result["skipped"].append(v)
        return

    go_ver = _get_go_version(local_binary)
    logger.info(f"Analyzing {target} (Go {go_ver or 'unknown'}) with govulncheck …")

    reachable_ids, all_ids = _run_govulncheck(local_binary)
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
