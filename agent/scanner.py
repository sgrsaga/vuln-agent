import subprocess
import json
import logging

logger = logging.getLogger(__name__)


def scan_image(image_ref: str) -> dict:
    """Run Trivy and return the full JSON output."""
    logger.info(f"Scanning {image_ref} with Trivy...")
    result = subprocess.run(
        [
            "trivy", "image",
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            "--exit-code", "0",
            "--quiet",
            image_ref,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"Trivy scan failed:\n{result.stderr}")
    return json.loads(result.stdout)


def extract_vulnerabilities(scan_data: dict) -> list[dict]:
    """Flatten Trivy JSON into a normalised list of CVE dicts."""
    vulns = []
    for result in scan_data.get("Results", []):
        result_type = result.get("Type", "")      # e.g. "alpine", "gobinary"
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            vulns.append({
                "target": target,
                "type": result_type,
                "id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", ""),
                "package": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "title": v.get("Title", ""),
                "description": (v.get("Description") or "")[:300],
            })
    return vulns
