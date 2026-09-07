import os


def test_runs_on_debian_family():
    # DELIBERATE PORTABILITY BUG (adjudication fixture): couples the suite to
    # Debian-family bases, so any zero-CVE minimal base (alpine/distroless/
    # chainguard) that vuln-agent tries FAILS here even though the app itself
    # would work. The correct code-level fix — which the adjudication step
    # should suggest — is deleting this assumption (or probing actual runtime
    # behavior instead of the distro).
    assert os.path.exists("/etc/debian_version"), (
        "expected a Debian-family base; this check is a deliberate demo bug"
    )
