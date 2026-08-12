# ── Stage 1: Python dependencies ────────────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim

# Install Trivy (vulnerability scanner) and Docker CLI (to build/push images).
# The Docker *daemon* is NOT included — mount the host socket at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && \
    # Trivy
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin latest \
    && \
    # Docker CLI only (no daemon)
    install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Go toolchain for `go version` (embedded version detection) and govulncheck
# (call-graph analysis of Go binaries to distinguish false positives from real CVEs).
# Using a build arg so the version can be pinned at image build time.
ARG GOVERSION=1.24.4
ENV GOPATH=/go
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
RUN curl -fsSL "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz \
    && go install golang.org/x/vuln/cmd/govulncheck@latest \
    # Remove source cache but keep the compiled govulncheck binary
    && rm -rf /go/pkg /root/.cache/go-build \
    # Make /go/bin readable by all users (agent runs as non-root)
    && chmod -R 755 /go/bin

# Copy pre-built Python packages from deps stage
COPY --from=deps /install /usr/local

# Copy application source
WORKDIR /app
COPY agent/ ./agent/
COPY main.py .

# Output artifacts land here; mount a PVC/volume to persist across pod restarts
VOLUME ["/app/output"]

# Trivy DB cache — mount a PVC to avoid re-downloading on every run
ENV TRIVY_CACHE_DIR=/app/.trivy-cache
VOLUME ["/app/.trivy-cache"]

# Non-root user for safety (docker socket access requires supplemental group)
RUN groupadd -r agent && useradd -r -g agent -G root agent \
    && chown -R agent:agent /app
USER agent

ENTRYPOINT ["python", "main.py"]
# Pass the target image as the container argument:
#   docker run ... vuln-agent ghcr.io/dexidp/dex:v2.45.1
