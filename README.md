# vuln-agent

An agentic pipeline that automatically scans a Docker image for vulnerabilities, generates a detailed security report using Claude AI, applies iterative patches, and pushes improved images to a private container registry — continuing until no further improvement is possible.

## How it works

```
Input image
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Remediation Loop                           │
│                                                                 │
│  Trivy scan ──► Save scan JSON ──► Claude Opus 4.8 report      │
│       ▲                 │                    │                  │
│       │            GitHub Release        GitHub Release         │
│       │                                                         │
│  Rescan new image ◄── docker push ◄── docker build             │
│       │                   │                 ▲                   │
│       │               Private registry  Claude Opus 4.8        │
│       │                                  Dockerfile patch       │
│       │                                                         │
│  Improvement? ──No──► Stop (best effort reached)               │
│       │                                                         │
│      Yes ────────────────────────────────────────────────────► │
└─────────────────────────────────────────────────────────────────┘
```

**Loop termination — first condition wins:**

| Condition | Status |
|-----------|--------|
| Zero HIGH/CRITICAL CVEs remain | `clean` |
| All remaining CVEs require source rebuild (Go binaries, no upstream fix) | `no_further_patches` |
| Patch applied but CVE count did not decrease | `no_improvement` |
| `MAX_ITERATIONS` reached (default: 5) | `max_iterations` |

**Output artifacts per run:**

| Artifact | Description |
|----------|-------------|
| `output/scan-iter-N.json` | Full Trivy JSON output for each scan |
| `output/report-iter-N.md` | Claude Opus 4.8 security analysis and remediation report |
| `output/dockerfile-iter-N` | The patch Dockerfile applied in each iteration |
| GitHub Release | All files above attached as downloadable release assets |
| Patched image | Pushed to your registry as `<name>:<tag>-patched-iterN` |

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.12+ | Runtime | [python.org](https://www.python.org/downloads/) |
| Trivy | Vulnerability scanning | [trivy.dev](https://trivy.dev/latest/getting-started/installation/) |
| Docker CLI | Build and push patched images | [docs.docker.com](https://docs.docker.com/engine/install/) |
| Anthropic API key | Claude Opus 4.8 (report + patch generation) | [console.anthropic.com](https://console.anthropic.com/) |
| GitHub PAT | Create releases, push artifacts | Scopes: `repo` + `write:packages` |

---

## Running locally

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/sgrsaga/vuln-agent.git
cd vuln-agent

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Install Trivy

```bash
# Linux / macOS
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin latest

# macOS (Homebrew)
brew install trivy
```

### 3. Configure environment variables

```bash
cp .env.example .env
# Edit .env with your values
```

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key (`sk-ant-...`) |
| `GHCR_NAMESPACE` | No | Registry prefix for pushed images, e.g. `ghcr.io/myorg`. Leave empty to build locally only |
| `GITHUB_TOKEN` | No | GitHub PAT (`ghp_...`) with `repo` + `write:packages` scopes. Enables GitHub Release creation |
| `GITHUB_REPO` | No | `owner/repo` or full GitHub URL. Required for release creation |
| `MAX_ITERATIONS` | No | Safety cap on remediation loops (default: `5`) |
| `OUTPUT_DIR` | No | Directory for artifacts (default: `output`) |

### 4. Log in to your private registry

```bash
# GitHub Container Registry
echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Any other registry (AWS ECR, GCP Artifact Registry, Docker Hub, etc.)
docker login your.registry.io
```

### 5. Pre-warm Trivy (first run only)

On the first run Trivy downloads its vulnerability database (~600 MB). Pre-download it once to avoid a timeout during the scan:

```bash
trivy image --download-db-only
```

### 6. Run the agent

```bash
source .venv/bin/activate

python main.py ghcr.io/dexidp/dex:v2.45.1
```

Or with explicit flags:

```bash
python main.py ghcr.io/your-org/your-image:tag \
  --max-iterations 3 \
  --output-dir /tmp/scan-results
```

### 7. View results

Artifacts are written to `output/` in real time. If `GITHUB_TOKEN` and `GITHUB_REPO` are configured, a GitHub Release is created at the end of every run with all files attached.

```
output/
├── scan-iter-1.json       ← full Trivy scan (63 KB)
├── report-iter-1.md       ← Claude security report (12–15 KB)
├── dockerfile-iter-1      ← applied patch Dockerfile
├── scan-iter-2.json
└── report-iter-2.md
```

Example output for `ghcr.io/dexidp/dex:v2.45.1`:

```
🚀  [pipeline_start] Starting remediation for ghcr.io/dexidp/dex:v2.45.1
🔍  [scan_complete] Found 104 vulnerabilities (CRITICAL: 11, HIGH: 93)
📋  [report_complete] Report saved → output/report-iter-1.md
🔧  [patch_generated] Dockerfile saved → output/dockerfile-iter-1 (4 lines)
🏗️  [build_complete] Built and pushed: ghcr.io/sgrsaga/dex:v2.45.1-patched-iter1
✅  [improvement] Reduced by 15: 104 → 89 CVEs
🔍  [scan_complete] Found 89 vulnerabilities (CRITICAL: 9, HIGH: 80)
🏁  [pipeline_complete] No further patches possible — remaining CVEs require source rebuild
```

---

## Running in a Kubernetes cluster

The agent runs as a Kubernetes **Job** (one-shot on demand) or **CronJob** (automated schedule). It mounts the node's Docker socket to build and push images without needing a Docker daemon inside the pod.

### Cluster architecture

```
┌────────────────────────────────────────────────────────┐
│  Kubernetes namespace: security                        │
│                                                        │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Job / CronJob pod                              │  │
│  │                                                 │  │
│  │  [init] trivy --download-db-only               │  │
│  │                                                 │  │
│  │  [main] vuln-agent                             │  │
│  │    ├── Trivy scan          (local process)      │  │
│  │    ├── Claude API calls    (HTTPS outbound)     │  │
│  │    ├── docker build        (via host socket)    │  │
│  │    └── docker push         (HTTPS outbound) ───┼──┼──► Private registry
│  │                                                 │  │    (GHCR / ECR / GCR / ACR)
│  │  Volumes:                                       │  │
│  │    /var/run/docker.sock   ← hostPath            │  │
│  │    /root/.docker/config   ← registry secret     │  │
│  │    /app/output            ← PVC (artifacts)      │  │
│  │    /trivy-cache           ← PVC (Trivy DB)       │  │
│  └─────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
          │
          └──► GitHub Releases API (artifacts uploaded at end of run)
```

### Step 1 — Build and push the agent image

```bash
# Build
docker build -t ghcr.io/your-org/vuln-agent:latest .

# Push to your registry
docker push ghcr.io/your-org/vuln-agent:latest
```

### Step 2 — Create namespace and persistent storage

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
```

Two PVCs are created:
- `vuln-agent-output` (1 Gi) — scan JSON, reports, Dockerfiles
- `vuln-agent-trivy-cache` (2 Gi) — Trivy vulnerability DB (avoids re-downloading on every run)

### Step 3 — Create secrets

```bash
# Anthropic API key + GitHub token
kubectl -n security create secret generic vuln-agent-secrets \
  --from-literal=anthropic-api-key=sk-ant-... \
  --from-literal=github-token=ghp_...

# Registry credentials so the agent can push patched images
kubectl -n security create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=ghp_...
```

For other registries replace `--docker-server` with your registry hostname (e.g. `123456789.dkr.ecr.us-east-1.amazonaws.com`).

### Step 4 — Configure the manifests

Edit `k8s/job.yaml` (and `k8s/cronjob.yaml` if using scheduled scans). The key fields to change:

```yaml
# --- k8s/job.yaml ---

containers:
  - name: vuln-agent
    # ① Your agent image (built in Step 1)
    image: ghcr.io/your-org/vuln-agent:latest

    # ② The target image to scan
    args: ["ghcr.io/your-org/your-image:your-tag"]

    env:
      # ③ Where to push patched images
      - name: GHCR_NAMESPACE
        value: "ghcr.io/your-org"             # or your.registry.io/your-org

      # ④ Where to publish GitHub Release artifacts
      - name: GITHUB_REPO
        value: "your-org/your-repo"

      # ⑤ Max iterations (optional)
      - name: MAX_ITERATIONS
        value: "5"
```

### Step 5 — Run a one-shot Job

```bash
kubectl apply -f k8s/job.yaml

# Stream live logs
kubectl -n security logs -f job/vuln-remediate-dex

# Check completion status
kubectl -n security get job vuln-remediate-dex
```

### Step 6 — Schedule automatic scans (CronJob)

```bash
kubectl apply -f k8s/cronjob.yaml
```

The default schedule is **every Monday at 04:00 UTC**. To change it, edit `spec.schedule` in `k8s/cronjob.yaml` using standard cron syntax:

```yaml
schedule: "0 4 * * 1"   # Mon 04:00 UTC
schedule: "0 2 * * *"   # Every day at 02:00 UTC
schedule: "0 0 1 * *"   # First day of every month
```

Trigger a scan immediately without waiting for the schedule:

```bash
kubectl -n security create job vuln-scan-manual \
  --from=cronjob/vuln-agent-scan
```

List all runs and their status:

```bash
kubectl -n security get jobs -l app=vuln-agent
```

### Retrieve artifacts from the cluster

If `GITHUB_TOKEN` and `GITHUB_REPO` are set, all artifacts are automatically uploaded to a GitHub Release — no manual retrieval needed. The release URL is printed in the pod logs.

To access artifacts stored on the PVC directly:

```bash
kubectl -n security run artifact-reader --rm -it \
  --image=busybox \
  --overrides='{
    "spec": {
      "volumes": [{"name":"out","persistentVolumeClaim":{"claimName":"vuln-agent-output"}}],
      "containers": [{
        "name":"reader","image":"busybox","command":["sh"],
        "volumeMounts":[{"name":"out","mountPath":"/output"}]
      }]
    }
  }'

# Inside the shell:
ls -lh /output
cat /output/report-iter-1.md
```

---

## What gets fixed automatically — and what does not

### Fixed automatically (OS / distro packages)

When Alpine, Debian, or Ubuntu packages have a newer version available:

```dockerfile
FROM your-image:tag
USER root
RUN apk upgrade --no-cache      # Alpine
# or: RUN apt-get update && apt-get upgrade -y    # Debian/Ubuntu
USER original-user
```

### Cannot be fixed at the image layer (requires source rebuild)

**Go binary CVEs** — the vulnerable code is statically compiled into the binary. No package manager can update it. Fixing requires:

1. Bumping Go module dependencies in the source repository
2. Rebuilding the binary with an updated Go toolchain
3. Releasing a new upstream image version

The agent identifies these, documents them clearly in the report, and stops iterating rather than applying ineffective patches. The report includes the exact `go get` commands needed for a source-level fix.

---

## Security considerations for production

The Job manifests mount `/var/run/docker.sock` from the host node, which gives root-equivalent access to the Docker daemon. For production deployments:

- **Dedicated nodes** — use a `nodeSelector` or taint/toleration to confine socket-mounting pods to designated build nodes
- **Namespace policy** — use OPA Gatekeeper or Kyverno to restrict `hostPath` mounts to the `security` namespace only
- **Rootless builds** — replace the Docker socket with **[Kaniko](https://github.com/GoogleContainerTools/kaniko)** for fully rootless in-cluster image builds (no socket mount required)
- **Secret rotation** — rotate `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` regularly; use External Secrets Operator, HashiCorp Vault, or your cloud provider's secret manager to inject them rather than storing them in Kubernetes Secrets directly

---

## Project structure

```
vuln-agent/
├── agent/
│   ├── scanner.py        # Trivy wrapper — runs scan, parses JSON
│   ├── reporter.py       # Claude Opus 4.8 — generates Markdown security report
│   ├── patcher.py        # Claude Opus 4.8 — generates patch Dockerfile
│   ├── builder.py        # docker build + docker push to private registry
│   ├── publisher.py      # Writes artifacts to disk; creates GitHub Release via REST API
│   └── orchestrator.py   # Main remediation loop and termination logic
├── k8s/
│   ├── namespace.yaml    # security namespace
│   ├── pvc.yaml          # output + Trivy cache PersistentVolumeClaims
│   ├── secrets.yaml      # Secret templates (fill in values or use kubectl create)
│   ├── job.yaml          # One-shot remediation Job
│   └── cronjob.yaml      # Scheduled weekly scan CronJob
├── .github/
│   └── workflows/
│       └── vuln-remediate.yml  # GitHub Actions workflow (manual trigger)
├── Dockerfile            # Agent container image
├── .dockerignore
├── main.py               # CLI entry point
├── requirements.txt
└── .env.example
```
