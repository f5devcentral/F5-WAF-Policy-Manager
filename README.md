# F5 WAF for NGINX — Policy & Logging Profile Manager

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Redis](https://img.shields.io/badge/Redis-5.0+-DC382D?logo=redis&logoColor=white)](https://redis.io)
[![F5 WAF for NGINX](https://img.shields.io/badge/F5%20WAF%20for%20NGINX-Security-009639?logo=nginx&logoColor=white)](https://docs.nginx.com/waf/policies/configuration/)
[![Tests](https://img.shields.io/badge/Tests-188%20passed-brightgreen?logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm%20Chart-326CE5?logo=kubernetes&logoColor=white)](helm/f5-waf-policy-manager)

A modern, declarative DevSecOps web interface and REST management engine for **F5 WAF for NGINX** security policies, logging profiles, and user-defined custom signatures (Snort syntax).

Backed by a high-performance **Redis** key-value store with automatic in-memory fallback, and an integrated **F5 WAF Compiler (`apcompile`)** service to validate and test binary policy bundle compilation directly within the UI.

<p align="center">
  <img src="docs/screenshots/01_waf_policies_dashboard.png" alt="F5 WAF for NGINX Policy Manager Dashboard" width="100%">
</p>

> [!TIP]
> **New to F5 WAF Policy Manager?** Check out the [📖 Complete Step-by-Step Visual Walkthrough](docs/walkthrough.md) for in-depth guidance with real interface walkthroughs!

---

## 📸 Visual Walkthrough & Interface Tour

The interface provides an end-to-end declarative DevSecOps workflow from policy design to binary compilation and GitOps version control:

| View | Preview | Highlights |
| :--- | :--- | :--- |
| **WAF Policies Dashboard** | [![WAF Policies Dashboard](docs/screenshots/01_waf_policies_dashboard.png)](docs/walkthrough.md#1-waf-policies-dashboard--quick-deploy-templates) | Single-pane management with real-time telemetry, quick-deploy production templates, and GitOps state tracking (`● synced` / `● draft`). |
| **Visual Form Builder** | [![Visual Form Builder](docs/screenshots/02_policy_visual_builder_technologies.png)](docs/walkthrough.md#2-visual-form-builder--server-technologies-targeting) | Interactive visual builder with server technologies quick stacks, dual-mode CodeMirror JSON synchronization, and diff inspector. |
| **Logging Profiles** | [![Logging Profiles](docs/screenshots/03_logging_profiles_dashboard.png)](docs/walkthrough.md#3-logging-profiles-management--siem-formats) | Fleet-wide logging configuration with built-in presets for Splunk, ArcSight CEF, gRPC, and custom key-value formats. |
| **Compiler Tester (`apcompile`)** | [![Compiler Tester](docs/screenshots/04_compiler_tester_modal.png)](docs/walkthrough.md#4-official-policy-compilation--bundle-verification-apcompile) | Real-time bundle validation and binary `.tgz` generation running the official F5 WAF compiler engine with diagnostic logging. |
| **GitOps Version Control** | [![GitOps Commit](docs/screenshots/05_github_commit_push_modal.png)](docs/walkthrough.md#5-gitops-synchronization-conflict-resolution--verbose-commits) | Direct GitHub push with automated diff change summarization, conflict resolution on pull, and branch management. |

👉 **[Read the Full Visual Walkthrough Guide with Detailed Step-by-Step Instructions →](docs/walkthrough.md)**

---

## 🌟 Key Features

### 🖥️ Modern DevSecOps Web Interface
- **Theme Switcher**: Instant switching between an eye-friendly Light theme and a dark cybersecurity theme with persistent `localStorage` preference and synchronized CodeMirror syntax styling.
- **Unified Navigation**: Switch seamlessly across **WAF Policies**, **Logging Profiles**, and **Compiler Diagnostics** dashboards.
- **Real-Time Storage Health**: Live connection latency indicator with one-click Redis reconfiguration and resilient In-Memory fallback.

---

### 🛡️ Declarative WAF Policy Management
- **Dual-Mode Editor (Visual Form Builder & CodeMirror JSON)**:
  - **Visual Form Builder**: Interactive controls for general settings, enforcement mode (`blocking` vs `transparent`), violation blocking/alarm toggles, server technologies, allowed HTTP methods, URL routing rules, and Data Guard (DLP).
  - **CodeMirror Direct JSON Editor**: Syntax highlighting, brace matching, code folding, beautify formatting, and live JSON schema validation.
  - **Live Bidirectional Synchronization**: Switch between visual form and raw JSON at any time without losing edits.
- **40+ Official F5 Violations Catalog**: Categorized by HTTP protocol, Evasion techniques, Access violations, Request/Response inspection, Sub-violations, and Input anomalies.
- **Server Technologies Tuning**: Automatic signature selection for Linux, Apache, NGINX, PHP, Node.js, Python, MySQL, MongoDB, and more.
- **Data Guard DLP**: Sensitive data masking for Credit Cards (PAN) and US Social Security Numbers (SSN).
- **Side-by-Side Diff Inspector**: Visually compare uncommitted policy edits against the saved version.
- **Declarative OpenAPI Import**: Generate comprehensive WAF policies directly from OpenAPI 3.0 / Swagger specs (only URI `link` references are permitted).
- **BIG-IP ASM Policy Conversion**: Ingest legacy BIG-IP ASM XML/JSON security policies and transform them into declarative JSON format for F5 WAF for NGINX.

---

### 🧬 User-Defined Custom Signatures (Snort Syntax)
- **Snort-Compatible Rule Engine**: Define, edit, and validate custom attack signatures using standard Snort rules syntax.
- **Interactive Payload Simulator**: Test Snort rules directly against custom HTTP request payloads with instant match inspection and alert visualization.
- **Workflow Operations**: One-click test launch, signature cloning with automatic deduplication, single delete confirmation modals, and multi-select mass deletion.

---

### 🌐 IP Address Lists, Response Signatures & Evasion Techniques
- **IP Address Lists**: Manage whitelists, blacklists, CIDRs (`10.0.0.0/24`), IP ranges, and geolocation overrides (`setGeolocation`) with multi-select mass deletion.
- **Response Signatures & HTTP Inspection**: Configure server response body inspection (`responseCheck`), inspection byte length limits (`responseCheckLength`), and target HTTP status codes (`allowedResponseCodes`).
- **Evasion Techniques**: Fine-tune all 8 official evasion defense techniques (Bad unescape, Directory traversals, Bare byte decoding, Apache whitespace, Multiple decoding, IIS Unicode codepoints, IIS backslashes, %u decoding) and configure maximum decoding passes.
- **Batch Table Operations**: Multi-select checkboxes and mass deletion available for Signature Sets, Allowed/Disallowed URLs, and Parameters.

---

### 📋 Logging Profiles Management
- **Declarative Logging Profile CRUD** ([F5 Documentation](https://docs.nginx.com/waf/logging/logs-overview/)): Create, clone, export, and import logging profiles stored under the `log:<name>` namespace.
- **Traffic Filters**: Filter requests by `illegal` (violations only), `all` (full audit trail), or `blocked` (actively dropped requests).
- **SIEM Presets & Formats**: Built-in templates for `default`, `splunk`, `arcsight` (CEF:0), `grpc`, `bigiq`, and custom `user-defined` key-value formats.
- **34+ Placeholder Tokens**: Interactive token insertion for `%date_time%`, `%ip_client%`, `%attack_type%`, `%violations%`, `%support_id%`, `%request%`, `%response%`, etc.

---

### ⚙️ Dedicated F5 WAF Compiler Service (`apcompile`)
- Integrated containerized compiler based on official F5 compiler images (`private-registry.nginx.com/nap/waf-compiler:latest`).
- Validates policy and logging profile compilation directly from the Web UI to verify that policies compile into valid `.tgz` runtime bundles before deployment.
- Reports installed versions of attack signatures, bot signatures, threat campaigns, and compiler engines via `/v1/bundle/info`.

---

## 🏛️ System Architecture & GitOps Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Browser Client (Light / Dark UI)                     │
│   ├── WAF Security Policies (Visual Builder / CodeMirror / Diff)       │
│   ├── User Custom Signatures (Snort Rule Builder & Payload Tester)     │
│   ├── IP Lists / Evasions / Signature Sets / URLs / Parameters         │
│   └── Logging Profiles     (Visual Builder / SIEM Presets / Tokens)   │
└───────────────────┬────────────────────────────────────┬───────────────┘
                    │ REST API                           │ Compilation Check
┌───────────────────▼────────────────────┐   ┌───────────▼───────────────┐
│     F5 WAF Policy Manager (FastAPI)    │   │  f5-waf-apcompile Service │
│  ├── Policy & Custom Sig Validators    │   │  ├── apcompile CLI        │
│  ├── Logging Profile Validator         │   │  ├── Attack Signatures    │
│  ├── GitOps Synchronization Engine     │   │  ├── Bot Signatures       │
│  ├── OpenAPI & BIG-IP Converters       │   │  └── Threat Campaigns     │
│  └── Storage Abstraction Layer         │   └───────────────────────────┘
└───────────┬────────────────────────────┘
            │
            ├─────────────────────────────────────────┐
            │ Working Copy (Fast CRUD)                │ GitOps Sync (Commit / Pull)
            ▼                                         ▼
┌───────────────────────────┐             ┌───────────────────────────────┐
│       Redis Store         │             │       GitHub Repository       │
│ • Active editing working  │             │ • Remote source-of-truth      │
│   copy (policies & logs)  │  Startup    │ • Version-controlled JSON:    │
│ • Instant save & diffs    │  Auto-Pull  │   ├── /policies/*.json        │
│ • Redis 7 persistent DB   │ ◄────────── │   ├── /log-profiles/*.json    │
│ • Resilient In-Memory     │  Explicit   │   └── /custom-signatures/*.json
│   fallback if unavailable │  Commit     │                               │
│                           │ ──────────► │ • Branch & commit history     │
└───────────┬───────────────┘             └───────────────────────────────┘
            │
            ▼ Runtime Deployment / Export
┌────────────────────────────────────────────────────────────────────────┐
│                     NGINX Plus / F5 WAF for NGINX                      │
│   app_protect_policy_file       "/etc/waf/policies/api_security.json"; │
│   app_protect_security_log      "/etc/waf/logging/log_splunk.json"     │
│                                 syslog:server=10.0.0.10:514;           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 GitOps Workflow & GitHub Configuration

F5 WAF for NGINX Policy Manager provides an integrated **GitOps hybrid architecture** that marries the speed of a high-performance in-memory/Redis working copy with the auditing and version-control benefits of GitHub.

### 🔄 The GitOps Lifecycle

1. **Automatic Retrieval on Startup (GitHub ➔ Redis)**:
   - When GitHub credentials (`GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_TOKEN`) are configured, the application **automatically queries the GitHub repository on startup**.
   - All WAF policy, logging profile, and custom signature JSON files stored in the repository are pulled directly into Redis.
   - The policies and logging profiles appear instantly in the web dashboard for editing, testing, and deployment.
2. **Editing & Testing in Redis Working Copy**:
   - All interactive operations—visual form editing, raw CodeMirror JSON updates, syntax beautification, and side-by-side diff inspections—are performed against **Redis**.
   - Edits are saved instantly to Redis with sub-millisecond response times.
   - You can run the **F5 WAF Compiler (`apcompile`)** directly against your Redis working copy to verify compilation into a binary `.tgz` bundle before committing changes to Git.
3. **Explicit Commit & Push (Redis ➔ GitHub)**:
   - Every policy and logging profile row in the dashboard includes a **"Commit & Push to GitHub"** button (also available in the editor top toolbar).
   - **Smart Inactive State**: The button is automatically disabled and grayed out if the policy or logging profile has not been modified since the last sync.
   - **Automated Diff Summarization**: Clicking it computes a diff against GitHub and automatically prefills a verbose commit description highlighting exact changes (added/removed server technologies, violation toggles, URL/parameter updates, Data Guard rules).
   - Commits the JSON document directly to GitHub via the GitHub REST API without requiring a local `git` binary.
4. **Manual Sync & Interactive Conflict Resolution (Pull from GitHub)**:
   - Click the **"Pull from GitHub"** button in the header to synchronize the local store with the latest remote repository state.
   - **Conflict Protection**: If a local policy or profile is in a modified **Draft** state, an interactive prompt asks whether you want to **Keep Local Draft** or **Overwrite with GitHub Copy**.

---

### ❓ Where are GitHub Configuration Variables Stored? Do They Persist Across Restarts?

**Yes, GitHub configuration variables persist permanently across restarts when defined in an environment file (`.env`) or injected into the container/host environment.**

#### 1. Persistence via `.env` File (Recommended for Local Dev & Docker Compose)
The application uses [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) to automatically load environment variables from a `.env` file located in the project root directory.

To configure GitHub variables:
```bash
# 1. Copy the template to create your .env file
cp .env.example .env

# 2. Add your GitHub repository settings and Personal Access Token
nano .env
```

Add your configuration:
```env
# Storage Backend: keep 'redis' for the GitOps hybrid workflow
STORAGE_BACKEND=redis

# GitHub Repository & Authentication
GITHUB_OWNER=my-org
GITHUB_REPO=f5-waf-policies
GITHUB_TOKEN=ghp_YourPersonalAccessTokenWithRepoScope
GITHUB_BRANCH=main
GITHUB_API_URL=https://api.github.com

# Target directories inside the repository
GITHUB_POLICIES_PATH=policies
GITHUB_LOG_PROFILES_PATH=log-profiles
GITHUB_CUSTOM_SIGS_PATH=custom-signatures
```

Because `.env` is stored on the persistent host filesystem, these settings **persist across container restarts, `docker compose down` / `docker compose up` cycles, and server reboots**.

#### 2. Persistence in Docker Compose (`docker-compose.yml`)
When using Docker Compose, variables in `.env` are automatically forwarded into the `waf-editor` container. Alternatively, you can declare them explicitly under the `environment:` section of `docker-compose.yml`:

```yaml
services:
  waf-editor:
    environment:
      - STORAGE_BACKEND=redis
      - GITHUB_OWNER=my-org
      - GITHUB_REPO=f5-waf-policies
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - GITHUB_BRANCH=main
      - GITHUB_POLICIES_PATH=policies
      - GITHUB_LOG_PROFILES_PATH=log-profiles
      - GITHUB_CUSTOM_SIGS_PATH=custom-signatures
```

#### 3. Persistence in Kubernetes (`helm/`)
In Kubernetes deployments, store the sensitive token in a `Secret` and repository configuration in a `ConfigMap`:

```yaml
env:
  - name: GITHUB_TOKEN
    valueFrom:
      secretKeyRef:
        name: f5-waf-github-credentials
        key: token
  - name: GITHUB_OWNER
    value: "my-org"
  - name: GITHUB_REPO
    value: "f5-waf-policies"
  - name: GITHUB_BRANCH
    value: "main"
```

#### 4. Runtime Configuration via Web Interface
You can also view and test your GitHub connection directly in the web browser by clicking the **Storage Health** badge in the header and switching to the **GitHub GitOps** tab. Configuration entered in the UI updates the running application in-memory immediately. To ensure your credentials survive container recreation, save them in `.env`.

---

### 📋 GitHub Configuration Variables Reference

| Environment Variable | Required | Default | Description |
|---|---|---|---|
| `STORAGE_BACKEND` | No | `redis` | Storage backend: `redis` (recommended for GitOps flow), `github`, or `in_memory`. |
| `GITHUB_OWNER` | Yes* | *None* | GitHub user or organization account owning the repository (e.g., `my-org`). |
| `GITHUB_REPO` | Yes* | *None* | Target GitHub repository name (e.g., `f5-waf-policies`). |
| `GITHUB_TOKEN` | Yes* | *None* | GitHub Personal Access Token (classic with `repo` scope, or fine-grained with Read/Write Contents permission). |
| `GITHUB_BRANCH` | No | `main` | Target Git branch for pulling configurations and pushing commits. |
| `GITHUB_API_URL` | No | `https://api.github.com` | Base API URL. Change for GitHub Enterprise Server (e.g., `https://github.corp.internal/api/v3`). |
| `GITHUB_POLICIES_PATH` | No | `policies` | Subdirectory inside the repository where WAF policy JSON files are stored. |
| `GITHUB_LOG_PROFILES_PATH`| No | `log-profiles` | Subdirectory inside the repository where logging profile JSON files are stored. |
| `GITHUB_CUSTOM_SIGS_PATH` | No | `custom-signatures` | Subdirectory inside the repository where custom signature JSON files are stored. |

*\* Required when GitHub GitOps synchronization is enabled.*

---

## 🐳 Building and Running with Docker Compose

The stack comprises three orchestrated containers defined in `docker-compose.yml`:
1. **`waf-editor`** (`f5-waf-policy-manager`): The web UI and FastAPI backend (port `8000`).
2. **`apcompile`** (`f5-waf-apcompile`): The policy compiler REST service running F5's `apcompile` (port `9000`).
3. **`redis`** (`f5-waf-redis`): Persistent Redis 7 key-value database (port `6379`).

---

### Step 1: Configure Registry Authentication (One-Time Setup)

The compiler image pulls from F5's private container registry (`private-registry.nginx.com/nap/waf-compiler:latest`), which requires **Mutual TLS (mTLS)** client certificate authentication.

> [!IMPORTANT]
> **Docker Daemon vs. Build Secrets**: Docker BuildKit secrets (`--secret`) only apply *inside* container `RUN` steps; they are **not** used by the Docker daemon when pulling base images (`FROM ...`).
>
> The Docker daemon on your host must have the client certificates installed in `/etc/docker/certs.d/private-registry.nginx.com/`. Furthermore, Docker strictly requires the certificate file to end in **`.cert`** (not `.crt` — Docker treats `.crt` files as server CA certificates!).

Run the following commands on your Docker host (or use the provided [`setup-registry-auth.sh`](setup-registry-auth.sh)):

```bash
# 1. Create Docker's registry certificate directory
sudo mkdir -p /etc/docker/certs.d/private-registry.nginx.com

# 2. Copy your valid MyF5 certificate as client.cert and key as client.key
sudo cp /etc/ssl/nginx/nginx-repo.crt /etc/docker/certs.d/private-registry.nginx.com/client.cert
sudo cp /etc/ssl/nginx/nginx-repo.key /etc/docker/certs.d/private-registry.nginx.com/client.key

# 3. Set secure permissions
sudo chmod 644 /etc/docker/certs.d/private-registry.nginx.com/client.cert
sudo chmod 600 /etc/docker/certs.d/private-registry.nginx.com/client.key

# 4. Verify that Docker can pull the base compiler image
docker pull private-registry.nginx.com/nap/waf-compiler:latest
```

*Automated setup via script:*
```bash
chmod +x setup-registry-auth.sh
./setup-registry-auth.sh /etc/ssl/nginx/nginx-repo.crt /etc/ssl/nginx/nginx-repo.key
```

---

### Step 2: Build the Container Images

You can provide your NGINX certificate and key to `docker compose build` using any of the following approaches:

#### Method A: Command-Line Inline Environment Variables (Recommended)
Specify the paths to your valid NGINX repository certificate and key directly on the command line:

```bash
NGINX_CERT=/etc/ssl/nginx/nginx-repo.crt NGINX_KEY=/etc/ssl/nginx/nginx-repo.key docker compose build
```

#### Method B: Export Variables in Your Shell Session
```bash
export NGINX_CERT=/etc/ssl/nginx/nginx-repo.crt
export NGINX_KEY=/etc/ssl/nginx/nginx-repo.key

docker compose build
```

#### Method C: Using an Environment File (`.env`)
Copy the provided `.env.example` file and configure your paths:

```bash
cp .env.example .env
```

Ensure `.env` contains:
```env
NGINX_CERT=/etc/ssl/nginx/nginx-repo.crt
NGINX_KEY=/etc/ssl/nginx/nginx-repo.key
WAF_COMPILER_IMAGE=private-registry.nginx.com/nap/waf-compiler:latest
APP_PORT=8000
COMPILER_PORT=9000
```

Then build simply with:
```bash
docker compose build
```

#### Method D: Building Individual Services
```bash
# Build only the web manager
docker compose build waf-editor

# Build only the apcompile service
NGINX_CERT=/etc/ssl/nginx/nginx-repo.crt NGINX_KEY=/etc/ssl/nginx/nginx-repo.key docker compose build apcompile
```

---

### Step 3: Run the Services

```bash
# Start all containers in the background
docker compose up -d

# Check service status and healthchecks
docker compose ps

# View live aggregate logs
docker compose logs -f

# View compiler service logs specifically
docker compose logs -f apcompile
```

Once running, access the services:
- **Web Interface**: [http://localhost:8000](http://localhost:8000)
- **Compiler REST API**: [http://localhost:9000/health](http://localhost:9000/health)
- **Redis Database**: `localhost:6379`

To shut down:
```bash
# Stop containers
docker compose down

# Stop containers and wipe Redis data volume
docker compose down -v
```

---

## 🛠️ Local Development (Without Docker)

### Prerequisites
- Python 3.10+ (or [uv](https://docs.astral.sh/uv/))
- Optional: Local Redis server (falls back gracefully to memory store if unavailable)

### Running with `uv` (Fastest)
```bash
# Install dependencies into virtual environment
uv sync

# Start the web manager
uv run python main.py
```

### Running with standard `pip` and `python`
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt
python main.py
```

---

## ☸️ Deploying to Kubernetes with Helm

A production-ready Helm chart is provided under [`helm/f5-waf-policy-manager`](helm/f5-waf-policy-manager).

```bash
# Install the Helm chart into namespace 'waf-system'
helm install f5-waf-editor ./helm/f5-waf-policy-manager \
  --namespace waf-system \
  --create-namespace

# Access via port-forward
kubectl --namespace waf-system port-forward svc/f5-waf-editor 8000:80
```

---

## 🗄️ Redis Data Model

Policies and logging profiles are cleanly isolated by key naming conventions:

| Resource Type | Redis Key Pattern | Document Schema | Example Key |
|---|---|---|---|
| **WAF Policy** | `<policy_name>` | JSON conforming to F5 WAF Schema | `prod_api_gateway_waf` |
| **Logging Profile** | `log:<profile_name>` | JSON conforming to F5 Logging Schema | `log:log_splunk` |

---

## 📡 REST API Reference

Interactive OpenAPI documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Core Endpoints Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/policies` | List all WAF security policies |
| `POST` | `/api/policies` | Create or upload a new policy |
| `GET` | `/api/policies/{name}` | Fetch full JSON policy document |
| `PUT` | `/api/policies/{name}` | Save modifications to policy |
| `DELETE`| `/api/policies/{name}` | Delete policy from storage |
| `POST` | `/api/policies/{name}/clone` | Duplicate policy with a new key |
| `GET` | `/api/policies/{name}/export`| Download policy as `.json` |
| `POST` | `/api/policies/import` | Import declarative JSON or OpenAPI spec |
| `POST` | `/api/policies/convert-bigip`| Convert legacy BIG-IP ASM XML/JSON policy |
| `GET` | `/api/log-profiles` | List all logging profiles |
| `POST` | `/api/log-profiles` | Create or update a logging profile |
| `GET` | `/api/custom-signatures` | List custom signatures (Snort syntax) |
| `POST` | `/api/custom-signatures/test` | Test Snort rule against HTTP payload |
| `POST` | `/api/policies/{name}/github-push` | *(GitOps)* Commit and push policy from Redis to GitHub |
| `POST` | `/api/log-profiles/{name}/github-push` | *(GitOps)* Commit and push logging profile from Redis to GitHub |
| `POST` | `/api/custom-signatures/{tag}/github-push` | *(GitOps)* Commit and push custom signatures from Redis to GitHub |
| `POST` | `/api/github/pull` | *(GitOps)* Pull all policies and logging profiles from GitHub into Redis |
| `GET` | `/api/github/status` | Check GitHub connectivity, repo, and branch status |
| `POST` | `/api/github/connect` | Configure GitHub connection settings dynamically |
| `GET` | `/api/redis/status` | Live Redis connectivity and latency check |
| `POST` | `/v1/compile/policy` | *(Compiler)* Compile policy JSON into `.tgz` bundle |
| `POST` | `/v1/compile/logprofile` | *(Compiler)* Compile logging profile into `.tgz` |
| `GET` | `/v1/bundle/info` | *(Compiler)* Report signature & engine versions |

---

## 🧪 Testing

The test suite validates schema enforcement, Snort syntax parsing, IP list formats, evasion rules, storage layers, and REST endpoints:

```bash
# Run pytest with uv
uv run pytest tests/ -v
```

```text
============================= test session starts =============================
collected 171 items

tests/test_api.py ........................................               [ 23%]
tests/test_compiler.py .......                                           [ 27%]
tests/test_converter.py ......                                           [ 30%]
tests/test_custom_signatures_api.py .......                              [ 35%]
tests/test_custom_signatures_compiler.py ..                              [ 36%]
tests/test_custom_signatures_storage.py ..                               [ 37%]
tests/test_custom_signatures_validator.py .......                        [ 41%]
tests/test_deployments.py ........                                       [ 46%]
tests/test_github_storage.py .....                                       [ 49%]
tests/test_logging_api.py ......                                         [ 52%]
tests/test_logging_storage.py ..                                         [ 53%]
tests/test_logging_validator.py .........                                [ 59%]
tests/test_snort_validator.py ....                                       [ 61%]
tests/test_storage.py ....                                               [ 63%]
tests/test_templates.py ..                                               [ 64%]
tests/test_url_parameters_and_sanitization.py ............               [ 71%]
tests/test_validator.py ................................................ [100%]

====================== 171 passed, 4 warnings in 10.91s =======================
```

---

## 📄 License

This project is licensed under the [Apache 2.0 License](LICENSE).
