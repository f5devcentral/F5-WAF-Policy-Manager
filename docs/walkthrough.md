# F5 WAF for NGINX Policy & Logging Manager — Visual Walkthrough

Welcome to the visual walkthrough of **F5 WAF for NGINX Policy & Logging Profile Manager**. This guide showcases the core features, visual builders, compiler diagnostics, and GitOps workflows through real-world interface screenshots.

---

## Table of Contents
1. [WAF Policies Dashboard & Quick-Deploy Templates](#1-waf-policies-dashboard--quick-deploy-templates)
2. [Visual Form Builder & Server Technologies Targeting](#2-visual-form-builder--server-technologies-targeting)
3. [Logging Profiles Management & SIEM Formats](#3-logging-profiles-management--siem-formats)
4. [Official Policy Compilation & Bundle Verification (`apcompile`)](#4-official-policy-compilation--bundle-verification-apcompile)
5. [GitOps Synchronization, Conflict Resolution & Verbose Commits](#5-gitops-synchronization-conflict-resolution--verbose-commits)
6. [ClickHouse Security Log Violations & WAF Policy Fine-Tuning](#6-clickhouse-security-log-violations--waf-policy-fine-tuning)

---

## 1. WAF Policies Dashboard & Quick-Deploy Templates

The central landing page provides a single-pane-of-glass overview of all managed security policies, active storage status, and quick-start templates tailored for production workloads.

![WAF Policies Dashboard](screenshots/01_waf_policies_dashboard.png)

### Key Capabilities:
- **Real-Time Fleet Telemetry**: Instant stat cards displaying total policies, breakdown by enforcement mode (`blocking` vs `transparent`), and active storage engine status (**Redis** or **In-Memory** fallback).
- **Production Quick-Deploy Cards**:
  - **NGINX Default Base**: Standard baseline with OWASP Top 10 and Bot protection.
  - **Strict Security & Data Guard**: Strict enforcement with Data Guard masking (credit cards, SSNs), evasion inspection, and method restrictions.
  - **API & JSON Gateway**: Tuned for modern REST APIs, JSON/GraphQL format validation, and credential protection.
  - **Transparent Monitor**: Zero-risk auditing mode for staging and shadow traffic testing.
  - **gRPC Microservices Protection**: Strict Protobuf IDL schema validation and malformed frame blocking.
- **Inventory Table with GitOps State**:
  - Live **`● synced`** and **`● draft`** status badges indicating alignment with remote GitHub repositories.
  - Quick action controls: Edit in Visual Builder, Duplicate, CodeMirror JSON export, Direct GitHub commit, `.tgz` bundle download, and Safe Delete.
  - Fast client-side search by policy name, description, or enforcement mode.

---

## 2. Visual Form Builder & Server Technologies Targeting

The **Visual Form Builder** empowers security engineers and developers to configure complex WAF policies without manually writing error-prone JSON. Changes stay continuously synchronized bidirectionally with the raw CodeMirror JSON editor.

![Server Technologies Targeting](screenshots/02_policy_visual_builder_technologies.png)

### Key Capabilities:
- **Server Technologies Tuning**:
  - **Quick Stacks**: One-click technology profile selection for common stacks (**LAMP**, **MEAN/MERN**, **Python/Django**, **Java/Spring**, **.NET/IIS**, **WordPress**).
  - **Official Catalog of 70+ Technologies**: Precise signature targeting for web servers (Nginx, Apache, IIS, Tomcat), application frameworks (Express.js, Django, Laravel, Spring Boot), runtimes (Node.js, PHP, Python, Ruby), and databases.
  - Reduces false positives and minimizes processing latency by activating only relevant attack signatures.
- **Comprehensive Policy Navigation Categories**:
  - **General & Mode**: Base templates, application language (`utf-8`), and enforcement mode.
  - **Violations & Enforcement**: Granular alarm/block toggles across 40+ violations.
  - **Evasion Techniques**: Defense against directory traversals, bare byte decoding, Apache whitespace, and multiple decoding passes.
  - **Signatures & Bot Defense**: High accuracy signature sets and bot mitigation.
  - **User-Defined Custom Signatures**: Snort-compatible rule authoring and payload simulation.
  - **URLs, Parameters, Cookies & IP Address Lists**: Whitelists, blacklists, and routing controls.
  - **OpenAPI & gRPC Protection**: Schema-driven API firewalling.
  - **Data Guard (DLP)**: Real-time masking of credit cards and SSNs in response bodies.
- **Integrated Tooling Bar**:
  - **Diff Inspector**: Side-by-side visual diff against the saved baseline.
  - **Test Compiler**: On-demand compilation check directly from the editor.
  - **Commit & Push to GitHub**: Direct GitOps push with change summarization.

---

## 3. Logging Profiles Management & SIEM Formats

Logging profiles dictate how security events, alerts, and transaction metadata are captured, formatted, and shipped to SIEM platforms and analytics collectors.

![Logging Profiles Dashboard](screenshots/03_logging_profiles_dashboard.png)

### Key Capabilities:
- **Pre-Configured SIEM & Analytics Presets**:
  - **Default (Illegal Requests)**: Standard built-in F5 key-value format for policy violations.
  - **Log All Traffic**: Full audit compliance capturing both legal and illegal requests.
  - **Blocked Requests Only**: High-signal stream capturing only dropped traffic.
  - **gRPC Protocol All**: Optimized for microservice tracing with Base64 payload decoding.
  - **Splunk SIEM Profile**: Formatted specifically for native ingestion via the Splunk App for F5 WAF.
  - **ArcSight CEF Profile**: Standard Common Event Format (`CEF:0`) for enterprise SOCs.
  - **Custom Key-Value Profile**: Customizable token stream supporting custom delimiters and field sets.
- **Profile Inventory & Management**:
  - Stat cards summarizing total profiles, active filters (`illegal`, `all`, `blocked`), and SIEM configurations.
  - Full CRUD operations with instant duplication, JSON import/export, and GitHub synchronization.

---

## 4. Official Policy Compilation & Bundle Verification (`apcompile`)

Before deploying declarative policies to production NGINX instances, they must be compiled into binary `.tgz` runtime bundles. The built-in **Compiler Tester** leverages the official `apcompile` service container to validate policies with zero guesswork.

![Compiler Tester Modal](screenshots/04_compiler_tester_modal.png)

### Key Capabilities:
- **Instant Compilation Feedback**:
  - Validates full JSON schema compliance, SQLite catalog constraints, and signature definitions.
  - Displays comprehensive compilation metrics: **Archive Size**, **Compile Time (ms)**, and **Bundle SHA-256 Checksum**.
- **Execution Diagnostics**:
  - Outputs full compiler stdout logs including active versions of `attack_signatures_package` and `threat_campaigns_package`.
  - Built-in remediation engine automatically translates compiler errors (e.g. SQLite foreign key violations or unrecognized parameters) into actionable fixes.
- **One-Click Bundle Download**:
  - Download verified, production-ready `.tgz` bundles directly to your machine for deployment into NGINX Plus WAF instances.

---

## 5. GitOps Synchronization, Conflict Resolution & Verbose Commits

Adopt true Infrastructure-as-Code (IaC) and DevSecOps workflows by keeping your policies and logging profiles version-controlled directly in GitHub without requiring a local `git` binary.

![GitOps Commit and Push Modal](screenshots/05_github_commit_push_modal.png)

### Key Capabilities:
- **Automated Diff Summarization**:
  - When committing a policy or profile, the engine automatically analyzes changes between your working copy and remote repository.
  - Generates clear, structured multi-line commit descriptions highlighting added/removed server technologies, signature sets, violation changes, URLs, and Data Guard settings.
- **Smart Commit Button State**:
  - The **"Commit & Push to GitHub"** button is automatically grayed out when a policy is already in sync with GitHub, and only becomes active when modifications have been made.
- **Interactive Conflict Resolution on Pull**:
  - When triggering a **"Pull from GitHub"**, if a policy or logging profile is in a modified **Draft** state locally, the user is presented with a choice modal:
    - **Keep Local Draft**: Preserve current in-progress changes.
    - **Overwrite with GitHub Copy**: Reset to remote version.
- **Direct GitHub REST Integration**:
  - Communicates directly via authenticated GitHub API (`httpx`) supporting custom branches, personal access tokens, and private repositories.

---

## 6. ClickHouse Security Log Violations & WAF Policy Fine-Tuning

The **Violation Logs & Tuning** dashboard connects directly to the remote **ClickHouse** database inside **NGINX Instance Manager (NIM)** to search security violations, correlate event tables by `support_id`, and fine-tune WAF policies (`signature_id` tightening or relaxation).

### Step-by-Step Workflow:
1. **Configure & Persist ClickHouse Connection**:
   - Click the **ClickHouse** status badge in the top navigation bar or **ClickHouse Settings** in the **Violation Logs & Tuning** view.
   - Enter the remote NGINX Instance Manager ClickHouse IP/Hostname (`host`), HTTP port (`8123`), `username`, `password`, and `database` (default `nms`).
   - Click **Test Connection** to verify connectivity and inspect the status of the 3 security log tables, then click **Save & Persist in Redis**.
   - Connection credentials are saved under `waf:policy:__clickhouse__:config` in Redis so they automatically persist across container restarts and server reboots.
2. **Search & Filter Across All 53 Fields of `v4_security_events`**:
   - Use the **Global Search** bar or add multi-condition field filters across **any of the 53 columns** in `v4_security_events` (e.g., `support_id`, `policy_name`, `http__uri`, `http__remote_addr`, `severity`, `request_status`, `violation_rating`, `violations`, `sub_violations`, `signature_ids`, `bot_signature_name`, `request`, `is_truncated`).
   - Use quick filter presets (`Blocked Only`, `Critical Severity`, `Attack Signatures`, `Untrusted Bots`) to immediately surface high-priority security events.
3. **Correlate All 3 Tables by `support_id`**:
   - Click **Correlate & Tune** on any security event row (e.g. `support_id = 10134279319999872904`).
   - The correlation drawer queries all 3 ClickHouse tables using `support_id` as the join key and presents them in 4 dedicated tabs:
     - **Signature Fine-Tuning (`v4_security_events_signatures_data`)**: Lists every triggered `signature_id` with its `signature_name`, `signature_accuracy`, `signature_risk`, `blocking_mask`, matched `buffer` (`offset` / `length`), and `violation_contexts`.
     - **Violation Data (`v4_security_events_violation_data` — 39 fields)**: Shows all correlated violation and sub-violation rows, contexts, blocking masks, and field names/values.
     - **Full Event & HTTP Request (`v4_security_events` — 53 fields)**: Displays the raw HTTP request payload, XML `violation_details`, and a searchable 53-field inspector.
     - **Correlated SQL Queries**: Displays the exact parameterized ClickHouse SQL queries executed for full transparency.
4. **Tighten or Relax Signatures in Your WAF Policy (`signature_id`)**:
   - Select the target WAF policy (automatically matched from the event's `policy_name` when present in storage).
   - For any triggered `signature_id` (e.g. `200010468` — `"/etc/passwd" access (URI)` or `200003056` — `"/etc" execution attempt (URI)`):
     - Click **Enable (Tighten)** to set `{"signatureId": 200010468, "enabled": true}` in `policy.signatures`.
     - Click **Disable (Relax)** to set `{"signatureId": 200010468, "enabled": false}` in `policy.signatures` (suppressing false positives).
     - Click **Reset** to remove the explicit override and revert to policy signature set defaults.
   - Use **Enable All Signatures (Tighten)** or **Disable All Signatures (Relax)** for one-click bulk tuning, or click **Open Target Policy in Editor** to immediately inspect the diff, compile with `apcompile`, or commit to GitHub.

