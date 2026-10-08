# F5 WAF for NGINX Policy & Logging Manager — Visual Walkthrough

Welcome to the visual walkthrough of **F5 WAF for NGINX Policy & Logging Profile Manager**. This guide showcases the core features, visual builders, compiler diagnostics, and GitOps workflows through real-world interface screenshots.

---

## Table of Contents
1. [WAF Policies Dashboard & Quick-Deploy Templates](#1-waf-policies-dashboard--quick-deploy-templates)
2. [Visual Form Builder & Server Technologies Targeting](#2-visual-form-builder--server-technologies-targeting)
3. [Logging Profiles Management & SIEM Formats](#3-logging-profiles-management--siem-formats)
4. [Official Policy Compilation & Bundle Verification (`apcompile`)](#4-official-policy-compilation--bundle-verification-apcompile)
5. [GitOps Synchronization, Conflict Resolution & Verbose Commits](#5-gitops-synchronization-conflict-resolution--verbose-commits)

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
