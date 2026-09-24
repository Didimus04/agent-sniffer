# Requirements Document

## Introduction

PANTHEON is a code and runtime security system split into two operating divisions — ARES and ARGUS — unified under a single control layer. ARES is the offensive division: it intercepts, scans, and neutralizes threats at the perimeter before they reach the system. ARGUS is the defensive division: it operates continuously in the background, monitoring assets from within and detecting threats that bypass the perimeter. Both divisions share a unified Policy, EventLog, SDK, and Control Plane.

## Glossary

- **PANTHEON**: The full system — ARES division, ARGUS division, SDK, and Control Plane operating as a single unified security platform.
- **ARES**: The offensive division of PANTHEON responsible for perimeter interception, multi-agent threat analysis, and automated response.
- **ARGUS**: The defensive division of PANTHEON responsible for continuous background surveillance, three-layer filtration, and HVP-aware threat enrichment.
- **Gateway**: The PANTHEON intercept layer that sits between a Client and a target service at runtime.
- **Client**: Any application, mobile app, or system that integrates the PANTHEON SDK.
- **Payload**: The full content of a request, response, or submitted source file, including text, metadata, and structured data.
- **Signal**: A detected pattern indicating a security threat, vulnerability, or policy-violating behavior.
- **Severity**: A classification assigned to a detected Signal: `low`, `medium`, `high`, or `critical`. Severity is derived solely from the CVSSv3 final score (see CVSSv3 Score).
- **CVSSv3 Score**: The sole numeric severity scale in PANTHEON — a float from 0.0 to 10.0 per CVSS v3.0 Base Score specification. All `base_score` and `final_score` variables use this scale; no 0–1 or 0–100 custom scales are permitted. Severity bands: 0.0–3.9 → `low`, 4.0–6.9 → `medium`, 7.0–8.9 → `high`, 9.0–10.0 → `critical`.
- **Policy**: An operator-defined rule set governing what Payloads are permitted and what actions to take on violations.
- **Inspector**: The orchestration component that manages the multi-agent detection pipeline and aggregates results.
- **EventLog**: A persistent, tamper-evident record of all inspected interactions, detected Signals, and system actions.
- **Connector**: The component responsible for forwarding requests to a target service and receiving responses.
- **Parser Agent**: The first agent of the CrewAI Pipeline; normalizes and parses raw input into a structured representation.
- **Scanner Agent**: The second agent of the CrewAI Pipeline; runs SAST analysis using Semgrep and CPG/GNN anomaly detection against the parsed representation.
- **RedTeamer Agent**: The third agent of the CrewAI Pipeline; executes suspicious Payloads in a sandbox and queries the RAG knowledge base.
- **Auditor Agent**: The fourth and final agent of the CrewAI Pipeline; aggregates all prior agent outputs, assigns the CVSSv3 final score and Severity, and produces a threat report.
- **Sentry Gateway**: The pure-Python entry-point triage component on the FastAPI server; validates, deduplicates, and fast-triages incoming jobs before handing them to the CrewAI Pipeline. It is not an agent and performs no LLM calls.
- **CrewAI Pipeline**: The heavy asynchronous backend processing stage consisting of exactly 4 specialized worker agents executed sequentially: Parser Agent → Scanner Agent → RedTeamer Agent → Auditor Agent.
- **CPG**: Code Property Graph — a combined AST, CFG, and PDG representation produced by Joern for data flow analysis.
- **GNN**: Graph Neural Network applied to CPG node embeddings to detect anomalous data flow patterns.
- **RAG**: Retrieval-Augmented Generation — the pipeline component that queries a ChromaDB vector store of CVE and OWASP Top 10 documents using the Gemini API.
- **Control Plane**: The operator-facing management layer providing monitoring, configuration, and incident response interfaces.
- **SDK**: The embeddable PANTHEON library distributed for integration into any application, mobile, or system software.
- **HVP**: High-Value Person — a user or operator role with an elevated threat profile and a configured priority multiplier applied to all Signal scoring.
- **EventHandler**: The OS-level file system event listener (implemented via watchdog) that receives file change notifications and pushes events to the ScanQueue.
- **ScanQueue**: A bounded asyncio.Queue that receives file change events and code chunks pending pipeline execution.
- **CodeChunk**: A discrete unit of analysis — a single function or critical code block extracted from a source file by the AST/Regex filter — submitted to the CrewAI pipeline.
- **HashDB**: A local SQLite database storing per-function SHA-256 hashes used by the semantic hash gate to skip unchanged code.
- **HVP_Profile**: A configuration record defining threat vectors, monitored assets, priority multiplier, escalation channels, and auto-escalation thresholds for a given HVP role.
- **RBAC**: Role-Based Access Control — the permission system governing which roles can view, modify, or act on data within the Control Plane.
- **SUPER_ADMIN**: The highest-privilege Control Plane role; holds the decryption key for CRITICAL-level masked data and can approve severity downgrade requests.
- **ADMIN**: A restricted Control Plane role; can only view MEDIUM and LOW HVP-level data in masked form and submit resolutions.
- **SeverityChangeRequest**: A pending database record created when an ADMIN requests a severity downgrade, requiring SUPER_ADMIN approval before the change is applied.
- **SessionToken**: A cryptographically signed in-memory session credential binding a user identity to a role, validated via HMAC with a role-specific signing key.
- **EventBus**: An in-process asyncio.Queue-based pub/sub component that decouples the detection pipeline from WebSocket broadcast, allowing pipeline workers to publish events without waiting for delivery.
- **WebSocketManager**: The Control Plane component that maintains per-role WebSocket connection registries and broadcasts sanitized event payloads to connected clients.
- **SIEM**: Security Information and Event Management — the log format standard (single-line JSON) used by PANTHEON's EventLog output for compatibility with tools such as Splunk.
- **ForensicContext**: A JSON object extracted from a CodeChunk at SDK-side before transmission, containing file_path_hash (SHA-256 of the absolute path), relative_masked_path (e.g. `[root]/src/auth.py`), line_coordinates (start and end line numbers), and git_commit_hash of the last commit that touched the file. The raw absolute path never leaves the SDK process (Zero-Knowledge Privacy).
- **RelativeMaskedPath**: A display-safe path of the form `[root]/<repo-relative-path>` derived SDK-side by stripping the machine-specific prefix; the only path form ever shown on the dashboard or stored server-side.
- **Detached Metadata Indexing**: The privacy architecture in which the SDK transmits only SHA-256(path) for identity mapping while the absolute-path → hash map lives exclusively in a machine-local SDK-side index; inverse resolution executes only on the developer machine.
- **MaskedPayload**: The source text of a CodeChunk with sensitive variable values and tokens replaced by redaction placeholders, preserving code structure for forensic review without exposing raw credentials.
- **EvidenceHash**: A SHA-256 digest of the original, unmasked CodeChunk source text, used as a tamper-evident digital fingerprint for chain-of-custody verification by security teams.
- **Pipeline Worker**: An asyncio server task that dequeues jobs from SERVER_SCAN_QUEUE, invokes the Sentry Gateway triage, then executes the CrewAI Pipeline via run_in_executor. Distinct from the SDK background worker, which consumes the client-side ScanQueue.
- **ChainOfCustody**: The forensic verification process by which a security team confirms the integrity of a logged threat using the EvidenceHash, ForensicContext, and git history, without requiring access to the original source code.

---

## Requirements

## ARES — Offensive Division

### Requirement 1: Embeddable SDK

**User Story:** As a developer, I want to integrate PANTHEON into any application, mobile app, or system software via an SDK, so that threat detection is available wherever my software runs without requiring a separate proxy deployment.

#### Acceptance Criteria

1. THE SDK SHALL expose a programmatic API accepting a Payload and a Policy reference and returning a threat report synchronously and asynchronously.
2. THE SDK SHALL be distributable as a Python package installable via pip, with no mandatory system-level dependencies beyond the PANTHEON runtime.
3. WHEN the SDK is initialized with a valid Policy, THE SDK SHALL establish a connection to the configured Inspector endpoint or run an in-process Inspector instance, as specified in the configuration.
4. WHEN the SDK is initialized with an in-process Inspector, THE SDK SHALL load all pipeline agents and the GNN model within 10 seconds of initialization.
5. THE SDK SHALL expose a context manager interface that ensures all pipeline resources are released when the context exits.
6. IF the SDK is invoked without a valid Policy, THEN THE SDK SHALL raise a configuration error before executing any pipeline step.
7. WHERE the SDK is configured for mobile deployment, THE SDK SHALL support a lightweight mode that offloads RAG queries and GNN inference to a remote Inspector endpoint rather than running them in-process.

---

### Requirement 2: Multi-Agent Detection Pipeline

**User Story:** As a security operator, I want all submitted Payloads to pass through a sequential four-agent CrewAI pipeline, so that each analysis stage builds on the previous and produces a coherent, auditable threat assessment.

#### Acceptance Criteria

1. WHEN a Payload is submitted to the Inspector, THE Inspector SHALL invoke the Parser Agent, followed by the Scanner Agent, followed by the RedTeamer Agent, followed by the Auditor Agent, in that order, before returning a result to the caller.
2. WHEN the Parser Agent receives a raw Payload, THE Parser Agent SHALL normalize encoding, extract structured representations, and pass a parsed artifact to the Scanner Agent.
3. WHEN the Scanner Agent receives a parsed artifact, THE Scanner Agent SHALL pass its findings as a structured scan result to the RedTeamer Agent.
4. WHEN the RedTeamer Agent receives scan results, THE RedTeamer Agent SHALL pass its findings and RAG query results to the Auditor Agent.
5. WHEN the Auditor Agent receives all prior findings, THE Auditor Agent SHALL produce a threat report containing a final Severity classification, matched patterns, and a remediation summary.
6. IF any agent in the pipeline raises an unhandled exception, THEN THE Inspector SHALL record the failure in the EventLog with the agent identifier and error reason, and classify the Payload at Severity `high` under a fail-closed policy.
7. THE Inspector SHALL complete the full four-agent pipeline within 30 seconds for Payloads up to 1MB.

---

### Requirement 3: SAST Integration via Semgrep

**User Story:** As a developer, I want submitted source code scanned by Semgrep during static analysis, so that known vulnerability patterns are detected before the code is deployed or executed.

#### Acceptance Criteria

1. WHEN the Scanner Agent receives a parsed source code artifact, THE Scanner Agent SHALL invoke Semgrep using the configured rule sets and collect all rule match findings.
2. WHEN Semgrep returns one or more rule matches, THE Scanner Agent SHALL map each match to a Signal with Severity derived from the matched rule's severity classification.
3. WHEN Semgrep returns no rule matches, THE Scanner Agent SHALL record a clean-scan result and pass it to the next agent with zero findings.
4. THE Scanner Agent SHALL support Semgrep rule sets specified as local file paths or as Semgrep Registry identifiers in the Policy configuration.
5. IF Semgrep exits with a non-zero error code, THEN THE Scanner Agent SHALL log the error to the EventLog and classify the scan result as inconclusive, without blocking the pipeline.
6. WHERE a custom Semgrep rule set is specified in the Policy, THE Scanner Agent SHALL apply that rule set in addition to any default rules.

---

### Requirement 4: CPG and GNN Anomaly Detection

**User Story:** As a security engineer, I want code submitted for analysis to be modeled as a Code Property Graph and evaluated by a GNN, so that data flow anomalies not captured by pattern-matching rules can be detected.

#### Acceptance Criteria

1. WHEN the Scanner Agent receives a source code artifact in a supported language, THE Scanner Agent SHALL invoke Joern to generate a CPG capturing the AST, CFG, and PDG of the submitted code.
2. WHEN Joern produces a CPG, THE Scanner Agent SHALL extract node and edge embeddings from the CPG and pass them to the GNN inference component.
3. WHEN the GNN inference component returns an anomaly score, THE Scanner Agent SHALL include the score in its findings; IF the score exceeds the configured anomaly threshold, THEN THE Scanner Agent SHALL attach a Signal with Severity `high` to the findings.
4. THE Scanner Agent SHALL support CPG generation for Python, JavaScript, TypeScript, and Java source files; unsupported file types SHALL be passed through without CPG analysis.
5. IF Joern fails to produce a CPG within 20 seconds, THEN THE Scanner Agent SHALL log a timeout to the EventLog and continue with Semgrep findings only.
6. THE GNN inference component SHALL use a pre-trained model loaded at startup; WHERE a model path is specified in the Policy, THE Scanner Agent SHALL load that model instead of the default.

---

### Requirement 5: DAST Sandbox Execution

**User Story:** As a security operator, I want suspicious Payloads executed in an isolated sandbox, so that dynamic behavior — including network calls, file writes, and process spawning — can be observed without risk to the host system.

#### Acceptance Criteria

1. WHEN the RedTeamer Agent classifies a Payload as suspicious based on static scan results or RAG findings, THE RedTeamer Agent SHALL execute the Payload in an isolated sandbox environment.
2. WHILE sandbox execution is active, THE sandbox SHALL prevent the executed process from making outbound network connections, writing outside a designated scratch directory, and spawning child processes beyond a configured limit.
3. WHEN sandbox execution completes, THE RedTeamer Agent SHALL collect execution artifacts including stdout, stderr, system call trace, and exit code, and include them in the findings passed to the Auditor Agent.
4. IF sandbox execution exceeds 10 seconds, THEN THE RedTeamer Agent SHALL terminate the sandbox process, record a timeout entry in the EventLog, and continue with partial execution artifacts.
5. IF the sandbox environment fails to initialize, THEN THE RedTeamer Agent SHALL log the failure to the EventLog, skip sandbox execution, and continue the pipeline with static findings only.
6. THE sandbox SHALL run each Payload in a separate, ephemeral container or process namespace that is destroyed after execution completes.

---

### Requirement 6: RAG-Powered Threat Intelligence

**User Story:** As a security analyst, I want threat queries answered against a CVE and OWASP Top 10 knowledge base, so that detection is informed by current, structured vulnerability intelligence rather than static rules alone.

#### Acceptance Criteria

1. WHEN the RedTeamer Agent processes a Payload, THE RedTeamer Agent SHALL embed a query derived from the Payload's characteristics and retrieve the top-K most relevant documents from the ChromaDB vector store, where K is configurable in the Policy with a default of 5.
2. WHEN ChromaDB returns retrieval results, THE RedTeamer Agent SHALL submit the retrieved documents and the Payload summary to the Gemini API and incorporate the response into its findings.
3. THE ChromaDB vector store SHALL be pre-populated with CVE records and OWASP Top 10 vulnerability descriptions prior to PANTHEON startup.
4. WHEN new CVE or OWASP documents are added to the knowledge base, THE RedTeamer Agent SHALL use the updated embeddings for all subsequent queries without requiring a pipeline restart.
5. IF the Gemini API returns an error or times out after 15 seconds, THEN THE RedTeamer Agent SHALL log the failure to the EventLog and continue with retrieval results only, without a generated summary.
6. IF ChromaDB is unavailable, THEN THE RedTeamer Agent SHALL log the failure to the EventLog and continue the pipeline with static findings only, without a RAG query.

---

### Requirement 7: Auto-Block and Auto-Patch

**User Story:** As a security operator, I want high-confidence threats to be acted on immediately without human intervention, so that critical vulnerabilities and active attacks are stopped in real time.

#### Acceptance Criteria

1. WHEN the Auditor Agent assigns a final Severity of `high` or `critical` to a finding, THE Inspector SHALL classify the case as high-confidence and trigger an automated response without human escalation.
2. WHEN an auto-block response is triggered for a runtime Payload, THE Gateway SHALL immediately reject the Payload, return a policy-block error to the Client, and record the block action in the EventLog.
3. WHEN an auto-patch response is triggered for a source code Payload, THE Inspector SHALL generate a remediation patch using the Gemini API and include the patch in the threat report returned to the caller.
4. WHEN a remediation patch is generated, THE Inspector SHALL include the diff, the affected relative masked path, and the specific requirement or CVE the patch addresses in the threat report; THE Inspector SHALL never include the absolute raw file path.
5. THE Policy SHALL allow operators to configure, per Severity level, whether the automated response is `block`, `patch`, or `escalate`; IF no configuration is present for a Severity level, THEN THE Inspector SHALL default to `block`.
6. IF the Gemini API is unavailable during patch generation, THEN THE Inspector SHALL fall back to a rule-based remediation template from the knowledge base and flag the patch as template-generated in the threat report.

---

## ARGUS — Defensive Division

### Requirement 8: Background Scanning — Event-Driven Engine

**User Story:** As a security operator, I want continuous background scanning driven by OS-level file system events and Git webhooks, so that threats are detected proactively the moment code changes without polling loops or excessive CPU usage.

#### Acceptance Criteria

1. WHEN background scanning mode is enabled for a Client in the Policy, THE SDK background operation framework (`sdk/background.py`) SHALL register an EventHandler using OS-level file system notifications (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows via watchdog) rather than a polling loop, coordinating passive monitoring (ARGUS) and automated enforcement (ARES) tasks, pushing file change events to the ScanQueue.
2. WHEN a Git webhook POST request is received by the Inspector's webhook endpoint, THE Inspector SHALL extract the changed file paths from the diff payload and push each changed file path as an event to the ScanQueue.
3. THE ScanQueue SHALL be a bounded asyncio.Queue with a configurable maximum depth, defaulting to 1,000 entries; IF the queue reaches its maximum depth, THEN THE Inspector SHALL emit an operator alert via the Control Plane and discard the oldest pending entries.
4. WHEN background scanning mode is active, THE Inspector SHALL maintain a worker pool of configurable size (default: 3 async workers) consuming events from the ScanQueue, each worker applying the three-layer filter before invoking the CrewAI pipeline.
5. WHEN background scanning mode is active, THE Inspector SHALL operate transparently such that Client request latency increase does not exceed 200ms at the 95th percentile compared to a baseline without background scanning.
6. THE Inspector SHALL allow background scanning to be enabled or disabled per Client identifier in the Policy with no effect on Clients for which it is not configured.
7. WHEN a Signal is detected during background scanning, THE Inspector SHALL apply auto-block, auto-patch, or escalation logic per the Severity rules in Requirement 7 and record the detection source as `background` in the EventLog.
8. WHILE background scanning mode is active, THE Inspector SHALL generate a periodic scan summary report at the interval configured in the Policy, with a minimum interval of 60 seconds.

---

### Requirement 9: Background Scanning — Three-Layer Filtration

**User Story:** As a platform engineer, I want all background scan events filtered through structural L0 exclusions, string length boundaries, Layer 1 allowlists, Layer 2 SQLite hash lookups, and Layer 3 AST-regex heuristic gates inside `sdk/pre_filter.py` before reaching the CrewAI pipeline, so that LLM token usage is minimized and only security-critical code changes are submitted for AI analysis.

#### Acceptance Criteria

1. WHEN the Inspector receives a file change event from the ScanQueue, THE Inspector SHALL apply Layer 1 (Extension Filter) first: IF the changed file's extension is `.ics`, THEN THE Inspector SHALL route the event to the ICS Bypass Gateway, skipping the token-length gate and Layers 2–3; ELSE IF the extension is not in the configured allowlist (default: .py, .js, .ts, .java, .go, .rs, .c, .cpp), THEN THE Inspector SHALL discard the event and record a skip entry in the EventLog without proceeding to Layer 2.
2. WHEN a file passes Layer 1, THE Inspector SHALL apply Layer 2 (Semantic Hash Gate): compute a SHA-256 hash of each function body in the file using AST parsing, compare each hash against the HashDB, and forward only functions whose hash differs from the stored value; IF all function hashes are unchanged, THEN THE Inspector SHALL discard the event without invoking the pipeline.
3. WHEN one or more functions pass Layer 2, THE Inspector SHALL apply Layer 3 (AST/Regex Criticality & Heuristic Keyword Density Filter): extract functions and code blocks matching critical security patterns (auth, crypto, db, exec, network) OR matching the Sliding Window Keyword Density Tokenizer. The Sliding Window Tokenizer SHALL evaluate code blocks across a sliding window boundary of 10 continuous lines; IF the accumulation of security-sensitive tokens (`eval`, `exec`, `b64decode`, `subprocess`, `getattr`, `compile`, `__import__`, `getattr`, `setattr`) within any 10-line window exceeds a density weight threshold of > 2 tokens, THEN THE Inspector SHALL flag the block as a `Suspicious Low-Entropy Paywall` match, promote it to a CodeChunk, and pass it for AI analysis regardless of Shannon entropy score; IF no critical patterns or density threshold triggers occur, THE Inspector SHALL discard the code block.
4. WHEN one or more CodeChunks pass all three layers, THE Inspector SHALL push each CodeChunk to the worker pool for CrewAI pipeline execution; each CodeChunk SHALL include the file identifier (file_path_hash plus relative masked path), function name, source text, and the Layer 3 match reason. The absolute raw file path MAY exist transiently inside the SDK worker's memory for local processing, but SHALL never be transmitted to the Control Plane.
5. WHEN a worker completes pipeline execution for a CodeChunk, THE Inspector SHALL update the HashDB with the new SHA-256 hash for each processed function.
6. THE Inspector SHALL enforce a configurable rate limit on Gemini API calls per minute (default: 14 RPM) by applying a token-bucket delay between worker invocations to prevent exceeding the free-tier quota.
7. IF the Gemini API returns a rate-limit error (HTTP 429), THEN THE Inspector SHALL pause the affected worker for a configurable back-off duration (default: 60 seconds) and re-queue the CodeChunk at the front of the ScanQueue.
8. WHEN the ICS Bypass Gateway receives a calendar asset, THE Inspector SHALL parse SUMMARY, DESCRIPTION, URL, and ORGANIZER metadata fields with the dedicated ICS parser; IF URL anomalies or untrusted external elements are found, THEN THE Inspector SHALL append an External Anomaly Flag to the CodeChunk and elevate its initial context score before HVP enrichment.
9. WHEN the Length Boundary Tokenizer evaluates a string token, THE Inspector SHALL invoke the pure-Python Shannon Entropy Calculator only for tokens exceeding the boundary length requirement of > 60 characters; IF the Shannon entropy score of any such token is strictly greater than 5.2 (H > 5.2), THEN THE Inspector SHALL assign a high risk-weight parameter (`high_entropy_secret_detected=True`) to the metadata packet, promoting the token/block to a CodeChunk for priority analysis by the CrewAI Pipeline.

---

### Requirement 10: HVP Contextual Validator

**User Story:** As a security operator, I want background scan findings enriched with a High-Value Person risk profile before routing, so that the same Signal receives different handling depending on the role and threat exposure of the asset owner.

#### Acceptance Criteria

1. WHEN the Auditor Agent produces a threat report for a CodeChunk, THE Inspector SHALL look up the HVP_Profile associated with the asset owner's role as configured in the Policy before routing the report.
2. WHEN an HVP_Profile is found for the asset owner, THE Inspector SHALL multiply the Auditor Agent's CVSSv3 base score by the profile's priority_multiplier to compute the final signal score capped at 10.0, and SHALL use the final signal score for Severity routing.
3. WHEN the detected threat vector matches an entry in the HVP_Profile's threat_vectors list, THE Inspector SHALL apply a confidence boost of 2.0 points on the CVSSv3 scale to the final signal score, capped at 10.0.
4. WHEN the affected asset matches an entry in the HVP_Profile's monitored_assets list, THE Inspector SHALL mark the Signal as a targeted-asset hit in the EventLog entry.
5. THE Policy SHALL support the following built-in HVP roles with the specified default priority multipliers: CEO at 2.0 (Severity weight CRITICAL, threat vectors: spear phishing, business email compromise, financial authorization hijack, reputation manipulation); LEAD_DEV_DEVOPS at 1.5 (Severity weight HIGH, threat vectors: supply chain attack, credential leak in repository, environment variable tampering, CI/CD pipeline injection); HVP_CALENDAR at 1.2 (Severity weight MEDIUM, threat vectors: OSINT routine mapping, social engineering via schedule, meeting spoofing, location pattern extraction); HRD_RECRUITMENT at 1.0 (Severity weight LOW, threat vectors: infostealer via CV, macro-enabled document, PDF exploit).
6. WHEN the HVP_Profile for HRD_RECRUITMENT processes an ingested file event (such as CV/Resume document uploads), THE Inspector SHALL enforce a Force Sandbox Protocol: THE SDK SHALL completely bypass Layer 2 (Semantic Hash Gate) and Layer 3 (AST/Regex Filter) on the client side to prevent telemetry starvation and false-positive hash bypasses; THE SDK SHALL transmit the baseline file metadata directly to the Control Plane, which SHALL automatically force-isolate the raw asset payload into an active dynamic execution sandbox environment for behavioral malware parsing before any pipeline completion.
7. WHEN the HVP_Profile for HVP_CALENDAR is active, THE Inspector SHALL enable OSINT enrichment mode: extract location metadata, attendee lists, and recurrence patterns from calendar assets and include them in the RAG query submitted to the RedTeamer Agent.
8. WHEN the final signal score after HVP multiplier application meets or exceeds the auto-escalation threshold defined in the HVP_Profile, THE Inspector SHALL trigger active containment (auto-block or auto-patch per Requirement 7) and deliver the escalation notification via the channels specified in the profile (CEO: SMS + email + Control Plane; LEAD_DEV_DEVOPS: Slack webhook + email + Control Plane; HVP_CALENDAR: email + Control Plane; HRD_RECRUITMENT: email + Control Plane).
9. IF no HVP_Profile is configured for the asset owner's role, THE Inspector SHALL NOT assume a Low Risk default state (Zero Trust constraint). THE Inspector SHALL assign the identity to the `UNKNOWN_HIGH_RISK` level, apply a CVSSv3 base score floor of 7.0, and immediately route the CodeChunk to the full CrewAI Pipeline for deep analysis; the UNKNOWN identity SHALL be recorded in the EventLog with `identity_resolved=False` and `zero_trust_escalation=True`.
10. WHEN the Inspector resolves the HVP role for a CodeChunk, THE Inspector SHALL determine the role by first extracting the git commit author email from the git_commit_hash in the ForensicContext and matching it against configured email patterns; IF no email pattern matches, THEN THE Inspector SHALL fall back to matching the relative_masked_path in the ForensicContext against configured relative path patterns; IF neither matches, THEN THE Inspector SHALL assign role `UNKNOWN_HIGH_RISK` per AC#9.
11. WHEN the Inspector resolves a git commit author email, THE Inspector SHALL store only the SHA-256 hash of the author email in the EventLog entry and SHALL NOT persist the raw email address in any log, database, or event payload.
12. WHEN the HVP_Profile for HVP_CALENDAR is active and OSINT enrichment mode is enabled, THE Inspector SHALL scan attendee email domains in the monitored calendar asset against a configurable list of trusted organizational domains; IF an attendee email originates from a domain not on the trusted list and the domain was registered within the past 365 days or exhibits typosquatting similarity to a trusted domain, THEN THE Inspector SHALL classify the entry as a Signal with Severity `medium` and include the suspicious domain in the threat report.
13. WHEN the Inspector resolves the HVP role for a CodeChunk with HVP severity weight `CRITICAL` or `HIGH`, THE Inspector SHALL verify the GPG signature of the associated git commit by executing `git verify-commit <git_commit_hash>`; IF the GPG signature is invalid or absent, THEN THE Inspector SHALL set `identity_spoofing_detected=True` in the EventLog entry, escalate the Signal to the configured SUPER_ADMIN escalation channel regardless of the active Severity routing policy, and include the commit hash and verification failure reason in the threat report.
14. WHEN GPG verification returns `untrusted_key` or `expired_key` AND the commit author email hash matches a record in the internal employee directory, THE Inspector SHALL NOT raise an emergency alarm; instead THE Inspector SHALL hold the case at Severity `medium` with status `Pending Key Verification`, apply a `WARM LOCK` flag to the commit in the EventLog entry, and automatically issue a key-rotation bootstrap token to the affected developer for self-service validation (Cryptographic Key Lifecycle Grace Period).
15. WHEN a developer redeems a valid bootstrap token with a renewed GPG key within the grace window configured in the Policy (default: 72 hours), THE Inspector SHALL clear the `WARM LOCK` flag, re-verify the commit, and record the resolution in the EventLog; IF the grace window expires without redemption, THEN THE Inspector SHALL escalate the case to the SUPER_ADMIN channel as `identity_spoofing_detected=True`.

---

### Requirement 11: Human-in-the-Loop Escalation

**User Story:** As a developer, I want to be notified and presented with options when PANTHEON cannot confidently classify a threat, so that I can make an informed decision without the system auto-blocking ambiguous cases.

#### Acceptance Criteria

1. WHEN the Auditor Agent assigns a final Severity of `medium` to a threat finding, THE Inspector SHALL classify the case as ambiguous and trigger a human-in-the-loop escalation.
2. WHEN an escalation is triggered, THE Inspector SHALL send a notification to the configured escalation target — operator, developer, or webhook endpoint — containing the threat report, matched evidence, Severity classification, and a list of available response options.
3. THE available response options presented in an escalation notification SHALL include at minimum: allow, block, and flag for further review.
4. WHEN a human response is received for an escalation, THE Inspector SHALL apply the chosen action to the pending Payload within 2 seconds of receiving the response and record the decision in the EventLog.
5. WHILE awaiting a human response, THE Gateway SHALL hold the Payload in a pending queue and SHALL NOT forward it to the target service.
6. IF no human response is received within the escalation timeout configured in the Policy, with a default of 60 seconds, THEN THE Inspector SHALL apply the default escalation policy — block or allow — as configured, and record the timeout action in the EventLog.
7. THE Inspector SHALL support escalation delivery via email, Slack webhook, and HTTP POST to a configured endpoint.

---

## Shared Infrastructure

### Requirement 12: Control Plane

**User Story:** As an operator, I want a management layer with a dashboard and CLI for monitoring activity, configuring policies, and responding to incidents, so that I can oversee PANTHEON deployments across all integrated Clients.

#### Acceptance Criteria

1. THE Control Plane SHALL expose a read-only dashboard interface displaying active Client connections, recent Signals, Severity distribution, and pipeline agent status.
2. WHEN a new Signal is recorded in the EventLog, THE Control Plane SHALL reflect the updated Signal count and Severity distribution in the dashboard within 5 seconds.
3. THE Control Plane SHALL provide a CLI that supports the following operations: load Policy, reload Policy, list active Clients, query EventLog by time range and Severity, and trigger a manual scan.
4. WHEN an operator updates a Policy via the Control Plane, THE Inspector SHALL apply the updated Policy to all subsequent Payloads within 5 seconds and confirm the update in the EventLog.
5. IF an operator submits a malformed Policy via the Control Plane, THEN THE Control Plane SHALL return a descriptive validation error identifying the invalid field, reject the update, and leave the active Policy unchanged.
6. THE Control Plane SHALL enforce authentication for all write operations using an API key or token specified in the Control Plane configuration.
7. WHEN an escalation is pending, THE Control Plane dashboard SHALL display the pending case with the threat report and available response options, and SHALL allow the operator to submit a response.

---

### Requirement 13: Control Plane Access Control & FastAPI Ingestion Core

**User Story:** As a Super Admin, I want role-based access control with cryptographic session validation, automatic data masking, dual authorization for sensitive operations, and consolidated HTTP transmission pipeline handling inside `control_plane/rbac.py` and `control_plane/api/jobs.py`, so that no single operator has unrestricted access to all system data or the ability to unilaterally override threat classifications.

#### Acceptance Criteria

1. THE Control Plane SHALL enforce two built-in roles — SUPER_ADMIN and ADMIN — where SUPER_ADMIN has visibility over all HVP Severity levels (CRITICAL, HIGH, MEDIUM, LOW) and ADMIN is restricted to MEDIUM and LOW HVP Severity levels only.
2. WHEN an ADMIN session queries the EventLog, THE Control Plane SHALL filter out all entries associated with HVP profiles of Severity weight CRITICAL or HIGH before returning results to the ADMIN client.
3. WHEN an event with HVP Severity weight CRITICAL is written to the EventLog, THE Inspector SHALL store two versions of the Payload: an AES-encrypted version accessible only by SUPER_ADMIN, and a regex-masked version with sensitive patterns replaced by `[REDACTED]` accessible by ADMIN.
4. THE sensitive data patterns subject to masking SHALL include at minimum: email addresses, 16-digit card numbers, credential key-value pairs (password=, token=, api_key=), and Social Security Number patterns.
5. WHEN a SUPER_ADMIN requests a CRITICAL-level Payload, THE Control Plane SHALL decrypt and return the original text using the SUPER_ADMIN decryption key; WHEN an ADMIN requests the same Payload, THE Control Plane SHALL return only the masked version.
6. WHEN an ADMIN submits a request to change a Signal's Severity to a value lower than the current Severity, THE Control Plane SHALL create a SeverityChangeRequest record with status `pending_approval` in the database and SHALL NOT apply the change immediately.
7. WHEN a SeverityChangeRequest is created, THE Control Plane SHALL notify all active SUPER_ADMIN sessions via the dashboard and SHALL display the request with the original Severity, the requested Severity, the requesting ADMIN identifier, and the stated reason.
8. WHEN a SUPER_ADMIN approves a SeverityChangeRequest, THE Control Plane SHALL apply the Severity change to the Signal, update the SeverityChangeRequest status to `approved`, record the SUPER_ADMIN identifier and approval timestamp in the EventLog, and notify the requesting ADMIN.
9. IF a SUPER_ADMIN rejects a SeverityChangeRequest, THEN THE Control Plane SHALL update the status to `rejected`, leave the Signal Severity unchanged, and record the rejection with reason in the EventLog.
10. WHEN a user authenticates to the Control Plane, THE Control Plane SHALL issue a SessionToken containing the session ID, user ID, role, issued-at timestamp, and expiry timestamp, signed with an HMAC-SHA256 signature using a role-specific signing key stored only in server memory.
11. WHEN the Control Plane validates a SessionToken, THE Control Plane SHALL recompute the HMAC-SHA256 signature using the role extracted from the token and the corresponding in-memory signing key; IF the computed signature does not match the provided signature, THEN THE Control Plane SHALL reject the request with an authentication error.
12. THE SessionToken SHALL expire after a configurable duration, defaulting to 3600 seconds; IF a request arrives with an expired SessionToken, THEN THE Control Plane SHALL reject it and require re-authentication.
13. THE SUPER_ADMIN role signing key SHALL be a minimum of 512 bits and THE ADMIN role signing key SHALL be a minimum of 256 bits; both keys SHALL be generated at Control Plane startup and stored exclusively in process memory, never written to disk or database.
14. IF an ADMIN session token is presented for an operation that requires SUPER_ADMIN privileges, THEN THE Control Plane SHALL reject the request, log the unauthorized access attempt in the EventLog with the session ID and attempted operation, and return an authorization error to the client.

---

### Requirement 14: Real-Time Event Pipeline

**User Story:** As a Control Plane operator, I want threat events pushed to the dashboard instantly via WebSocket the moment a background scan produces a finding, so that I can respond to high-severity threats without polling or page refresh.

#### Acceptance Criteria

1. WHEN the Auditor Agent produces a threat report, THE Inspector SHALL invoke a post-audit hook that writes the EventLog entry and publishes the event to the EventBus within the same async execution context, without blocking the pipeline worker from processing the next queued CodeChunk.
2. THE EventLog entry written by the post-audit hook SHALL conform to a single-line JSON schema containing at minimum: ts (ISO 8601 UTC), event_id, target_hvp, hvp_multiplier, asset_type, asset_ext, source_path_hash (SHA-256 of the original path), relative_masked_path (display path of the form [root]/..., never absolute), severity_level, base_score, final_score, threat_detected (array), matched_patterns (array), detection_source, layer_passed, action_taken, patch_generated, agent_chain (array), pipeline_duration_ms, masked_for_admin, session_id, and operator_id.
3. THE source_path_hash field in the EventLog entry SHALL contain only the SHA-256 hash of the original file path; THE Inspector SHALL never write the raw file path to the EventLog.
4. THE EventBus SHALL operate as a separate asyncio task running a continuous dispatch loop; WHEN an event is published to the EventBus queue, THE dispatch loop SHALL process and broadcast it without blocking the pipeline worker that published it.
5. WHEN the EventBus dispatch loop processes an event with severity_level `high` or `critical` and target_hvp other than CEO, THE WebSocketManager SHALL broadcast the ADMIN-sanitized event payload to all active ADMIN and SUPER_ADMIN WebSocket connections.
6. WHEN the EventBus dispatch loop processes an event with severity_level `high` or `critical` and target_hvp CEO, THE WebSocketManager SHALL broadcast only to active SUPER_ADMIN WebSocket connections and SHALL NOT deliver any version of the event to ADMIN connections.
7. WHEN the EventBus dispatch loop processes an event with severity_level `medium` and target_hvp other than CEO, THE WebSocketManager SHALL broadcast a summary event payload (severity level, target HVP role, detected threat names, action taken, final score, timestamp — no raw Payload content) to all active ADMIN and SUPER_ADMIN WebSocket connections; WHEN target_hvp is CEO, THE WebSocketManager SHALL broadcast the summary only to active SUPER_ADMIN WebSocket connections.
8. WHEN the EventBus dispatch loop processes an event with severity_level `low`, THE Inspector SHALL write the entry to the EventLog only and SHALL NOT push a WebSocket notification.
9. THE Control Plane SHALL expose a WebSocket endpoint that accepts a SessionToken query parameter; IF the SessionToken is invalid or expired, THEN THE Control Plane SHALL close the WebSocket connection with code 4001 before accepting any messages.
10. WHEN a validated WebSocket connection is established, THE WebSocketManager SHALL register the connection under the role extracted from the SessionToken and SHALL silently remove the connection from the registry if the connection drops.
11. WHEN the WebSocketManager broadcasts an event to ADMIN connections, THE WebSocketManager SHALL apply the same data masking rules defined in Requirement 13 AC#3 and AC#4 before sending, ensuring ADMIN clients never receive unmasked CRITICAL Payload content via WebSocket.
12. WHEN a connected Control Plane UI client receives a WebSocket event with severity_level `high`, `critical`, or `medium`, THE client SHALL display a push notification popup containing at minimum: severity level, target HVP role, detected threat names, action taken, final score, and timestamp, without requiring a page reload.
13. THE post-audit hook SHALL write the EventLog entry using asynchronous file I/O so that disk write latency does not block the asyncio event loop.
14. THE end-to-end latency from Auditor Agent completion to WebSocket message delivery at the connected client SHALL not exceed 2 seconds under normal operating conditions with up to 50 concurrent WebSocket connections.

---

### Requirement 15: SDK-to-Control-Plane Async Pipeline

**User Story:** As a platform engineer, I want CodeChunks that pass the three-layer filter to be submitted to the Control Plane asynchronously without blocking the SDK background worker, so that the client application experiences no additional latency from the scan submission process.

#### Acceptance Criteria

1. WHEN a CodeChunk passes all three filter layers in the SDK, THE SDK forensic extraction module (`sdk/forensics.py`) SHALL invoke the forensic extraction step (`ForensicExtractor`) to build the ForensicContext, MaskedPayload, and EvidenceHash before preparing the submission payload defined in `shared/models.py`, and SHALL delete the original source_text and file_source references from memory immediately after extraction completes. All validation structures during network transits SHALL be governed by centralized Pydantic data schemas in `shared/models.py` and configuration variables in `shared/policy.py`.
2. THE submission payload sent from the SDK to the Control Plane SHALL contain: file_path_hash (SHA-256 of the absolute path), relative_masked_path (e.g. [root]/src/auth.py), function_name, match_reason, asset_owner_role, client_id, forensic_context, masked_payload, and evidence_hash; THE SDK SHALL NOT include the original source_text or the absolute raw file_path in the submission payload under any circumstance (Zero-Knowledge Privacy). The forensic_context itself SHALL contain no absolute path — only file_path_hash, relative_masked_path, line coordinates, and git_commit_hash.
3. WHEN the SDK submits a CodeChunk to the Control Plane via HTTP POST, THE Control Plane SHALL respond with a job_id and status `queued` within 50 milliseconds of receiving the request, without waiting for pipeline execution to complete.
4. WHEN the Control Plane HTTP endpoint receives a valid submission, THE Control Plane SHALL place the job onto the SERVER_SCAN_QUEUE using a non-blocking asyncio.Queue put operation; IF the SERVER_SCAN_QUEUE is at maximum capacity (default: 5,000 entries), THEN THE Control Plane SHALL return HTTP 503 to the SDK.
5. WHEN the SDK receives HTTP 503 from the Control Plane, THE SDK SHALL re-queue the CodeChunk at the front of the local ScanQueue and apply a back-off delay of 30 seconds before retrying.
6. WHEN the SDK receives a rate-limit response (HTTP 429) from the Control Plane, THE SDK SHALL re-queue the CodeChunk and pause the submission worker for the duration specified in the Retry-After response header, defaulting to 60 seconds if the header is absent.
7. THE SDK submission worker SHALL use a persistent HTTP connection pool with a maximum of 10 concurrent connections to the Control Plane endpoint, reusing connections across multiple submissions to avoid TCP handshake overhead.
8. WHEN the SDK derives identity material for a CodeChunk, THE SDK SHALL maintain a machine-local index mapping file_path_hash to the absolute path on the developer machine; THE SDK SHALL transmit only the hash (Detached Metadata Indexing) and SHALL never upload the index or any absolute path to the Control Plane.
9. WHEN an operator or worker requires the physical local path (dashboard drill-down, patch application), inverse resolution from file_path_hash SHALL execute only on the developer machine via the stateful local SDK agent; THE Control Plane database SHALL remain completely blind to the actual directory tree.
10. THE Control Plane SHALL implement a Per-User Server-Side Throttling and Rate Limiting Engine wrapping the `SERVER_SCAN_QUEUE` and Pipeline Worker pool. THE Control Plane SHALL track transaction volumes per unique client ID / device signature or user ID token; THE Control Plane SHALL enforce a strict rate ceiling of maximum N LLM-orchestrated CrewAI Pipeline invocations per minute per active user (configurable in Policy, defaulting to 10 RPM per user); IF a client's submission volume or bulk modification burst exceeds this boundary ceiling, THE Control Plane SHALL automatically throttle the incoming stream, return HTTP 429 with a `Retry-After` header to the SDK, and suspend overflowing jobs in a memory-bounded per-client holding queue (`USER_SUSPENDED_QUEUE`) without triggering unthrottled LLM calls or Denial of Wallet attacks.
11. WHEN multiple separate `ForensicContext` payloads are submitted simultaneously by the same user context / client ID within a tight window frame of < 2 seconds (such as bulk auto-formatting executions), THE `SERVER_SCAN_QUEUE` batching manager SHALL pool the incoming inputs and execute a Data Concatenation/Batching Routine: THE batching manager SHALL pack the isolated `masked_payload` code chunks into a single clustered context window payload array (`BatchedSubmissionPayload`) before feeding it to a single CrewAI Pipeline worker execution, optimizing LLM context usage and preventing prompt spamming.

---

### Requirement 16: Forensic Evidence Preservation

**User Story:** As a security investigator, I want every threat detection event to include tamper-evident forensic metadata (relative masked path, line coordinates, git commit hash) and a masked code snippet extracted by `sdk/forensics.py` and serialized via `shared/models.py`, so that I can verify the integrity of a finding and locate the exact source location without the system storing raw source code.

#### Acceptance Criteria

1. WHEN the SDK builds a ForensicContext for a CodeChunk, THE SDK SHALL extract the function's start and end line numbers by parsing the full file source using AST, compute file_path_hash as SHA-256 of the absolute path, derive relative_masked_path by stripping the machine-specific prefix to the form `[root]/<repo-relative-path>`, and SHALL retrieve the git commit hash of the last commit that modified the file using `git log -1 --format=%H`; IF git is unavailable, THE SDK SHALL set git_commit_hash to null without failing the submission. THE ForensicContext SHALL contain no absolute raw file path.
2. WHEN the SDK builds a MaskedPayload, THE SDK SHALL apply regex substitution to replace at minimum: credential key-value pairs (password=, secret=, api_key=, token= followed by a quoted value), base64 strings of 32 or more characters, and 16-digit card number patterns, replacing each match with a role-labelled redaction placeholder that preserves the variable name but hides the value.
3. WHEN the SDK computes the EvidenceHash, THE SDK SHALL compute SHA-256 of the original, unmasked source_text encoded as UTF-8 before any masking or deletion is applied.
4. THE ForensicContext, MaskedPayload, and EvidenceHash SHALL all be computed within the same synchronous extraction step before the submission payload is assembled, so that no partial forensic data is submitted to the Control Plane.
5. WHEN the Pipeline Worker builds a log entry for a completed pipeline job, THE log entry SHALL include the forensic_context object, masked_payload string, and evidence_hash string received from the SDK submission payload.
6. THE Control Plane log entry SHALL NOT store the original source_text or any absolute raw file path at any point; WHEN the job dict is removed from the SERVER_SCAN_QUEUE after pipeline completion, THE Pipeline Worker SHALL release all references to the job dict to allow garbage collection.
7. WHEN a security team member queries a threat event via the Control Plane, THE Control Plane SHALL return the forensic_context, masked_payload, and evidence_hash fields so that the investigator can verify the finding by computing SHA-256 of the suspected source code and comparing it to the stored evidence_hash.
8. THE Pipeline Worker SHALL first invoke the Sentry Gateway triage; WHEN the Sentry Gateway determines that a CodeChunk does not require deep analysis, THE Pipeline Worker SHALL build a log entry with the Sentry Gateway's triage result and SHALL NOT invoke the CrewAI Pipeline, preserving LLM token quota for genuinely suspicious chunks.
9. WHEN the Sentry Gateway flags a CodeChunk as suspicious, THE Pipeline Worker SHALL run CrewAI Pipeline execution using asyncio.get_event_loop().run_in_executor() to offload the synchronous CrewAI kickoff call to a thread pool, preventing the Pipeline Worker from blocking the asyncio event loop during Gemini API calls or Semgrep execution.
10. THE Pipeline Worker pool SHALL use a configurable asyncio.Semaphore to limit the number of concurrent CrewAI Pipeline executions (default: 3), preventing simultaneous Gemini API calls from exceeding the free-tier rate limit.
