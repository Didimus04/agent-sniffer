# Design Document — PANTHEON (agent-sniffer)

## Overview

PANTHEON is a code and runtime security platform composed of two operating divisions — **ARES** (offensive, perimeter interception) and **ARGUS** (defensive, continuous background surveillance) — unified under a shared Control Plane, EventLog, EventBus, SDK, and Policy layer.

ARES intercepts Payloads at the perimeter using a sequential four-agent CrewAI pipeline: Parser → Static Scanner → Red Teamer → Auditor. ARGUS monitors assets continuously using OS-level file system events, a three-layer filter, and HVP-aware threat enrichment.

The shared infrastructure provides a FastAPI-based Control Plane with real-time WebSocket delivery, RBAC-enforced session management, forensic evidence preservation, and a SIEM-compatible append-only EventLog.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              PANTHEON                                      │
│                                                                            │
│  ┌──────────────────────────┐    ┌──────────────────────────────────────┐ │
│  │      ARES Division        │    │          ARGUS Division              │ │
│  │                          │    │                                      │ │
│  │  Client App              │    │  watchdog EventHandler               │ │
│  │     │ SDK.submit()       │    │     │ FileSystemEvent                │ │
│  │     ▼                    │    │     ▼                                │ │
│  │  Gateway (intercept)     │    │  SDK Pre-Filter Module               │ │
│  │     │                    │    │  (folder/ext/token filter)           │ │
│  │     ▼                    │    │     │ FilterResult                   │ │
│  │  Inspector               │    │     ▼                                │ │
│  │  ┌──────────────────┐    │    │  ScanQueue (asyncio.Queue, bounded)  │ │
│  │  │ Parser Agent     │    │    │     │                                │ │
│  │  │ Static Scanner   │    │    │  Worker Pool (3 async workers)       │ │
│  │  │   Semgrep        │    │    │  ┌───────────────────────────┐       │ │
│  │  │   Joern+GNN      │    │    │  │ Layer 1: Extension Filter │       │ │
│  │  │ Red Teamer Agent │    │    │  │ Layer 2: SHA-256 Hash Gate│       │ │
│  │  │   ChromaDB RAG   │    │    │  │ Layer 3: AST/Regex Filter │       │ │
│  │  │   Sandbox DAST   │    │    │  └───────────────────────────┘       │ │
│  │  │ Auditor Agent    │    │    │     │ CodeChunk                      │ │
│  │  └──────────────────┘    │    │     ▼                                │ │
│  │     │ ThreatReport       │    │  HVP Contextual Validator            │ │
│  │     ▼                    │    │     │                                │ │
│  │  Auto-Block / Auto-Patch │    │     ▼                                │ │
│  │  / Escalation            │    │  Inspector (shared pipeline)         │ │
│  └──────────────────────────┘    └──────────────────────────────────────┘ │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                    Shared Infrastructure                             │  │
│  │                                                                      │  │
│  │  EventLog (JSONL, append-only)   EventBus (asyncio.Queue pub/sub)   │  │
│  │  HashDB (SQLite)                 WebSocketManager                   │  │
│  │  ChromaDB (vector store)         Policy (operator config)           │  │
│  │                                                                      │  │
│  │  ┌──────────────────────────────────────────────────────────────┐   │  │
│  │  │                    Control Plane (FastAPI)                    │   │  │
│  │  │  REST endpoints + WebSocket + RBAC + SessionToken             │   │  │
│  │  │  SUPER_ADMIN / ADMIN roles                                    │   │  │
│  │  └──────────────────────────────────────────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Components and Interfaces

### ARES Division

#### SDK

- Entry point for all client integrations.
- Exposes `submit(payload, policy) -> ThreatReport` (sync and async).
- Implements context manager (`__aenter__` / `__aexit__`) to release pipeline resources.
- In mobile/lightweight mode, stubs out local GNN and RAG, forwarding to remote Inspector via HTTP.
- On initialization with invalid Policy, raises `ConfigurationError` before any agent is instantiated.

#### Gateway

- Sits between SDK and target service.
- Receives the auto-block decision from Inspector and returns `PolicyBlockError` to the caller.
- Maintains a pending queue for Payloads awaiting human escalation response (Requirement 11).

#### Inspector

- Orchestrates the four-agent CrewAI crew.
- Applies Policy to routing decisions (block / patch / escalate per Severity).
- Owns the post-audit hook: writes EventLog entry + publishes to EventBus atomically in the same async context.
- Enforces the 30-second pipeline timeout for Payloads up to 1 MB.

#### Parser Agent (CrewAI Agent)

- Normalizes encoding (UTF-8), detects language, extracts structured AST representation.
- Outputs a `ParsedArtifact`: `{language, ast_json, normalized_text, metadata}`.

#### Static Scanner Agent (CrewAI Agent)

- Runs Semgrep via subprocess with configured rule sets (local path or registry ID).
- Invokes Joern via subprocess to generate CPG; passes node/edge embeddings to the GNN inference component.
- Aggregates Semgrep Signals + GNN anomaly score into `ScanResult`.
- On Semgrep non-zero exit: logs `EventLog` entry, sets `scan_status=inconclusive`, continues.
- On Joern timeout (20 s): logs timeout, continues with Semgrep findings only.

#### Red Teamer Agent (CrewAI Agent)

- Queries ChromaDB with embedding derived from Payload characteristics; retrieves top-K docs (default K=5).
- Calls Gemini API with retrieved docs + Payload summary.
- If Payload is classified suspicious by static scan or RAG: spawns sandbox execution.
- Outputs `RedTeamFindings`: `{rag_results, gemini_summary, sandbox_artifacts}`.

#### Auditor Agent (CrewAI Agent)

- Aggregates all prior findings.
- Assigns final `Severity` (`low` / `medium` / `high` / `critical`).
- Produces `ThreatReport`: `{severity, matched_patterns, remediation_summary, signals, agent_chain}`.

#### Sandbox

- Implemented as an ephemeral subprocess in a separate OS namespace (Linux: `unshare`, macOS/Windows: containerized process).
- Enforces: no outbound network, write only to scratch dir, process spawn limit.
- 10-second hard timeout via `asyncio.wait_for`.
- Collects: stdout, stderr, strace output, exit code.

#### GNN Inference Component

- Loaded once at startup from a pre-trained model file.
- Accepts node/edge embeddings from Joern CPG.
- Returns an `anomaly_score: float` in [0, 1].
- If `anomaly_score > policy.anomaly_threshold`: attaches Signal with Severity `high`.

---

### ARGUS Division

#### SDK Pre-Filter Module

See dedicated section below.

#### EventHandler (watchdog)

- Registers `PantheonEventHandler` with a watchdog `Observer`.
- Handles `on_modified` events; ignores directory events.
- Runs in a separate thread; bridges to asyncio event loop via `asyncio.run_coroutine_threadsafe`.
- Also listens for Git webhook POST on `/webhook/git`; extracts changed file paths from diff payload and enqueues them.

#### ScanQueue

- `asyncio.Queue(maxsize=policy.scan_queue_depth)` (default: 1,000).
- On overflow: oldest entry is discarded (custom `AsyncBoundedQueue` wrapping `Queue`); operator alert emitted via Control Plane WebSocket.

#### Worker Pool

- Three `asyncio.Task` workers (configurable) consuming from `ScanQueue`.
- Each worker applies three-layer filtration before invoking CrewAI pipeline.
- Workers use `asyncio.Semaphore(3)` to limit concurrent Gemini calls.

#### Three-Layer Filter

**Layer 1 — Extension Filter**

- Allowlist: `.py .js .ts .java .go .rs .c .cpp` (configurable in Policy).
- File not in allowlist → discard + `EventLog` skip entry.

**Layer 2 — SHA-256 Hash Gate**

- AST-parse the file to extract individual function bodies.
- For each function: compute `SHA-256(function_body)`.
- Query `HashDB` (SQLite); forward only functions with a changed hash.
- All hashes unchanged → discard entire event.

**Layer 3 — AST/Regex Criticality Filter**

- Extract functions matching: auth patterns, crypto ops, DB queries, `eval`/`exec`/`subprocess`, network calls.
- No critical patterns → discard.
- Matching functions promoted to `CodeChunk` objects.

#### HVP Contextual Validator

- After Auditor produces `ThreatReport`, lookup `HVP_Profile` by role (git author email hash → path match → UNKNOWN).
- Apply `priority_multiplier` to base signal score.
- Apply 20-point confidence boost (capped at 100) if threat vector matches profile.
- Route escalation via configured channels (SMS / Slack / email / Control Plane) if final score ≥ `auto_escalation_threshold`.
- Special rules: `HRD_RECRUITMENT` → always route to sandbox regardless of Layer 3; `HVP_CALENDAR` → enable OSINT enrichment (attendee domain analysis).

---

### Shared Infrastructure

#### Policy

- Dataclass / Pydantic model loaded from YAML or JSON at startup.
- Contains: agent config, Semgrep rule sets, GNN model path, ChromaDB settings, Gemini API key, HVP_Profiles, severity routing (block/patch/escalate), scan queue depth, worker count, Gemini RPM limit, escalation targets, session TTL, signing key lengths.
- Hot-reload via Control Plane; Inspector applies within 5 seconds.

#### HashDB (SQLite)

- Table: `function_hashes(file_path_hash TEXT, function_name TEXT, sha256 TEXT, updated_at INTEGER)`.
- `file_path_hash` stores SHA-256 of the original path, never raw path.
- Updated after each successful pipeline execution for the processed function.

#### EventLog (SIEM JSONL)

- Append-only file; each line is a single-line JSON object.
- Written via async file I/O (`aiofiles`).
- Schema: see Data Models section.
- `source_path_hash` stores SHA-256 of original path; raw path is never written.
- Author email stored only as SHA-256 hash.

#### EventBus

- `asyncio.Queue`-based pub/sub.
- Single dispatch task (`asyncio.create_task`) running a continuous loop.
- Pipeline workers publish events without awaiting delivery.
- Dispatch loop reads events and calls `WebSocketManager.broadcast()`.

#### WebSocketManager

- Maintains two connection registries: `{SUPER_ADMIN: set[WebSocket], ADMIN: set[WebSocket]}`.
- Routing rules (Requirement 14 AC#5/#6):
  - Severity `high`/`critical`, `target_hvp != CEO` → broadcast to ADMIN + SUPER_ADMIN (ADMIN-masked payload).
  - Severity `high`/`critical`, `target_hvp == CEO` → SUPER_ADMIN only.
  - Severity `medium`/`low` → EventLog only, no WebSocket push.
- Applies data masking (Requirement 13 AC#3/#4) before sending to ADMIN connections.
- Silently removes dropped connections on `WebSocketDisconnect`.

#### Control Plane (FastAPI)

- REST API + WebSocket endpoint.
- Authentication: HMAC-SHA256 `SessionToken` (see Security section).
- RBAC enforced at endpoint level via dependency injection.
- Exposes dashboard data, CLI-equivalent REST ops, escalation response endpoint.

---

## Data Flow Diagrams

### ARES — Runtime Interception Flow

```
Client
  │── SDK.submit(payload, policy)
  │
  ▼
Gateway
  │── enqueue to Inspector
  │
  ▼
Inspector
  │
  ├── Parser Agent
  │     normalize encoding → extract AST → ParsedArtifact
  │
  ├── Static Scanner Agent
  │     Semgrep(artifact) → Signals[]
  │     Joern(artifact) → CPG → GNN → anomaly_score → Signal?
  │     → ScanResult
  │
  ├── Red Teamer Agent
  │     embed query → ChromaDB(top-K docs)
  │     Gemini(docs + summary) → threat_summary
  │     suspicious? → Sandbox(payload) → artifacts
  │     → RedTeamFindings
  │
  ├── Auditor Agent
  │     aggregate all findings → assign Severity → ThreatReport
  │
  └── Post-Audit Hook
        ├── write EventLog entry (async file I/O)
        └── publish to EventBus
              └── WebSocketManager.broadcast()
  │
  ▼
Inspector routing decision
  ├── Severity critical/high → auto-block or auto-patch (Gemini patch / template fallback)
  ├── Severity medium → human escalation (Gateway holds Payload)
  └── Severity low → allow
  │
  ▼
ThreatReport returned to SDK caller
```

### ARGUS — Background Scan Flow

```
File System Change
  │
  ▼
watchdog EventHandler (thread)
  │── PantheonPreFilter.pre_filter(path)
  │     folder exclusion → extension check → tokenize (len > 60)
  │── passed? → asyncio.run_coroutine_threadsafe(ScanQueue.put(...))
  │
  ▼
ScanQueue (asyncio.Queue, bounded=1000)
  │
  ▼
Worker (one of 3 async workers)
  │
  ├── Layer 1: Extension Filter
  │     allowlist check → discard if not in allowlist
  │
  ├── Layer 2: SHA-256 Hash Gate
  │     AST parse → per-function SHA-256 → compare with HashDB
  │     → forward only changed functions
  │
  ├── Layer 3: AST/Regex Criticality Filter
  │     match auth/crypto/db/exec/network patterns
  │     → forward only critical CodeChunks
  │
  ├── HVP Role Resolution
  │     git commit author email SHA-256 → path match → UNKNOWN
  │     → lookup HVP_Profile
  │
  ├── Inspector (CrewAI pipeline — shared with ARES)
  │     SentryAgent (fast triage) → skip if not suspicious
  │     TrafficCodeAnalyzer (deep analysis: Semgrep + RAG + sandbox)
  │     Auditor Agent → ThreatReport
  │
  ├── HVP Contextual Validator
  │     apply priority_multiplier, confidence boost, escalation routing
  │
  └── HashDB update (new SHA-256 for each processed function)
```

### SDK-to-Control-Plane Async Submission Flow

```
SDK Worker (ARGUS background scan)
  │── CodeChunk passes three layers
  │── ForensicExtractor:
  │     AST line numbers + git log -1 → ForensicContext
  │     regex masking → MaskedPayload
  │     SHA-256(original_text) → EvidenceHash
  │── delete original source_text from memory
  │── build SubmissionPayload (no raw path, no source_text)
  │── HTTP POST /api/v1/jobs  (connection pool, max 10 conns)
  │
  ▼
Control Plane HTTP endpoint
  │── validate SessionToken
  │── SERVER_SCAN_QUEUE.put_nowait(job)
  │     → full? → return HTTP 503
  │── return {job_id, status: "queued"} within 50ms
  │
  ▼
Server-side Worker Pool (asyncio.Semaphore(3))
  │── run_in_executor → SentryAgent → TrafficCodeAnalyzer → Auditor
  │── post-audit hook → EventLog + EventBus
```

---

## Tech Stack Decisions

| Concern         | Choice                                        | Rationale                                                                  |
| --------------- | --------------------------------------------- | -------------------------------------------------------------------------- |
| Language        | Python 3.11+                                  | CrewAI, watchdog, Semgrep Python bindings, asyncio native support          |
| Agent Framework | CrewAI                                        | Multi-agent orchestration with sequential crews; built-in tool support     |
| LLM             | Gemini API (free tier)                        | Cost-effective; 14 RPM free tier managed via token-bucket rate limiter     |
| Vector DB       | ChromaDB                                      | Embedded, no separate server; supports pre-populated CVE/OWASP collections |
| SAST            | Semgrep                                       | Broad language support; extensible rule sets; registry + local rules       |
| CPG             | Joern                                         | Gold standard for AST+CFG+PDG; supports Python, JS, TS, Java               |
| File Watcher    | watchdog                                      | Cross-platform inotify/FSEvents/ReadDirectoryChangesW; Python-native       |
| Async           | asyncio                                       | Python standard; Queue-based concurrency; no external broker needed        |
| HTTP/WS         | FastAPI + WebSockets                          | Async-first; Pydantic validation; WebSocket support built-in               |
| Crypto          | cryptography (Fernet/AES-256), hmac, hashlib  | Standard library + well-audited cryptography package                       |
| Storage         | SQLite (HashDB), append-only JSONL (EventLog) | Zero-config; JSONL is SIEM-compatible and grep-friendly                    |
| Async file I/O  | aiofiles                                      | Non-blocking EventLog writes; avoids blocking asyncio event loop           |
| PBT library     | Hypothesis                                    | Industry standard for Python property-based testing                        |

---

## SDK Pre-Filter Module

### Part 1: Deterministic Pre-Filter and Boundary Rules

#### Objective

Filter file system events before any CPU-intensive or LLM analysis, using pure Python deterministic rules with zero external dependencies.

#### Folder Exclusion Rules

Excluded folders (absolute ignore, no processing):

- `node_modules/`, `venv/`, `.venv/`, `.git/`, `assets/`, `dist/`, `build/`, `__pycache__/`, `.tox/`, `coverage/`

Excluded extensions (non-code files):

- `.md`, `.txt`, `.json`, `.yaml`, `.yml`, `.lock`, `.log`, `.png`, `.jpg`, `.svg`, `.ico`, `.pdf`, `.csv`

Logic: Check both folder path AND extension before any further processing. If either matches the exclusion list, discard immediately.

#### Length Boundary Tokenizer

Objective: Minimize CPU usage by filtering trivial tokens before deeper analysis.

Rules:

- Tokenize file content into single string tokens (split on whitespace).
- Only tokens with continuous character length > 60 (no spaces) proceed to further analysis.
- Tokens ≤ 60 characters are passed through (ignored/cleared) immediately.
- Rationale: Meaningful secrets, encoded payloads, and long identifiers exceed 60 chars. Short tokens (variable names, keywords) are not worth analyzing.

#### Logic Flow

```
FileSystemEvent (watchdog)
    ↓
[Folder Exclusion Check]   → excluded? → discard, log skip
    ↓
[Extension Filter]         → non-code? → discard, log skip
    ↓
[Read file content]
    ↓
[Length Boundary Tokenizer]
    tokenize → split on whitespace
    filter: keep only tokens where len(token) > 60
    ↓
[Pass filtered tokens to Layer 2 (SHA-256 Hash Gate)]
```

#### Input/Output Schema

- Input: `FileSystemEvent(src_path: str, event_type: str)`
- Output: `FilterResult(passed: bool, tokens: list[str], skip_reason: str | None)`

`skip_reason` values: `"excluded_folder"`, `"excluded_extension"`, `"read_error"`, `"no_tokens_above_threshold"`, `None` (passed).

#### Core Code Snippet

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
import asyncio

EXCLUDED_FOLDERS: frozenset[str] = frozenset({
    "node_modules", "venv", ".venv", ".git",
    "assets", "dist", "build", "__pycache__",
    ".tox", "coverage",
})

EXCLUDED_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".txt", ".json", ".yaml", ".yml",
    ".lock", ".log", ".png", ".jpg", ".svg",
    ".ico", ".pdf", ".csv",
})

MIN_TOKEN_LENGTH: int = 60

@dataclass
class FilterResult:
    passed: bool
    tokens: list[str] = field(default_factory=list)
    skip_reason: str | None = None

def is_excluded_path(path: str) -> bool:
    parts = Path(path).parts
    return any(part in EXCLUDED_FOLDERS for part in parts)

def is_excluded_extension(path: str) -> bool:
    return Path(path).suffix.lower() in EXCLUDED_EXTENSIONS

def tokenize_and_filter(content: str) -> list[str]:
    return [
        token for token in content.split()
        if len(token) > MIN_TOKEN_LENGTH
    ]

def pre_filter(event_path: str) -> FilterResult:
    if is_excluded_path(event_path):
        return FilterResult(passed=False, skip_reason="excluded_folder")
    if is_excluded_extension(event_path):
        return FilterResult(passed=False, skip_reason="excluded_extension")
    try:
        content = Path(event_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FilterResult(passed=False, skip_reason="read_error")
    tokens = tokenize_and_filter(content)
    if not tokens:
        return FilterResult(passed=False, skip_reason="no_tokens_above_threshold")
    return FilterResult(passed=True, tokens=tokens)

class PantheonEventHandler(FileSystemEventHandler):
    def __init__(self, scan_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        self._queue = scan_queue
        self._loop = loop

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return
        result = pre_filter(event.src_path)
        if result.passed:
            asyncio.run_coroutine_threadsafe(
                self._queue.put({"path": event.src_path, "tokens": result.tokens}),
                self._loop,
            )
```

---

## API Design (FastAPI Endpoints)

### Authentication

All endpoints except `/auth/token` require a valid `SessionToken` in the `Authorization: Bearer <token>` header.

### Endpoints

#### Authentication

```
POST /auth/token
  Body: {username: str, password: str}
  Response: {session_token: str, expires_at: int}
  Auth: none
```

#### Policy Management

```
POST /api/v1/policy
  Body: Policy (JSON)
  Response: {status: "applied", applied_at: str}
  Auth: SUPER_ADMIN
  Notes: Applied within 5 seconds; returns 422 with field-level errors on malformed input.

GET /api/v1/policy
  Response: Policy (sanitized, no signing keys)
  Auth: SUPER_ADMIN
```

#### Client Management

```
GET /api/v1/clients
  Response: [{client_id, connected_at, scan_mode, status}]
  Auth: ADMIN, SUPER_ADMIN
```

#### EventLog Query

```
GET /api/v1/events
  Query params: ?from=<ISO8601>&to=<ISO8601>&severity=<low|medium|high|critical>&limit=<int>
  Response: [{...EventLogEntry}]
  Auth: ADMIN (filtered to MEDIUM/LOW), SUPER_ADMIN (all)
  Notes: ADMIN receives masked payloads; SUPER_ADMIN receives AES-decrypted payloads for CRITICAL entries.
```

#### Manual Scan

```
POST /api/v1/scan
  Body: {client_id: str, file_path: str}
  Response: {job_id: str, status: "queued"}
  Auth: SUPER_ADMIN
```

#### Job Submission (SDK → Control Plane)

```
POST /api/v1/jobs
  Body: SubmissionPayload
  Response: {job_id: str, status: "queued"}  -- within 50ms
  Auth: SDK client_id + API key
  Notes: Returns HTTP 503 if SERVER_SCAN_QUEUE at capacity.
```

#### Job Status

```
GET /api/v1/jobs/{job_id}
  Response: {job_id, status, severity?, completed_at?}
  Auth: ADMIN, SUPER_ADMIN
```

#### Escalation Response

```
POST /api/v1/escalations/{escalation_id}/respond
  Body: {action: "allow" | "block" | "flag"}
  Response: {applied_at: str}
  Auth: ADMIN, SUPER_ADMIN
  Notes: Action applied to pending Payload within 2 seconds.
```

#### Severity Change Request

```
POST /api/v1/signals/{signal_id}/severity-change
  Body: {requested_severity: str, reason: str}
  Response: {request_id: str, status: "pending_approval"}
  Auth: ADMIN

POST /api/v1/severity-change-requests/{request_id}/approve
  Body: {}
  Response: {status: "approved"}
  Auth: SUPER_ADMIN

POST /api/v1/severity-change-requests/{request_id}/reject
  Body: {reason: str}
  Response: {status: "rejected"}
  Auth: SUPER_ADMIN
```

#### WebSocket

```
WS /ws/events?token=<SessionToken>
  Notes:
    - Invalid/expired token → close with code 4001.
    - Validated connections registered under role.
    - Events pushed per routing rules (Requirement 14).
    - ADMIN connections receive masked payloads only.
```

---

## Data Models

### EventLog Entry (SIEM JSONL schema)

Every line in the EventLog is a single-line JSON object conforming to this schema:

```python
@dataclass
class EventLogEntry:
    ts: str                     # ISO 8601 UTC timestamp
    event_id: str               # UUID v4
    target_hvp: str             # HVP role name or "UNKNOWN"
    hvp_multiplier: float       # applied priority multiplier (1.0 if no HVP)
    asset_type: str             # "source_code" | "runtime_payload" | "calendar"
    asset_ext: str              # file extension (e.g. ".py")
    source_path_hash: str       # SHA-256(original_file_path)
    severity_level: str         # "low" | "medium" | "high" | "critical"
    base_score: float           # Auditor base score before multiplier
    final_score: float          # base_score * hvp_multiplier (+ confidence boost)
    threat_detected: list[str]  # list of threat names
    matched_patterns: list[str] # Semgrep rule IDs or GNN pattern names
    detection_source: str       # "perimeter" | "background"
    layer_passed: int           # highest filter layer passed (1, 2, or 3)
    action_taken: str           # "block" | "patch" | "escalate" | "allow"
    patch_generated: bool       # whether a remediation patch was produced
    agent_chain: list[str]      # agent names in execution order
    pipeline_duration_ms: int   # total pipeline wall time
    masked_for_admin: bool      # True if CRITICAL payload was masked
    session_id: str             # session ID of the operator (or "system")
    operator_id: str            # operator identifier (or "system")
    # CRITICAL entries additionally contain:
    # encrypted_payload: str    # AES-256 encrypted, SUPER_ADMIN only
    # masked_payload: str       # regex-masked, ADMIN accessible
```

### ForensicContext

```python
@dataclass
class ForensicContext:
    file_path_hash: str          # SHA-256(original_file_path)
    function_name: str
    start_line: int
    end_line: int
    git_commit_hash: str | None  # SHA-1 from `git log -1 --format=%H`; None if git unavailable
```

### MaskedPayload

The source text of a `CodeChunk` with sensitive values replaced. Replacement format: `<VARIABLE_NAME>=[REDACTED:<TYPE>]`.

Patterns replaced:

- `password=`, `secret=`, `api_key=`, `token=` followed by a quoted value.
- Base64 strings of ≥ 32 characters.
- 16-digit card number patterns.
- Email addresses.
- SSN patterns (`\d{3}-\d{2}-\d{4}`).

### EvidenceHash

`SHA-256` hex digest of the original unmasked `source_text` encoded as UTF-8, computed before any masking or deletion.

### CodeChunk

```python
@dataclass
class CodeChunk:
    file_path_hash: str      # SHA-256(original_file_path)
    function_name: str
    source_text: str         # deleted from memory after ForensicExtractor runs
    match_reason: str        # Layer 3 matched pattern label
    asset_owner_role: str    # resolved HVP role
    client_id: str
```

### SubmissionPayload (SDK → Control Plane)

```python
@dataclass
class SubmissionPayload:
    file_path_hash: str       # SHA-256(original_file_path)
    function_name: str
    match_reason: str
    asset_owner_role: str
    client_id: str
    forensic_context: ForensicContext
    masked_payload: str
    evidence_hash: str
    # source_text and raw file_path are NEVER included
```

### ThreatReport

```python
@dataclass
class ThreatReport:
    severity: str                    # "low" | "medium" | "high" | "critical"
    matched_patterns: list[str]
    remediation_summary: str
    patch_diff: str | None           # populated if auto-patch triggered
    affected_file_path_hash: str
    cve_reference: str | None
    signals: list[Signal]
    agent_chain: list[str]
    pipeline_duration_ms: int
    patch_source: str | None         # "gemini" | "template" | None
```

### Signal

```python
@dataclass
class Signal:
    severity: str             # "low" | "medium" | "high" | "critical"
    pattern_id: str           # Semgrep rule ID or "gnn_anomaly"
    source: str               # "semgrep" | "gnn" | "rag" | "sandbox"
    confidence: float         # [0.0, 1.0]
    description: str
```

### HVP_Profile

```python
@dataclass
class HVP_Profile:
    role: str                           # "CEO" | "LEAD_DEV_DEVOPS" | "HVP_CALENDAR" | "HRD_RECRUITMENT"
    severity_weight: str                # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    priority_multiplier: float          # 2.0 / 1.5 / 1.2 / 1.0
    threat_vectors: list[str]
    monitored_assets: list[str]         # file path patterns or asset identifiers
    escalation_channels: list[str]      # "sms" | "email" | "slack" | "control_plane"
    auto_escalation_threshold: float    # final score threshold for immediate escalation
    email_patterns: list[str]           # regex patterns for git author email matching
    path_patterns: list[str]            # glob patterns for file path matching
```

### SessionToken (in-memory only)

```python
@dataclass
class SessionToken:
    session_id: str
    user_id: str
    role: str               # "SUPER_ADMIN" | "ADMIN"
    issued_at: int          # Unix timestamp
    expires_at: int         # Unix timestamp (issued_at + TTL, default 3600s)
    # signature: HMAC-SHA256(session_id + user_id + role + issued_at + expires_at,
    #                         role_signing_key)
    # Signing keys: SUPER_ADMIN ≥ 512-bit, ADMIN ≥ 256-bit
    # Keys generated at startup, stored only in process memory
```

### SeverityChangeRequest

```python
@dataclass
class SeverityChangeRequest:
    request_id: str
    signal_id: str
    original_severity: str
    requested_severity: str
    requesting_admin_id: str
    reason: str
    status: str             # "pending_approval" | "approved" | "rejected"
    created_at: str
    resolved_at: str | None
    resolved_by: str | None
```

---

## Security Design

### RBAC

Two built-in roles enforced at FastAPI dependency level:

| Role        | EventLog visibility | Payload access | Severity change   | Approve change |
| ----------- | ------------------- | -------------- | ----------------- | -------------- |
| SUPER_ADMIN | All severity levels | AES-decrypted  | N/A               | Yes            |
| ADMIN       | MEDIUM and LOW only | Masked only    | Request (pending) | No             |

### SessionToken Lifecycle

1. User posts credentials to `POST /auth/token`.
2. Control Plane validates credentials, generates `session_id` (UUID v4), computes `HMAC-SHA256(payload, role_key)`.
3. Returns signed token as JWT-like structure.
4. On every request: Control Plane re-derives `role` from token, re-computes HMAC, rejects on mismatch or expiry.
5. Signing keys are generated via `secrets.token_bytes(64)` (SUPER_ADMIN) and `secrets.token_bytes(32)` (ADMIN) at startup; never persisted.

### Data Masking Rules

Applied when writing CRITICAL EventLog entries for ADMIN access, and before WebSocket broadcast to ADMIN connections:

```python
MASKING_PATTERNS = [
    (r'(?i)(password|secret|api_key|token)\s*=\s*["\']?[^"\'\s]+["\']?', r'\1=[REDACTED:CREDENTIAL]'),
    (r'\b[A-Za-z0-9+/]{32,}={0,2}\b', '[REDACTED:BASE64]'),
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[REDACTED:CARD]'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED:EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED:SSN]'),
]
```

AES-256 encryption for CRITICAL payloads uses `cryptography.fernet.Fernet` (AES-128-CBC with HMAC); the SUPER_ADMIN decryption key is stored only in process memory.

### Path and Email Privacy

- Raw file paths are never written to EventLog, HashDB, or SubmissionPayload; only `SHA-256(path)` is stored.
- Git author email is stored only as `SHA-256(email)` in EventLog.
- `EvidenceHash` is stored instead of raw source text.

---

## Async Architecture

### Event Loop Topology

```
Main asyncio event loop
  ├── FastAPI ASGI server (uvicorn)
  ├── EventBus dispatch task (asyncio.create_task)
  ├── ScanQueue worker tasks (3 × asyncio.create_task)
  ├── WebSocketManager broadcast handlers
  └── aiofiles EventLog writer

Threads (bridged via asyncio.run_coroutine_threadsafe)
  ├── watchdog Observer thread (file system events)
  └── CrewAI executor threads (run_in_executor for sync CrewAI kickoff)
```

### Rate Limiting (Gemini API)

Token-bucket rate limiter (default 14 RPM):

- Implemented as an `asyncio.Semaphore` + timestamp check.
- Workers acquire the semaphore before each Gemini call; a background task releases tokens at 14/min.
- On HTTP 429: worker pauses for `Retry-After` duration (default 60 s) and re-queues the `CodeChunk` at the front of `ScanQueue`.

### Concurrency Limits

| Resource                              | Limit                | Mechanism                                              |
| ------------------------------------- | -------------------- | ------------------------------------------------------ |
| Concurrent CrewAI pipelines (server)  | 3                    | `asyncio.Semaphore(3)`                                 |
| SDK HTTP connections to Control Plane | 10                   | `httpx.AsyncClient(limits=Limits(max_connections=10))` |
| Gemini API calls                      | 14 RPM               | Token-bucket `asyncio.Semaphore`                       |
| ScanQueue depth                       | 1,000 (configurable) | `asyncio.Queue(maxsize=N)`                             |
| SERVER_SCAN_QUEUE depth               | 5,000 (configurable) | `asyncio.Queue(maxsize=N)`                             |

### Post-Audit Hook (Non-Blocking)

```python
async def post_audit_hook(threat_report: ThreatReport, job: dict) -> None:
    entry = build_event_log_entry(threat_report, job)
    await event_log.write_async(entry)      # aiofiles, non-blocking
    await event_bus.publish(entry)          # asyncio.Queue.put_nowait, non-blocking
    # returns immediately; dispatch task handles WebSocket broadcast
```

---

## Correctness Properties

_A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees._

### Property 1: SDK returns well-formed ThreatReport for any valid input

_For any_ valid `Payload` and `Policy`, invoking `SDK.submit()` returns a `ThreatReport` containing non-null `severity`, `matched_patterns`, `remediation_summary`, `agent_chain`, and `pipeline_duration_ms`.

**Validates: Requirements 1.1, 2.5**

---

### Property 2: Invalid Policy raises ConfigurationError before pipeline execution

_For any_ malformed or missing `Policy` input, the SDK raises `ConfigurationError` and no CrewAI agent is instantiated or invoked.

**Validates: Requirements 1.6**

---

### Property 3: Pipeline agent invocation order is always preserved

_For any_ valid `Payload`, the `agent_chain` field in the resulting `ThreatReport` is always `["Parser", "StaticScanner", "RedTeamer", "Auditor"]` in that order, regardless of payload content or size.

**Validates: Requirements 2.1**

---

### Property 4: Agent failure causes fail-closed classification at Severity high

_For any_ agent in the pipeline that raises an unhandled exception, the resulting `ThreatReport.severity` is `"high"`, the EventLog entry contains the failing agent's identifier and error reason, and no subsequent agent in the chain is invoked.

**Validates: Requirements 2.6**

---

### Property 5: Semgrep findings are bijectively mapped to Signals

_For any_ non-empty Semgrep result containing N rule matches, the `ScanResult` contains exactly N `Signal` objects each with a `severity` value matching the corresponding Semgrep rule severity classification, and no Signals are present when Semgrep returns zero matches.

**Validates: Requirements 3.2, 3.3**

---

### Property 6: Semgrep non-zero exit produces inconclusive result without blocking pipeline

_For any_ Semgrep subprocess that exits with a non-zero return code, the `ScanResult.scan_status` is `"inconclusive"`, an EventLog entry records the error, and the pipeline continues to the Red Teamer Agent.

**Validates: Requirements 3.5**

---

### Property 7: GNN anomaly score threshold determines Signal attachment

_For any_ GNN anomaly score `s` and configured threshold `t`: if `s > t`, the `ScanResult` contains a `Signal` with `severity = "high"` and `source = "gnn"`; if `s <= t`, no GNN Signal is present in the findings.

**Validates: Requirements 4.3**

---

### Property 8: RAG retrieval count never exceeds configured K

_For any_ configured value of `K` and any `Payload`, the number of documents returned from ChromaDB and passed to the Gemini API is at most `K`.

**Validates: Requirements 6.1**

---

### Property 9: Gemini API failure does not block pipeline

_For any_ Gemini API call that returns an error or times out, the pipeline produces a `ThreatReport` using only ChromaDB retrieval results (no generated summary), and the EventLog records the Gemini failure.

**Validates: Requirements 6.5**

---

### Property 10: High/critical Severity always triggers automated response

_For any_ `ThreatReport` with `severity` of `"high"` or `"critical"`, the Inspector triggers an automated response (block, patch, or escalate per Policy) and no human escalation queue entry is created unless Policy explicitly routes to escalate.

**Validates: Requirements 7.1**

---

### Property 11: Pre-filter excludes all paths containing excluded folder names

_For any_ file path containing a component that appears in `EXCLUDED_FOLDERS`, `pre_filter()` returns `FilterResult(passed=False, skip_reason="excluded_folder")` and the file content is never read.

**Validates: Requirements 9.1**

---

### Property 12: Pre-filter excludes all paths with excluded extensions

_For any_ file path whose suffix (case-insensitive) appears in `EXCLUDED_EXTENSIONS`, `pre_filter()` returns `FilterResult(passed=False, skip_reason="excluded_extension")`.

**Validates: Requirements 9.1**

---

### Property 13: Length boundary tokenizer passes only tokens exceeding 60 characters

_For any_ file content string, all tokens in `FilterResult.tokens` have `len(token) > 60`, and any file whose content contains no such tokens results in `FilterResult(passed=False, skip_reason="no_tokens_above_threshold")`.

**Validates: Requirements 9.1, 9.3**

---

### Property 14: SHA-256 hash gate is idempotent for unchanged functions

_For any_ function body submitted to the hash gate that has already been processed and stored in `HashDB`, resubmitting the identical content without modification produces no `CodeChunk` output (the function is discarded by Layer 2).

**Validates: Requirements 9.2, 9.5**

---

### Property 15: HVP final score equals base score multiplied by priority multiplier

_For any_ `base_score` and `HVP_Profile.priority_multiplier`, the `final_score` recorded in the EventLog equals `base_score * priority_multiplier`, and if the detected threat vector matches the profile's `threat_vectors`, the final score is `min(final_score + 20, 100)`.

**Validates: Requirements 10.2, 10.3**

---

### Property 16: Data masking removes all sensitive patterns

_For any_ string containing email addresses, 16-digit card numbers, credential key-value pairs (`password=`, `secret=`, `api_key=`, `token=`), base64 strings of ≥ 32 characters, or SSN patterns, the masked output contains no unredacted instances of those patterns and each match is replaced by a `[REDACTED:<TYPE>]` placeholder.

**Validates: Requirements 13.4, 16.2**

---

### Property 17: SessionToken tamper detection rejects any modified token

_For any_ valid `SessionToken`, modifying any byte of the token (session_id, user_id, role, timestamps, or signature) causes `validate_session_token()` to return an authentication error and reject the request.

**Validates: Requirements 13.11**

---

### Property 18: SessionToken round-trip — issued tokens pass their own validation

_For any_ valid user credentials, the `SessionToken` issued by `POST /auth/token` passes `validate_session_token()` when presented within its expiry window and fails after expiry.

**Validates: Requirements 13.10, 13.12**

---

### Property 19: EventLog entries always contain all required fields

_For any_ pipeline execution that produces a `ThreatReport`, the resulting EventLog entry contains non-null values for all fields defined in the EventLog schema (Requirement 14 AC#2): `ts`, `event_id`, `target_hvp`, `hvp_multiplier`, `asset_type`, `asset_ext`, `source_path_hash`, `severity_level`, `base_score`, `final_score`, `threat_detected`, `matched_patterns`, `detection_source`, `layer_passed`, `action_taken`, `patch_generated`, `agent_chain`, `pipeline_duration_ms`, `masked_for_admin`, `session_id`, `operator_id`.

**Validates: Requirements 14.2**

---

### Property 20: WebSocket routing: CEO high/critical events never reach ADMIN connections

_For any_ event with `severity_level` of `"high"` or `"critical"` and `target_hvp == "CEO"`, the `WebSocketManager` delivers the event only to `SUPER_ADMIN` WebSocket connections and zero bytes are sent to any registered `ADMIN` connection.

**Validates: Requirements 14.5, 14.6**

---

### Property 21: SubmissionPayload never contains raw file path or source text

_For any_ `CodeChunk` processed by the SDK forensic extractor, the resulting `SubmissionPayload` contains `file_path_hash` (a SHA-256 hex digest) and `masked_payload`, and does not contain the original `source_text` or the raw `file_path` string.

**Validates: Requirements 15.2, 16.6**

---

### Property 22: EvidenceHash equals SHA-256 of original source text

_For any_ `CodeChunk`, `EvidenceHash` equals `hashlib.sha256(source_text.encode("utf-8")).hexdigest()` computed before any masking is applied.

**Validates: Requirements 16.3**

---

### Property 23: Escalation timeout applies default action for any configured timeout value

_For any_ configured escalation timeout `T` (in seconds), if no human response is received within `T` seconds of an escalation being triggered, the Inspector applies the default escalation policy (block or allow) and records the timeout action in the EventLog.

**Validates: Requirements 11.6**

---

## Error Handling

### Pipeline Failures

- Agent exception → fail-closed: Severity `high`, EventLog entry with agent ID + error, pipeline terminates.
- Partial pipeline (< 4 agents) → always classified at Severity `high`.

### External Service Failures

| Service                             | Failure behavior                                                      |
| ----------------------------------- | --------------------------------------------------------------------- |
| Semgrep non-zero exit               | `scan_status = "inconclusive"`, pipeline continues                    |
| Joern timeout (> 20 s)              | Log timeout, continue with Semgrep only                               |
| Gemini API error / timeout (> 15 s) | Log failure, continue with RAG results only                           |
| Gemini unavailable during patch gen | Fall back to rule-based template, flag as `patch_source = "template"` |
| ChromaDB unavailable                | Log failure, continue with static findings only                       |
| Sandbox init failure                | Log failure, skip sandbox, continue with static findings              |
| Sandbox timeout (> 10 s)            | Terminate process, log timeout, continue with partial artifacts       |

### Queue and Capacity Failures

- `ScanQueue` at max depth: discard oldest entry, emit Control Plane operator alert.
- `SERVER_SCAN_QUEUE` at max capacity: return HTTP 503 to SDK; SDK re-queues with 30 s back-off.
- SDK receives HTTP 429: pause submission worker for `Retry-After` duration (default 60 s), re-queue at front.

### Authentication and Authorization Failures

- Invalid or tampered `SessionToken`: reject request, return 401.
- Expired `SessionToken`: reject request, return 401, require re-authentication.
- ADMIN token for SUPER_ADMIN-only operation: reject, log unauthorized attempt in EventLog with session ID and operation, return 403.
- WebSocket with invalid/expired token: close with code 4001.

---

## Testing Strategy

### Dual Testing Approach

Unit tests cover specific examples, edge cases, and error conditions. Property-based tests (Hypothesis) cover universal correctness properties across all valid inputs. Together they provide comprehensive coverage: unit tests catch concrete bugs; property tests verify general correctness.

### Property-Based Tests (Hypothesis)

Each property in the Correctness Properties section maps to exactly one `@given`-decorated test. Minimum 100 examples per test (`settings(max_examples=100)`). Each test is tagged with a comment:

```
# Feature: agent-sniffer, Property N: <property_text>
```

Key strategies:

- `st.text()` / `st.binary()` for Payload content.
- Composite strategies for `Policy`, `HVP_Profile`, `ThreatReport`.
- Monkeypatched mocks for Gemini API, ChromaDB, Semgrep subprocess, Joern subprocess, sandbox.
- `st.floats(min_value=0.0, max_value=1.0)` for anomaly scores and base scores.

### Unit Tests

Focused on:

- Semgrep result parsing and Signal mapping.
- Masking regex correctness with representative PII inputs.
- HMAC validation: correct key succeeds, wrong key fails, expired token rejected.
- ScanQueue overflow: 1001st entry discards oldest.
- Layer 1/2/3 filter logic with concrete file path / AST fixtures.
- Escalation timeout application with mock asyncio clock.

### Integration Tests

- Full ARES pipeline against a real Semgrep binary with a test rule set and 1 MB payload.
- ARGUS worker pool: modify a real Python file, observe `CodeChunk` produced and `HashDB` updated.
- Control Plane WebSocket: connect two sessions (SUPER_ADMIN + ADMIN), publish CEO-targeted event, verify ADMIN receives nothing.
- SDK-to-Control-Plane submission: HTTP POST, verify `job_id` returned within 50 ms (measured).

### Property Test Configuration

```python
from hypothesis import settings, HealthCheck

@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,  # pipeline tests can be slow with mocks
)
```

## SDK Implementation Spec

This section documents the formal technical specification for each SDK module, structured as Part-by-Part implementation guides. Each part covers Objective, Logic Flow, Input/Output Schema, and Core Code Snippet.

---

### Part 1: SDK Client-Side Background Detection

#### Modules: `sdk/background.py` and `sdk/pre_filter.py`

---

#### `sdk/background.py` — Event-Driven Background Core

##### Objective

Detect file changes in real-time using OS-level events (watchdog) and feed them into a bounded async queue for non-blocking processing by worker tasks. No polling loops. No blocking the main application thread.

##### Logic Flow

```
OS file system change (inotify / FSEvents / ReadDirectoryChangesW)
    ↓
watchdog Observer (runs in dedicated thread)
    ↓
PantheonEventHandler.on_modified()
    │── is_directory? → skip
    │── pre_filter(path) → FilterResult
    │── passed? → asyncio.run_coroutine_threadsafe(ScanQueue.put(...), loop)
    ↓
ScanQueue (asyncio.Queue, maxsize=1000)
    ↓
Worker tasks (3 async workers, configurable)
    │── consume one event at a time
    │── apply Layer 1 → Layer 2 → Layer 3
    │── produce CodeChunk → ForensicExtractor → SubmissionPayload → HTTP POST
```

##### Input/Output Schema

```
Input:  FileModifiedEvent(src_path: str, is_directory: bool)
Output: ScanQueue entry → {"path": str, "tokens": list[str]}

ScanQueue:  asyncio.Queue(maxsize=1000)
Overflow:   discard oldest entry + emit operator alert
Workers:    3 asyncio.Task (configurable via Policy)
```

##### Core Code Snippet

```python
# sdk/background.py
from __future__ import annotations

import asyncio
from pathlib import Path

from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sdk.pre_filter import pre_filter


class PantheonEventHandler(FileSystemEventHandler):
    """Bridge watchdog thread → asyncio ScanQueue."""

    def __init__(
        self,
        scan_queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__()
        self._queue = scan_queue
        self._loop = loop

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        result = pre_filter(event.src_path)
        if result.passed:
            asyncio.run_coroutine_threadsafe(
                self._enqueue(event.src_path, result.tokens),
                self._loop,
            )

    async def _enqueue(self, path: str, tokens: list[str]) -> None:
        if self._queue.full():
            # Discard oldest to make room — bounded queue contract
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self._queue.put({"path": path, "tokens": tokens})


class BackgroundScanner:
    """Manages the watchdog Observer and async worker pool."""

    def __init__(
        self,
        watch_path: str,
        worker_count: int = 3,
        queue_maxsize: int = 1_000,
    ) -> None:
        self._watch_path = watch_path
        self._worker_count = worker_count
        self._loop = asyncio.get_event_loop()
        self.scan_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)
        self._observer = Observer()
        self._handler = PantheonEventHandler(self.scan_queue, self._loop)

    def start(self) -> None:
        self._observer.schedule(self._handler, self._watch_path, recursive=True)
        self._observer.start()
        for _ in range(self._worker_count):
            self._loop.create_task(self._worker())

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()

    async def _worker(self) -> None:
        """Consume ScanQueue events one at a time."""
        while True:
            event = await self.scan_queue.get()
            try:
                await self._process(event)
            finally:
                self.scan_queue.task_done()

    async def _process(self, event: dict) -> None:
        # Placeholder: Layer 1 → 2 → 3 → ForensicExtractor → HTTP POST
        # Implemented in sdk/layers.py and sdk/transport.py
        pass
```

---

#### `sdk/pre_filter.py` — Deterministic Pre-Filter (L0 + Layer 1 + Layer 2 + Layer 3)

##### Objective

Apply all deterministic filtering stages in a single module before any LLM or CPU-intensive work is triggered. Zero external dependencies beyond Python stdlib and SQLite. Discard as early as possible.

##### Logic Flow

```
event_path (str)
    ↓
[L0 — Folder Exclusion]
    path parts ∩ EXCLUDED_FOLDERS → discard (skip_reason: "excluded_folder")
    ↓
[L0 — Extension Exclusion]
    suffix ∈ EXCLUDED_EXTENSIONS → discard (skip_reason: "excluded_extension")
    ↓
[L0 — Length Boundary Tokenizer]
    read file content
    split on whitespace → keep only tokens where len(token) > 60
    no tokens above threshold → discard (skip_reason: "no_tokens_above_threshold")
    ↓
[Layer 1 — Code Extension Allowlist]
    suffix ∉ CODE_EXTENSIONS → discard (skip_reason: "not_in_allowlist")
    ↓
[Layer 2 — Semantic Hash Gate]
    AST parse → extract function bodies
    SHA-256 per function body → compare against HashDB (SQLite)
    all hashes unchanged → discard (skip_reason: "hash_unchanged")
    changed functions → forward
    ↓
[Layer 3 — AST/Regex Criticality Filter]
    match CRITICAL_PATTERNS (auth / crypto / db / exec / network)
    no matches → discard (skip_reason: "no_critical_patterns")
    matched functions → promoted to CodeChunk list
    ↓
FilterResult(passed=True, chunks=[CodeChunk, ...])
```

##### Input/Output Schema

```
Input:
    event_path: str    — absolute file path from watchdog event

Output:
    FilterResult
        passed: bool
        chunks: list[CodeChunk]   — populated only when passed=True
        skip_reason: str | None   — one of:
            "excluded_folder"
            "excluded_extension"
            "no_tokens_above_threshold"
            "not_in_allowlist"
            "hash_unchanged"
            "no_critical_patterns"
            None  (passed)

CodeChunk
    file_path_hash: str      — SHA-256(original_file_path)
    function_name: str
    source_text: str         — raw function body (deleted after ForensicExtractor)
    match_reason: str        — Layer 3 matched pattern label
    asset_owner_role: str    — resolved by HVP Validator (default: "UNKNOWN")
    client_id: str
```

##### Core Code Snippet

```python
# sdk/pre_filter.py
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from shared.hashdb import HashDB

# ── L0 Constants ────────────────────────────────────────────────────────────

EXCLUDED_FOLDERS: frozenset[str] = frozenset({
    "node_modules", "venv", ".venv", ".git",
    "assets", "dist", "build", "__pycache__",
    ".tox", "coverage",
})

EXCLUDED_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".txt", ".json", ".yaml", ".yml",
    ".lock", ".log", ".png", ".jpg", ".svg",
    ".ico", ".pdf", ".csv",
})

MIN_TOKEN_LENGTH: int = 60

# ── Layer 1 Constants ────────────────────────────────────────────────────────

CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".go", ".cpp", ".c", ".java", ".rs",
})

# ── Layer 3 Constants ────────────────────────────────────────────────────────

CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(authenticate|authorize|login|verify_token|check_permission)", "auth"),
    (r"(?i)(encrypt|decrypt|hmac|sha256|aes|rsa|cipher|hash)", "crypto"),
    (r"(?i)(execute|query|cursor\.execute|db\.run|session\.exec)", "db"),
    (r"(?i)(eval|exec|subprocess|os\.system|__import__)", "exec"),
    (r"(?i)(requests\.|urllib|httpx|aiohttp|socket\.)", "network"),
]


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class CodeChunk:
    file_path_hash: str
    function_name: str
    source_text: str
    match_reason: str
    asset_owner_role: str = "UNKNOWN"
    client_id: str = ""


@dataclass
class FilterResult:
    passed: bool
    chunks: list[CodeChunk] = field(default_factory=list)
    skip_reason: str | None = None


# ── L0 Helpers ───────────────────────────────────────────────────────────────

def _is_excluded_path(path: str) -> bool:
    return any(part in EXCLUDED_FOLDERS for part in Path(path).parts)


def _is_excluded_extension(path: str) -> bool:
    return Path(path).suffix.lower() in EXCLUDED_EXTENSIONS


def _has_long_tokens(content: str) -> bool:
    return any(len(tok) > MIN_TOKEN_LENGTH for tok in content.split())


# ── Layer 2 Helper ───────────────────────────────────────────────────────────

def _function_sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _extract_functions_python(source: str) -> list[tuple[str, str]]:
    """Return [(name, body_source)] for all top-level and nested functions."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                body = ast.unparse(node)
                results.append((node.name, body))
            except Exception:
                pass
    return results


# ── Layer 3 Helper ───────────────────────────────────────────────────────────

def _match_critical(source: str) -> str | None:
    """Return the first matched pattern label, or None."""
    for pattern, label in CRITICAL_PATTERNS:
        if re.search(pattern, source):
            return label
    return None


# ── Public Entry Point ───────────────────────────────────────────────────────

def pre_filter(event_path: str, hashdb: HashDB | None = None) -> FilterResult:
    # L0 — Folder exclusion
    if _is_excluded_path(event_path):
        return FilterResult(passed=False, skip_reason="excluded_folder")

    # L0 — Extension exclusion
    if _is_excluded_extension(event_path):
        return FilterResult(passed=False, skip_reason="excluded_extension")

    # L0 — Read file
    try:
        content = Path(event_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FilterResult(passed=False, skip_reason="read_error")

    # L0 — Length boundary tokenizer
    if not _has_long_tokens(content):
        return FilterResult(passed=False, skip_reason="no_tokens_above_threshold")

    # Layer 1 — Code extension allowlist
    if Path(event_path).suffix.lower() not in CODE_EXTENSIONS:
        return FilterResult(passed=False, skip_reason="not_in_allowlist")

    # Layer 2 — Semantic hash gate
    file_path_hash = hashlib.sha256(event_path.encode()).hexdigest()
    functions = _extract_functions_python(content)
    changed: list[tuple[str, str]] = []

    if hashdb:
        for name, body in functions:
            current_hash = _function_sha256(body)
            stored = hashdb.get(file_path_hash, name)
            if stored != current_hash:
                changed.append((name, body))
    else:
        changed = functions  # no hashdb → treat all as changed

    if not changed:
        return FilterResult(passed=False, skip_reason="hash_unchanged")

    # Layer 3 — AST/Regex criticality filter
    chunks: list[CodeChunk] = []
    for name, body in changed:
        reason = _match_critical(body)
        if reason:
            chunks.append(CodeChunk(
                file_path_hash=file_path_hash,
                function_name=name,
                source_text=body,
                match_reason=reason,
            ))

    if not chunks:
        return FilterResult(passed=False, skip_reason="no_critical_patterns")

    return FilterResult(passed=True, chunks=chunks)
```

---

### Part 2: Forensic Extractor and Data Models

#### Modules: `sdk/forensics.py`, `shared/models.py`, `shared/policy.py`

---

#### `sdk/forensics.py` — ForensicExtractor

##### Objective

Transform a raw `CodeChunk` (which holds original source text and file path) into a `SubmissionPayload` that is safe to transmit. The original file path and source text are never included in the output. All sensitive values in the source text are masked before leaving the SDK process.

##### Logic Flow

```
CodeChunk (from pre_filter)
    │   file_path_hash, function_name, source_text, match_reason
    ↓
[1. File Path Hashing]
    SHA-256(original_file_path) → file_path_hash
    del original file_path reference

[2. Line Coordinate Extraction]
    AST parse full file source
    locate FunctionDef node matching function_name
    extract node.lineno (start) and node.end_lineno (end)
    → line_coordinates: {"start": int, "end": int}

[3. Git Commit Hash]
    subprocess: git log -1 --format=%H -- <file_path>
    → git_commit_hash: str | None
    (None if git unavailable or file untracked)

[4. Evidence Hash]
    SHA-256(source_text.encode("utf-8"))   ← computed BEFORE any masking
    → evidence_hash: str

[5. MaskedPayload]
    apply regex substitution rules to source_text:
        credential key-value pairs → <NAME>=[REDACTED:CREDENTIAL]
        base64 strings ≥ 32 chars  → [REDACTED:BASE64]
        16-digit card numbers      → [REDACTED:CARD]
        email addresses            → [REDACTED:EMAIL]
        SSN patterns               → [REDACTED:SSN]
    → masked_payload: str

[6. Memory Cleanup]
    del source_text from CodeChunk
    del original file_path variable
    → both freed for garbage collection

[7. Assemble ForensicContext + SubmissionPayload]
    ForensicContext(
        file_path=original_file_path,    ← stored in ForensicContext only
        line_coordinates={"start": n, "end": m},
        git_commit_hash=hash_or_none,
    )
    SubmissionPayload(
        file_path_hash=file_path_hash,
        function_name=function_name,
        match_reason=match_reason,
        asset_owner_role=asset_owner_role,
        client_id=client_id,
        forensic_context=ForensicContext,
        masked_payload=masked_payload,
        evidence_hash=evidence_hash,
    )
    ← source_text and raw file_path are NOT in SubmissionPayload
```

##### Input/Output Schema

```
Input:
    chunk: CodeChunk          — from pre_filter(), contains source_text
    file_path: str            — original absolute path (used locally, not transmitted)
    file_source: str          — full file content (for AST line extraction)
    client_id: str

Output:
    SubmissionPayload         — safe to transmit, no raw path or source_text
    (source_text and file_path deleted from memory after extraction)
```

##### Core Code Snippet

```python
# sdk/forensics.py
from __future__ import annotations

import ast
import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from shared.models import CodeChunk, ForensicContext, SubmissionPayload

# ── Masking Rules ────────────────────────────────────────────────────────────

_MASKING_RULES: list[tuple[str, str]] = [
    (
        r'(?i)(password|secret|api_key|token|auth_token)\s*=\s*["\']?([^"\';\s]+)["\']?',
        r'\1=[REDACTED:CREDENTIAL]',
    ),
    (r'\b[A-Za-z0-9+/]{32,}={0,2}\b', '[REDACTED:BASE64]'),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', '[REDACTED:CARD]'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED:EMAIL]'),
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED:SSN]'),
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mask(text: str) -> str:
    """Apply all masking rules; return sanitized source text."""
    result = text
    for pattern, replacement in _MASKING_RULES:
        result = re.sub(pattern, replacement, result)
    return result


def _evidence_hash(source_text: str) -> str:
    """SHA-256 of original unmasked source — computed before masking."""
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _git_commit_hash(file_path: str) -> str | None:
    """Last git commit hash that touched this file. None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H", "--", file_path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        value = result.stdout.strip()
        return value if value else None
    except Exception:
        return None


def _line_coordinates(file_source: str, function_name: str) -> dict[str, int | None]:
    """Extract start/end line numbers of a named function via AST."""
    try:
        tree = ast.parse(file_source)
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function_name
            ):
                return {"start": node.lineno, "end": node.end_lineno}
    except Exception:
        pass
    return {"start": None, "end": None}


# ── Public Entry Point ───────────────────────────────────────────────────────

def extract(
    chunk: CodeChunk,
    file_path: str,
    file_source: str,
    client_id: str,
) -> SubmissionPayload:
    """
    Transform CodeChunk into a SubmissionPayload.
    Deletes chunk.source_text and file_path after extraction.
    """
    source_text: str = chunk.source_text  # local reference before deletion

    # 1. File path hash (path never leaves this function)
    file_path_hash = hashlib.sha256(file_path.encode("utf-8")).hexdigest()

    # 2. Line coordinates
    coords = _line_coordinates(file_source, chunk.function_name)

    # 3. Git commit hash
    commit = _git_commit_hash(file_path)

    # 4. Evidence hash — MUST be computed before masking
    ev_hash = _evidence_hash(source_text)

    # 5. Masked payload
    masked = _mask(source_text)

    # 6. Memory cleanup — source_text and file_path no longer needed
    del source_text
    del file_source
    chunk.source_text = ""  # clear reference on the chunk object

    # 7. Assemble
    forensic = ForensicContext(
        file_path=file_path,          # stored inside ForensicContext only
        line_coordinates=coords,
        git_commit_hash=commit,
    )

    return SubmissionPayload(
        file_path_hash=file_path_hash,
        function_name=chunk.function_name,
        match_reason=chunk.match_reason,
        asset_owner_role=chunk.asset_owner_role,
        client_id=client_id,
        forensic_context=forensic,
        masked_payload=masked,
        evidence_hash=ev_hash,
    )
```

---

#### `shared/models.py` — Formal Data Models

##### Objective

Define all canonical dataclasses used across SDK, pipeline, and Control Plane. Single source of truth for payload structure. No business logic — pure data containers.

##### Core Code Snippet

```python
# shared/models.py
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CodeChunk:
    """Unit of analysis produced by pre_filter Layer 3."""
    file_path_hash: str
    function_name: str
    source_text: str          # deleted by ForensicExtractor after use
    match_reason: str
    asset_owner_role: str = "UNKNOWN"
    client_id: str = ""


@dataclass
class ForensicContext:
    """Metadata extracted at SDK side for chain-of-custody."""
    file_path: str                        # original path — stays in ForensicContext only
    line_coordinates: dict[str, int | None]  # {"start": int, "end": int}
    git_commit_hash: str | None


@dataclass
class SubmissionPayload:
    """Safe-to-transmit payload from SDK → Control Plane."""
    file_path_hash: str          # SHA-256(original_file_path)
    function_name: str
    match_reason: str
    asset_owner_role: str
    client_id: str
    forensic_context: ForensicContext
    masked_payload: str          # source with sensitive values redacted
    evidence_hash: str           # SHA-256(original source_text)
    # source_text and raw file_path are NEVER included


@dataclass
class Signal:
    """A single detected threat indicator."""
    severity: str                # "low" | "medium" | "high" | "critical"
    pattern_id: str              # Semgrep rule ID or "gnn_anomaly"
    source: str                  # "semgrep" | "gnn" | "rag" | "sandbox"
    confidence: float            # [0.0, 1.0]
    description: str


@dataclass
class ThreatReport:
    """Final output of the four-agent CrewAI pipeline."""
    severity: str
    matched_patterns: list[str]
    remediation_summary: str
    patch_diff: str | None
    affected_file_path_hash: str
    cve_reference: str | None
    signals: list[Signal]
    agent_chain: list[str]
    pipeline_duration_ms: int
    patch_source: str | None     # "gemini" | "template" | None


@dataclass
class EventLogEntry:
    """SIEM-compatible single-line JSON log record."""
    ts: str
    event_id: str
    target_hvp: str
    hvp_multiplier: float
    asset_type: str
    asset_ext: str
    source_path_hash: str
    severity_level: str
    base_score: float
    final_score: float
    threat_detected: list[str]
    matched_patterns: list[str]
    detection_source: str        # "perimeter" | "background"
    layer_passed: int
    action_taken: str
    patch_generated: bool
    agent_chain: list[str]
    pipeline_duration_ms: int
    masked_for_admin: bool
    session_id: str
    operator_id: str
    forensic_context: ForensicContext | None = None
    masked_payload: str | None = None
    evidence_hash: str | None = None
    encrypted_payload: bytes | None = None  # AES-256, SUPER_ADMIN only


@dataclass
class SeverityChangeRequest:
    """Pending severity downgrade — requires SUPER_ADMIN approval."""
    request_id: str
    signal_id: str
    original_severity: str
    requested_severity: str
    requesting_admin_id: str
    reason: str
    status: str                  # "pending_approval" | "approved" | "rejected"
    created_at: str
    resolved_at: str | None = None
    resolved_by: str | None = None


@dataclass
class HVP_Profile:
    """Risk profile for a High-Value Person role."""
    role: str
    severity_weight: str
    priority_multiplier: float
    threat_vectors: list[str]
    monitored_assets: list[str]
    escalation_channels: list[str]
    auto_escalation_threshold: float
    email_patterns: list[str]    # regex patterns for git author email
    path_patterns: list[str]     # glob patterns for file path matching
```

---

#### `shared/policy.py` — Policy Configuration

##### Objective

Define the Pydantic model for operator-supplied Policy configuration loaded from YAML or JSON at startup. Validated at load time; rejected with field-level errors if invalid. Hot-reloaded by Inspector within 5 seconds of file modification.

##### Core Code Snippet

```python
# shared/policy.py
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SemgrepConfig(BaseModel):
    rule_sets: list[str] = Field(
        default=["p/default"],
        description="Local file paths or Semgrep Registry identifiers.",
    )


class GNNConfig(BaseModel):
    model_path: str = "models/gnn_default.pt"
    anomaly_threshold: float = Field(default=0.75, ge=0.0, le=1.0)


class ChromaDBConfig(BaseModel):
    collection_name: str = "threat_intel"
    persist_directory: str = ".chromadb"
    top_k: int = Field(default=5, ge=1, le=50)


class GeminiConfig(BaseModel):
    api_key: str
    model: str = "gemini-1.5-flash"
    rpm_limit: int = Field(default=14, ge=1, le=60)
    timeout_seconds: int = Field(default=15, ge=1)


class HVPProfileConfig(BaseModel):
    role: str
    severity_weight: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    priority_multiplier: float = Field(ge=1.0, le=5.0)
    threat_vectors: list[str] = Field(default_factory=list)
    monitored_assets: list[str] = Field(default_factory=list)
    escalation_channels: list[str] = Field(default_factory=list)
    auto_escalation_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    email_patterns: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)


class ScanQueueConfig(BaseModel):
    maxsize: int = Field(default=1_000, ge=100, le=10_000)
    worker_count: int = Field(default=3, ge=1, le=20)


class ServerQueueConfig(BaseModel):
    maxsize: int = Field(default=5_000, ge=100, le=50_000)
    worker_count: int = Field(default=3, ge=1, le=20)


class SeverityRoutingConfig(BaseModel):
    critical: Literal["block", "patch", "escalate"] = "block"
    high: Literal["block", "patch", "escalate"] = "block"
    medium: Literal["block", "patch", "escalate"] = "escalate"
    low: Literal["block", "patch", "escalate"] = "block"


class FailModeConfig(BaseModel):
    on_inspector_error: Literal["fail_open", "fail_closed"] = "fail_closed"
    on_oversized_payload: Literal["block", "allow", "truncate"] = "block"
    max_payload_bytes: int = Field(default=32_768, ge=1_024)


class SessionConfig(BaseModel):
    ttl_seconds: int = Field(default=3_600, ge=60)
    super_admin_key_bits: int = Field(default=512, ge=512)
    admin_key_bits: int = Field(default=256, ge=256)


class EscalationConfig(BaseModel):
    timeout_seconds: int = Field(default=60, ge=5)
    default_action: Literal["block", "allow"] = "block"


class AuditLogConfig(BaseModel):
    output: Literal["file", "stdout", "both"] = "both"
    log_file_path: str = "logs/pantheon.jsonl"
    verbose: bool = False
    max_buffer_entries: int = Field(default=10_000, ge=1_000)


class Policy(BaseModel):
    """Root Policy configuration. Loaded from YAML or JSON at startup."""

    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    gnn: GNNConfig = Field(default_factory=GNNConfig)
    chromadb: ChromaDBConfig = Field(default_factory=ChromaDBConfig)
    gemini: GeminiConfig
    hvp_profiles: list[HVPProfileConfig] = Field(default_factory=list)
    scan_queue: ScanQueueConfig = Field(default_factory=ScanQueueConfig)
    server_queue: ServerQueueConfig = Field(default_factory=ServerQueueConfig)
    severity_routing: SeverityRoutingConfig = Field(
        default_factory=SeverityRoutingConfig
    )
    fail_mode: FailModeConfig = Field(default_factory=FailModeConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)
    audit_log: AuditLogConfig = Field(default_factory=AuditLogConfig)

    code_extension_allowlist: list[str] = Field(
        default=[".py", ".js", ".ts", ".go", ".cpp", ".c", ".java", ".rs"]
    )
    trusted_domains: list[str] = Field(
        default_factory=list,
        description="Trusted org domains for HVP_CALENDAR OSINT check.",
    )
    url_allowlist: list[str] = Field(
        default_factory=list,
        description="Trusted external URLs; suppresses data exfiltration signal.",
    )

    @field_validator("hvp_profiles")
    @classmethod
    def _unique_roles(cls, profiles: list[HVPProfileConfig]) -> list[HVPProfileConfig]:
        roles = [p.role for p in profiles]
        if len(roles) != len(set(roles)):
            raise ValueError("hvp_profiles: duplicate role entries are not allowed")
        return profiles
```

---

### Part 3: Transport Submission and Control Plane Ingestion Layer

#### Modules: `sdk/transport.py`, `control_plane/api/jobs.py`, `control_plane/rbac.py`

---

#### `sdk/transport.py` — Async HTTP Submission Client

##### Objective

Deliver a `SubmissionPayload` from the SDK to the Control Plane via async HTTP POST. The call must return a `job_id` within 50ms without blocking the SDK background worker. Handle rate-limit (429) and capacity (503) responses with automatic re-queue and back-off.

##### Logic Flow

```
SubmissionPayload (from ForensicExtractor)
    ↓
TokenBucket.acquire()          ← enforce 14 RPM (configurable)
    ↓
httpx.AsyncClient.post(
    url=/api/v1/jobs,
    json=payload.dict(),
    headers={Authorization: Bearer <api_key>},
    timeout=10s
)
    ↓
HTTP 200 → return job_id       ← Control Plane queued within 50ms
HTTP 429 → RateLimitError      → re-queue + sleep(Retry-After, default 60s)
HTTP 503 → CapacityError       → re-queue + sleep(30s)
Timeout  → TimeoutError        → re-queue + sleep(5s)
    ↓
SDK worker proceeds to next CodeChunk immediately
(does not wait for pipeline result — result arrives via WebSocket)
```

##### Input/Output Schema

```
Input:
    payload: SubmissionPayload
    api_key: str
    control_plane_url: str

Output:
    job_id: str                ← UUID returned by Control Plane
    (raises on unrecoverable error)

Exceptions:
    ChunkSubmitTimeout         → caller re-queues
    RateLimitError(retry_after: int)  → caller backs off
    CapacityError              → caller backs off 30s
```

##### Core Code Snippet

```python
# sdk/transport.py
from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass

import httpx

from shared.models import SubmissionPayload


# ── Custom Exceptions ─────────────────────────────────────────────────────────

class ChunkSubmitTimeout(Exception):
    def __init__(self, payload: SubmissionPayload) -> None:
        self.payload = payload


class RateLimitError(Exception):
    def __init__(self, retry_after: int = 60) -> None:
        self.retry_after = retry_after


class CapacityError(Exception):
    pass


# ── Token Bucket Rate Limiter ─────────────────────────────────────────────────

class TokenBucket:
    """Async token bucket — enforces max N calls per minute."""

    def __init__(self, rpm: int = 14) -> None:
        self._interval = 60.0 / rpm   # seconds between tokens
        self._last_call: float = 0.0

    async def acquire(self) -> None:
        now = asyncio.get_event_loop().time()
        wait = self._interval - (now - self._last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = asyncio.get_event_loop().time()


# ── Transport Client ──────────────────────────────────────────────────────────

class ChunkTransport:
    """Async HTTP client for SDK → Control Plane submission."""

    def __init__(
        self,
        control_plane_url: str,
        api_key: str,
        rpm_limit: int = 14,
    ) -> None:
        self._url = f"{control_plane_url.rstrip('/')}/api/v1/jobs"
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self._rate_limiter = TokenBucket(rpm=rpm_limit)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=10,
            ),
        )

    async def submit(self, payload: SubmissionPayload) -> str:
        """Submit one SubmissionPayload; return job_id. Non-blocking."""
        await self._rate_limiter.acquire()

        body = dataclasses.asdict(payload)

        try:
            response = await self._client.post(
                self._url,
                json=body,
                headers=self._headers,
            )
        except httpx.TimeoutException:
            raise ChunkSubmitTimeout(payload)

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after=retry_after)

        if response.status_code == 503:
            raise CapacityError()

        response.raise_for_status()
        return response.json()["job_id"]

    async def aclose(self) -> None:
        await self._client.aclose()


# ── SDK Worker Integration ────────────────────────────────────────────────────

async def submit_with_retry(
    transport: ChunkTransport,
    payload: SubmissionPayload,
    scan_queue: asyncio.Queue,
) -> str | None:
    """
    Submit payload; re-queue on recoverable errors.
    Returns job_id on success, None if re-queued.
    """
    try:
        job_id = await transport.submit(payload)
        return job_id

    except ChunkSubmitTimeout:
        await scan_queue.put(payload)
        await asyncio.sleep(5)
        return None

    except RateLimitError as e:
        await scan_queue.put(payload)
        await asyncio.sleep(e.retry_after)
        return None

    except CapacityError:
        await scan_queue.put(payload)
        await asyncio.sleep(30)
        return None
```

---

#### `control_plane/api/jobs.py` — Inbound Job Endpoint

##### Objective

Receive `SubmissionPayload` from the SDK, validate the API key, place the job onto the server-side `SERVER_SCAN_QUEUE` without blocking, and return `job_id` within 50ms. Return HTTP 503 if the queue is at capacity.

##### Logic Flow

```
POST /api/v1/jobs
    ↓
validate_api_key(Authorization header)    ← dependency injection
    invalid → HTTP 401
    ↓
parse SubmissionPayload (Pydantic)
    invalid → HTTP 422
    ↓
SERVER_SCAN_QUEUE.full()?
    True  → HTTP 503 {"detail": "queue_full"}
    ↓
job = {job_id: uuid4, chunk: payload, submitted_at: utcnow}
SERVER_SCAN_QUEUE.put_nowait(job)          ← non-blocking
    ↓
return HTTP 200 {job_id, status: "queued"} ← within 50ms
```

##### Input/Output Schema

```
POST /api/v1/jobs
    Header:  Authorization: Bearer <api_key>
    Body:    SubmissionPayload (JSON)

Response 200: {"job_id": str, "status": "queued"}
Response 401: {"detail": "invalid_api_key"}
Response 422: {"detail": [field validation errors]}
Response 503: {"detail": "queue_full"}
```

##### Core Code Snippet

```python
# control_plane/api/jobs.py
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from control_plane.rbac import require_sdk_client
from shared.models import SubmissionPayload

router = APIRouter(prefix="/api/v1", tags=["jobs"])

# Server-side bounded queue — shared across all workers
SERVER_SCAN_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=5_000)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.post("/jobs", status_code=200)
async def receive_job(
    payload: SubmissionPayload,
    _client: dict = Depends(require_sdk_client),
) -> dict:
    """
    Accept a SubmissionPayload from the SDK.
    Enqueues immediately; returns job_id within 50ms.
    """
    if SERVER_SCAN_QUEUE.full():
        raise HTTPException(status_code=503, detail="queue_full")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "chunk": payload,
        "submitted_at": utcnow_iso(),
        "client_id": payload.client_id,
    }

    # Non-blocking — if queue fills between .full() check and put, catch it
    try:
        SERVER_SCAN_QUEUE.put_nowait(job)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="queue_full")

    return {"job_id": job_id, "status": "queued"}
```

---

#### `control_plane/rbac.py` — Session Token and Role Validation

##### Objective

Issue HMAC-SHA256 signed session tokens at login. Validate every request by re-deriving the signature from the role-specific in-memory signing key. Reject tampered, expired, or role-mismatched tokens. Enforce SUPER_ADMIN and ADMIN boundaries at FastAPI dependency level.

##### Logic Flow

```
POST /auth/token (login)
    ↓
validate credentials
    ↓
generate session_id (UUID v4, 32-byte hex)
build payload string: session_id:user_id:role:issued_at:expires_at
HMAC-SHA256(payload, ROLE_SIGNING_KEYS[role])
store in SESSION_STORE[session_id] = {user_id, role, expires_at, signature}
return {session_token: "<payload>:<signature>", expires_at}

─────────────────────────────────────────────────────

Any protected endpoint
    ↓
extract token from Authorization: Bearer <token>
split → payload + provided_signature
parse role from payload
    ↓
re-derive expected_signature = HMAC-SHA256(payload, ROLE_SIGNING_KEYS[role])
hmac.compare_digest(expected, provided)
    mismatch → HTTP 401
    ↓
check expires_at > utcnow()
    expired → HTTP 401
    ↓
check SESSION_STORE[session_id] exists
    missing → HTTP 401
    ↓
return session dict {user_id, role}

─────────────────────────────────────────────────────

RBAC enforcement (dependency)
    require_super_admin: role != "SUPER_ADMIN" → HTTP 403
    require_admin:       role not in allowed   → HTTP 403
    require_sdk_client:  validate api_key header
```

##### Input/Output Schema

```
POST /auth/token
    Body: {username: str, password: str}
    Response 200: {session_token: str, expires_at: int}
    Response 401: invalid credentials

Protected endpoint dependency:
    Input:  Authorization: Bearer <session_token>
    Output: {"user_id": str, "role": str}
    Raises: HTTP 401 (invalid/expired), HTTP 403 (insufficient role)
```

##### Core Code Snippet

```python
# control_plane/rbac.py
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ── Signing Keys (generated once at startup, in-memory only) ─────────────────

ROLE_SIGNING_KEYS: dict[str, bytes] = {
    "SUPER_ADMIN": secrets.token_bytes(64),   # 512-bit
    "ADMIN":       secrets.token_bytes(32),   # 256-bit
}

# ── In-memory session store ───────────────────────────────────────────────────

SESSION_STORE: dict[str, dict] = {}

# ── SDK API keys (loaded from Policy at startup) ──────────────────────────────
SDK_API_KEYS: set[str] = set()

security = HTTPBearer()


# ── Token Issuance ────────────────────────────────────────────────────────────

def create_session_token(
    user_id: str,
    role: str,
    ttl_seconds: int = 3_600,
) -> dict:
    if role not in ROLE_SIGNING_KEYS:
        raise ValueError(f"Unknown role: {role}")

    session_id = secrets.token_hex(32)
    issued_at = int(time.time())
    expires_at = issued_at + ttl_seconds

    payload = f"{session_id}:{user_id}:{role}:{issued_at}:{expires_at}"
    signature = hmac.new(
        ROLE_SIGNING_KEYS[role],
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    SESSION_STORE[session_id] = {
        "user_id": user_id,
        "role": role,
        "expires_at": expires_at,
        "signature": signature,
    }

    return {
        "session_token": f"{payload}:{signature}",
        "expires_at": expires_at,
    }


# ── Token Validation ──────────────────────────────────────────────────────────

def validate_session_token(token: str) -> dict:
    """
    Validate token. Returns session dict {user_id, role} or raises HTTP 401.
    """
    try:
        *payload_parts, provided_sig = token.split(":")
        payload = ":".join(payload_parts)
        session_id, user_id, role, _, expires_at_str = payload_parts
    except (ValueError, IndexError):
        raise HTTPException(status_code=401, detail="malformed_token")

    # Expiry check
    if int(time.time()) > int(expires_at_str):
        raise HTTPException(status_code=401, detail="token_expired")

    # Role key lookup
    key = ROLE_SIGNING_KEYS.get(role)
    if key is None:
        raise HTTPException(status_code=401, detail="unknown_role")

    # HMAC verification — timing-safe comparison
    expected_sig = hmac.new(
        key,
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=401, detail="invalid_signature")

    # Session store check
    stored = SESSION_STORE.get(session_id)
    if not stored:
        raise HTTPException(status_code=401, detail="session_not_found")

    return {"user_id": user_id, "role": role, "session_id": session_id}


# ── FastAPI Dependencies ──────────────────────────────────────────────────────

async def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    return validate_session_token(credentials.credentials)


async def require_super_admin(
    session: dict = Depends(get_current_session),
) -> dict:
    if session["role"] != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="super_admin_required")
    return session


async def require_any_admin(
    session: dict = Depends(get_current_session),
) -> dict:
    if session["role"] not in ("SUPER_ADMIN", "ADMIN"):
        raise HTTPException(status_code=403, detail="admin_required")
    return session


async def require_sdk_client(
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Validate SDK API key (separate from session tokens)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_api_key")
    api_key = authorization.removeprefix("Bearer ").strip()
    if api_key not in SDK_API_KEYS:
        raise HTTPException(status_code=401, detail="invalid_api_key")
    return {"api_key": api_key}


# ── Unauthorized Access Logger ────────────────────────────────────────────────

async def log_unauthorized_attempt(
    session_id: str,
    attempted_operation: str,
    eventlog,   # EventLog instance injected by caller
) -> None:
    """Called when ADMIN attempts SUPER_ADMIN-only operation."""
    await eventlog.write({
        "event_type": "unauthorized_access_attempt",
        "session_id": session_id,
        "attempted_operation": attempted_operation,
    })
```

---

### Part 4: HVP Contextual Validator

> _Placeholder — to be specified in the next part._

---

### Part 5: Control Plane — FastAPI Server and Worker Pool

> _Placeholder — to be specified in the next part._

---

### Part 6: RBAC, SessionToken, and Data Masking

> _Placeholder — to be specified in the next part._

---

### Part 7: EventLog, EventBus, and WebSocket Pipeline

> _Placeholder — to be specified in the next part._

---

### Part 8: HashDB and Policy Configuration

> _Placeholder — to be specified in the next part._
