# Design Document — PANTHEON (agent-sniffer)

## Overview

PANTHEON is a code and runtime security platform composed of two operating divisions — **ARES** (offensive, perimeter interception) and **ARGUS** (defensive, continuous background surveillance) — unified under a shared Control Plane, EventLog, EventBus, SDK, and Policy layer.

ARES intercepts Payloads at the perimeter using a sequential four-agent CrewAI Pipeline: Parser → Scanner → RedTeamer → Auditor. ARGUS monitors assets continuously using OS-level file system events, a three-layer filter, and HVP-aware threat enrichment.

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
│  │  │ Scanner Agent    │    │    │  Worker Pool (3 async workers)       │ │
│  │  │   Semgrep        │    │    │  ┌───────────────────────────┐       │ │
│  │  │   Joern+GNN      │    │    │  │ Layer 1: Extension Filter │       │ │
│  │  │ RedTeamer Agent  │    │    │  │ Layer 2: SHA-256 Hash Gate│       │ │
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

#### Parser Agent (CrewAI Pipeline — agent 1 of 4)

- Normalizes encoding (UTF-8), detects language, extracts structured AST representation.
- Outputs a `ParsedArtifact`: `{language, ast_json, normalized_text, metadata}`.

#### Scanner Agent (CrewAI Pipeline — agent 2 of 4)

- Runs Semgrep via subprocess with configured rule sets (local path or registry ID).
- Invokes Joern via subprocess to generate CPG; passes node/edge embeddings to the GNN inference component.
- Aggregates Semgrep Signals + GNN anomaly score into `ScanResult`.
- On Semgrep non-zero exit: logs `EventLog` entry, sets `scan_status=inconclusive`, continues.
- On Joern timeout (20 s): logs timeout, continues with Semgrep findings only.

#### RedTeamer Agent (CrewAI Pipeline — agent 3 of 4)

- Queries ChromaDB with embedding derived from Payload characteristics; retrieves top-K docs (default K=5).
- Calls Gemini API with retrieved docs + Payload summary.
- If Payload is classified suspicious by static scan or RAG: spawns sandbox execution.
- Outputs `RedTeamFindings`: `{rag_results, gemini_summary, sandbox_artifacts}`.

#### Auditor Agent (CrewAI Pipeline — agent 4 of 4)

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

**Layer 3 — AST/Regex Criticality & Heuristic Keyword Density Filter**

- Extract functions matching: auth patterns, crypto ops, DB queries, `eval`/`exec`/`subprocess`, network calls.
- Apply **Sliding Window Tokenizer**: 10 continuous lines window, density threshold > 2 tokens (`eval`, `exec`, `b64decode`, `subprocess`, `getattr`, `setattr`, `compile`, `__import__`, `base64`, `system`).
- If density threshold > 2, flag as `suspicious_low_entropy_paywall` and promote to `CodeChunk` for AI analysis regardless of Shannon entropy score.
- No critical patterns or density triggers → discard.
- Matching functions promoted to `CodeChunk` objects.

#### HVP Contextual Validator

- After Auditor produces `ThreatReport`, lookup `HVP_Profile` by role (git author email hash → path match → UNKNOWN).
- Apply `priority_multiplier` to the CVSSv3 base score (cap 10.0).
- Apply 2.0-point CVSSv3 confidence boost (cap 10.0) if threat vector matches profile.
- Route escalation via configured channels if final score ≥ `auto_escalation_threshold` (≥ 9.0).
- Special rules: `HRD_RECRUITMENT` → always route to sandbox regardless of Layer 3; `HVP_CALENDAR` → enable OSINT enrichment (attendee domain analysis).
- **ICS Bypass Gateway**: `.ics` branch at Layer 1; routes calendar assets to the
  dedicated ICS parser (`sdk/ics_parser.py`), skipping the token-length gate and
  Layers 2–3. Emits `CodeChunk(match_reason="ics_anomaly"|"ics_clean")` with
  `initial_context_score` for HVP_CALENDAR OSINT enrichment.

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
  ├── Scanner Agent
  │     Semgrep(artifact) → Signals[]
  │     Joern(artifact) → CPG → GNN → anomaly_score → Signal?
  │     → ScanResult
  │
  ├── RedTeamer Agent
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
  ├── Inspector (CrewAI Pipeline — shared with ARES)
  │     Sentry Gateway (pure-Python triage) → skip if not suspicious
  │     CrewAI Pipeline: Parser → Scanner → RedTeamer → Auditor
  │     → ThreatReport
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
Pipeline Worker Pool (asyncio.Semaphore(3))
  │── Sentry Gateway triage → suspicious? → run_in_executor → CrewAI Pipeline
  │     (Parser → Scanner → RedTeamer → Auditor)
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

#### Length Boundary Tokenizer & Shannon Entropy Calculator

Objective: Minimize CPU usage by filtering trivial tokens before deeper analysis, and flag high-entropy secret payloads.

Rules:

- Tokenize file content into single string tokens (split on whitespace).
- Only tokens with continuous character length > 60 (no spaces) proceed to further analysis.
- Tokens ≤ 60 characters are passed through (ignored/cleared) immediately.
- **Shannon Entropy Calculation (Ambiguitas 9 resolved):** For any token exceeding 60 characters, calculate Shannon Entropy $H = -\sum p(x) \log_2 p(x)$ in pure Python (using `math` and `collections.Counter`). If $H > 5.2$, assign a high risk-weight parameter (`high_entropy_secret_detected=True`) to the metadata packet, prioritizing the chunk for CrewAI Pipeline analysis.
- Rationale: Meaningful secrets, encoded payloads, and long high-entropy identifiers exceed 60 chars and $H > 5.2$. Short tokens (variable names, keywords) are not worth analyzing.
- **ICS Bypass Gateway (Ambiguitas 6 resolved):** calendar assets (`.ics`) are text
  payloads with no code-execution properties, so they always fail the >60 gate yet
  remain a critical phishing vector. If the extension is `.ics`, Layer 1 routes to
  the dedicated ICS parser instead of the tokenizer — the length rule is skipped
  entirely.

#### Logic Flow

```
FileSystemEvent (watchdog)
    ↓
[Folder Exclusion Check]   → excluded? → discard, log skip
    ↓
[Extension Filter]
    ├── .ics? → ICS Bypass Gateway → ICS parser (SUMMARY/DESCRIPTION/URL/ORGANIZER)
    │             → External Anomaly Flag? → elevate context score → CodeChunk
    └── non-code? → discard, log skip
    ↓ (code path only)
[Read file content]
    ↓
[Length Boundary Tokenizer & Shannon Entropy Calculator]
    tokenize → split on whitespace
    filter: keep tokens where len(token) > 60
    entropy evaluation: compute H = -sum(p * log2(p))
    H > 5.2? → attach high_entropy_secret_detected=True
    ↓
[Pass filtered tokens & entropy metadata to Layer 2 (SHA-256 Hash Gate)]
```

#### ICS Parser Module (`sdk/ics_parser.py`)

##### Objective

Inspect text-based calendar metadata for phishing indicators without executing
anything. Pure stdlib, no external ICS library.

**Validates: Requirements 9.8**

##### Logic Flow

```
.ics content
    ↓
[unfold lines] (RFC 5545: continuation lines start with space/tab → join)
    ↓
[extract per-VEVENT] SUMMARY, DESCRIPTION, URL, ORGANIZER (+ATTENDEE list)
    ↓
[anomaly checks]
    URL field with non-https scheme, punycode/IDN, IP host, or @-trick
      → External Anomaly Flag + context +1.5
    ORGANIZER/ATTENDEE domain ∉ trusted_domains → flag + context +1.0
    DESCRIPTION containing URL whose display text host ≠ link host
      → flag + context +2.0
    ↓
CodeChunk(match_reason="ics_anomaly" | "ics_clean",
          initial_context_score=elevated | 0.0) → HVP enrichment (HVP_CALENDAR OSINT)
```

##### Input/Output Schema

```
Input:  content: str (raw .ics), trusted_domains: list[str]
Output: ICSParseResult(external_anomaly: bool, flags: list[str],
        initial_context_score: float, fields: {summary, description, urls, organizer})
skip_reason baru: "ics_clean" (parsed, no anomaly — still forwarded with score 0.0,
  HVP_CALENDAR OSINT decides) — never "no_tokens_above_threshold" for .ics
```

##### Core Code Snippet

```python
# sdk/ics_parser.py — stdlib only, no code execution
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


@dataclass
class ICSParseResult:
    external_anomaly: bool = False
    flags: list[str] = field(default_factory=list)
    initial_context_score: float = 0.0
    fields: dict = field(default_factory=dict)


def _unfold(content: str) -> list[str]:
    """RFC 5545 line unfolding: space/tab-prefixed lines continue the previous."""
    lines: list[str] = []
    for raw in content.splitlines():
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _field(lines: list[str], name: str) -> list[str]:
    prefix = name.upper() + ":"
    alt = name.upper() + ";"
    return [ln.split(":", 1)[1] for ln in lines
            if ln.upper().startswith(prefix) or ln.upper().startswith(alt)]


def _url_anomalies(url: str) -> list[str]:
    out: list[str] = []
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ["malformed_url"]
    if urlparse(url).scheme != "https":
        out.append("non_https_url")
    if host.replace(".", "").isdigit() or ":" in host:
        out.append("ip_host_url")
    if "xn--" in host or "@" in url.split("/")[2] if "/" in url else "@" in url:
        out.append("deceptive_url")
    return out


def parse_ics(content: str, trusted_domains: list[str] | None = None) -> ICSParseResult:
    """Parse calendar metadata; flag external anomalies. Never executes content."""
    trusted = {d.lower() for d in (trusted_domains or [])}
    res = ICSParseResult()
    lines = _unfold(content)
    summaries = _field(lines, "SUMMARY")
    descriptions = _field(lines, "DESCRIPTION")
    urls = _field(lines, "URL") + [u for d in descriptions for u in _URL_RE.findall(d)]
    organizers = _field(lines, "ORGANIZER")
    res.fields = {"summary": summaries, "description": descriptions,
                  "urls": urls, "organizer": organizers}
    for url in urls:
        for flag in _url_anomalies(url):
            res.flags.append(f"url:{flag}:{url[:64]}")
    for org in organizers:
        m = re.search(r"mailto:([^@\s]+)@([^\s;>]+)", org, re.IGNORECASE)
        if m and m.group(2).lower() not in trusted:
            res.flags.append(f"organizer:untrusted_domain:{m.group(2)[:64]}")
    boost = sum(1.5 if f.startswith("url:") else 1.0 for f in res.flags)
    # ponytail: bobot flag statis; kalibrasi dari data phishing nyata bila tersedia
    if res.flags:
        res.external_anomaly = True
        res.initial_context_score = round(min(boost, 10.0), 1)
    return res
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
SHANNON_ENTROPY_THRESHOLD: float = 5.2  # H > 5.2 triggers high risk weight (Req 9.9)

# ── Shannon Entropy Helper ───────────────────────────────────────────────────

import math
from collections import Counter


def calculate_shannon_entropy(token: str) -> float:
    """Pure-Python Shannon Entropy calculator: H = -sum(p * log2(p))."""
    if not token:
        return 0.0
    length = len(token)
    counts = Counter(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_long_tokens(content: str) -> bool:
    """Evaluates tokens > 60 chars. Returns True if any exists."""
    return any(len(tok) > MIN_TOKEN_LENGTH for tok in content.split())


def _has_high_entropy_tokens(content: str) -> bool:
    """Evaluates tokens > 60 chars. Returns True if any token has H > 5.2."""
    tokens = [tok for tok in content.split() if len(tok) > MIN_TOKEN_LENGTH]
    return any(calculate_shannon_entropy(tok) > SHANNON_ENTROPY_THRESHOLD for tok in tokens)

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
    severity_level: str         # from CVSSv3 final: 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical
    base_score: float           # CVSSv3 0.0-10.0, Auditor score before multiplier
    final_score: float          # CVSSv3 0.0-10.0 = min(base*hvp_multiplier + boost, 10.0)
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
    auto_escalation_threshold: float    # CVSSv3 0.0-10.0, hardcoded >= 9.0
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

_For any_ valid `Payload`, the `agent_chain` field in the resulting `ThreatReport` is always `["Parser", "Scanner", "RedTeamer", "Auditor"]` in that order, regardless of payload content or size.

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

_For any_ Semgrep subprocess that exits with a non-zero return code, the `ScanResult.scan_status` is `"inconclusive"`, an EventLog entry records the error, and the pipeline continues to the RedTeamer Agent.

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

### Property 15: HVP final score is CVSSv3-capped and severity-mapped

_For any_ CVSSv3 `base_score` in [0.0, 10.0] and `HVP_Profile.priority_multiplier`, the `final_score` recorded in the EventLog equals `min(base_score * priority_multiplier + boost, 10.0)` where `boost` is 2.0 if the detected threat vector matches the profile's `threat_vectors` else 0.0; `severity_level` is then `low` for 0.0–3.9, `medium` for 4.0–6.9, `high` for 7.0–8.9, `critical` for 9.0–10.0.

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
event_path (str) + asset_owner_role (str)
    ↓
[HRD_RECRUITMENT Override Check]
    asset_owner_role == "HRD_RECRUITMENT"?
    → YES: Bypass L0/L1/L2/L3 penuh (cegah telemetry starvation / false-positive hash bomb)
           baca file → CodeChunk(match_reason="force_sandbox_hrd")
           → FilterResult(passed=True) → ForensicExtractor → HTTP POST ke Control Plane
    ↓ NO
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
    event_path: str          — absolute file path from watchdog event
    asset_owner_role: str    — resolved role (default: "UNKNOWN")

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
            None  (passed, match_reason="force_sandbox_hrd" jika HRD)

CodeChunk
    file_path_hash: str      — SHA-256(original_file_path)
    function_name: str       — "<document_raw>" untuk HRD_RECRUITMENT
    source_text: str         — raw file content / function body (deleted after ForensicExtractor)
    match_reason: str        — Layer 3 label atau "force_sandbox_hrd"
    asset_owner_role: str    — resolved by HVP Validator
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
SHANNON_ENTROPY_THRESHOLD: float = 5.2  # H > 5.2 triggers high risk weight (Req 9.9)

# ── Shannon Entropy Helper ───────────────────────────────────────────────────

import math
from collections import Counter


def calculate_shannon_entropy(token: str) -> float:
    """Pure-Python Shannon Entropy calculator: H = -sum(p * log2(p))."""
    if not token:
        return 0.0
    length = len(token)
    counts = Counter(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_long_tokens(content: str) -> bool:
    """Evaluates tokens > 60 chars. Returns True if any exists."""
    return any(len(tok) > MIN_TOKEN_LENGTH for tok in content.split())


def _has_high_entropy_tokens(content: str) -> bool:
    """Evaluates tokens > 60 chars. Returns True if any token has H > 5.2."""
    tokens = [tok for tok in content.split() if len(tok) > MIN_TOKEN_LENGTH]
    return any(calculate_shannon_entropy(tok) > SHANNON_ENTROPY_THRESHOLD for tok in tokens)

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

# Sliding Window Tokenizer Constants (Ambiguitas 5 resolved)
SLIDING_WINDOW_SIZE: int = 10  # continuous lines
DENSITY_WEIGHT_THRESHOLD: int = 2  # tokens per window
DENSITY_TOKENS: frozenset[str] = frozenset({
    "eval", "exec", "b64decode", "subprocess", "getattr",
    "setattr", "compile", "__import__", "base64", "system"
})


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

def _check_keyword_density(source: str) -> bool:
    """Sliding Window Tokenizer: hit jika akumulasi token sensitif > 2 dalam window 10 baris."""
    lines = source.splitlines()
    if len(lines) < 1:
        return False
    for i in range(len(lines)):
        window_lines = lines[i : i + SLIDING_WINDOW_SIZE]
        window_text = " ".join(window_lines)
        tokens = re.findall(r"\b\w+\b", window_text.lower())
        count = sum(1 for tok in tokens if tok in DENSITY_TOKENS)
        if count > DENSITY_WEIGHT_THRESHOLD:
            return True
    return False


def _match_critical(source: str) -> str | None:
    """Return the first matched pattern label, low-entropy paywall flag, or None."""
    for pattern, label in CRITICAL_PATTERNS:
        if re.search(pattern, source):
            return label
    if _check_keyword_density(source):
        return "suspicious_low_entropy_paywall"
    return None


# ── Public Entry Point ───────────────────────────────────────────────────────

def pre_filter(
    event_path: str,
    hashdb: HashDB | None = None,
    asset_owner_role: str = "UNKNOWN",
) -> FilterResult:
    # Force Sandbox Protocol for HRD_RECRUITMENT (Ambiguitas 7, Req 10.6):
    # dokumen CV/Resume dari vektor rekrutmen eksternal rentan infostealer.
    # Karena file selalu baru, Layer 2 (Hash Gate) & Layer 3 (AST Filter) di-bypass
    # penuh untuk mencegah telemetry starvation dan false-positive hash bypass.
    if asset_owner_role == "HRD_RECRUITMENT":
        try:
            content = Path(event_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return FilterResult(passed=False, skip_reason="read_error")
        file_path_hash = hashlib.sha256(event_path.encode()).hexdigest()
        chunk = CodeChunk(
            file_path_hash=file_path_hash,
            function_name="<document_raw>",
            source_text=content,
            match_reason="force_sandbox_hrd",
            asset_owner_role="HRD_RECRUITMENT",
        )
        return FilterResult(passed=True, chunks=[chunk])

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
    base_score: float   # CVSSv3 0.0-10.0
    final_score: float  # CVSSv3 0.0-10.0
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
    auto_escalation_threshold: float = 9.0  # CVSSv3, hardcoded >= 9.0
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
    auto_escalation_threshold: float = Field(default=9.0, ge=9.0, le=10.0)
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

### Part 3: FastAPI Ingestion & RBAC Core

Consolidated: Part 3 absorbs all transport/submission, authentication, session, and
access-control specs. The former Part 6 (RBAC, SessionToken, Data Masking) is folded
here; the standalone Part 6 heading is removed. Canonical masking rules and RBAC
matrix live in `## Security Design`; this Part holds the ingestion + enforcement code.

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
[User Rate Limiting & Throttling Engine] (Req 15.10 — Anti Denial of Wallet)
    check_user_rate(client_id / user_token) > USER_RPM_CEILING (default: 10 RPM)?
    ├── YES: return HTTP 429 {"detail": "rate_limit_exceeded", "retry_after": 60}
    │        place job into USER_SUSPENDED_QUEUE[client_id] (memory-bounded holding queue)
    └── NO:  proceed
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

# Pipeline Worker queue — shared across all workers
SERVER_SCAN_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=5_000)

# Per-User Throttling & Suspended Queue Engine (Ambiguitas 10, Req 15.10)
USER_RPM_CEILING: int = 10  # max 10 RPM per user/device signature
USER_TRANSACTIONS: dict[str, list[float]] = {}  # client_id -> timestamps
USER_SUSPENDED_QUEUE: dict[str, asyncio.Queue] = {}  # client_id -> bounded holding queue


def check_and_track_user_rate(client_id: str, limit: int = USER_RPM_CEILING) -> bool:
    """Return True if under rate ceiling, False if burst threshold exceeded."""
    now = datetime.now(timezone.utc).timestamp()
    timestamps = USER_TRANSACTIONS.setdefault(client_id, [])
    # purge timestamps older than 60s
    USER_TRANSACTIONS[client_id] = [t for t in timestamps if now - t < 60.0]
    if len(USER_TRANSACTIONS[client_id]) >= limit:
        return False
    USER_TRANSACTIONS[client_id].append(now)
    return True


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.post("/jobs", status_code=200)
async def receive_job(
    payload: SubmissionPayload,
    _client: dict = Depends(require_sdk_client),
) -> dict:
    """
    Accept a SubmissionPayload from the SDK.
    Enforces per-user rate ceiling (10 RPM); suspends overflow, returns 429 on burst.
    """
    client_id = payload.client_id or payload.file_path_hash

    if not check_and_track_user_rate(client_id):
        # Throttle stream, place into memory-bounded suspended holding queue
        holding_queue = USER_SUSPENDED_QUEUE.setdefault(client_id, asyncio.Queue(maxsize=100))
        try:
            holding_queue.put_nowait({"chunk": payload, "submitted_at": utcnow_iso()})
        except asyncio.QueueFull:
            pass  # bound memory, drop if holding queue full
        raise HTTPException(
            status_code=429,
            detail="rate_limit_exceeded",
            headers={"Retry-After": "60"},
        )

    if SERVER_SCAN_QUEUE.full():
        raise HTTPException(status_code=503, detail="queue_full")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "chunk": payload,
        "submitted_at": utcnow_iso(),
        "client_id": client_id,
    }

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

### Part 4: HVP IDENTITY & THREAT MATCHER WITH ANTI-SPOOFING

#### Modules: `hvp/identity.py`, `hvp/matcher.py`

---

#### `hvp/identity.py` — GPG Validation

##### Objective

Verifikasi identitas penulis commit via GPG signature (`git verify-commit`) sebelum HVP role resolution dipercaya. Commit pada aset Critical/High tanpa signature valid → `identity_spoofing_detected=True`, eskalasi ke SUPER_ADMIN apapun Severity routing aktif.

**Validates: Requirements 10.13**

##### Logic Flow

```
ForensicContext.git_commit_hash + resolved role (severity_weight CRITICAL/HIGH)
    ↓
subprocess: git verify-commit <hash> (timeout 5s)
    ├── returncode 0 → valid → identity_spoofing_detected=False → lanjut normal
    └── returncode != 0 / timeout / git hilang:
          ├── stderr ∈ {"untrusted_key", "expired_key"} AND author_email_hash ∈ internal_employee_directory?
          │     ├── YES: [Cryptographic Key Lifecycle Grace Period]
          │     │        ├── Tahan status di MEDIUM (Pending Key Verification)
          │     │        ├── Pasang flag "WARM LOCK" pada commit di EventLog
          │     │        └── Terbitkan & kirim HMAC bootstrap token otomatis ke dev untuk self-remediation
          │     └── NO:  → identity_spoofing_detected=True
          │              → EventLog entry + threat_report.spoof_detail = {commit_hash, reason}
          │              → eskalasi SUPER_ADMIN channel, bypass Severity routing
role MEDIUM/LOW → skip verify, flag=False
```

##### Input/Output Schema

```
Input:  git_commit_hash: str | None, severity_weight: str,
        author_email_hash: str | None = None,
        employee_directory: EmployeeDirectory | None = None,
        grace_hours: int = 72
Output: IdentityVerdict(is_spoofed: bool, reason: str | None, detail: dict | None)
        reason ∈ {"invalid_signature","untrusted_key","expired_key","no_signature",
                  "git_unavailable","timeout","warm_lock", None}
        warm_lock → tahan MEDIUM (Pending Key Verification) + WARM LOCK commit
                     + bootstrap token di detail (Req 10.14-10.15)
```

##### Core Code Snippet

```python
# hvp/identity.py
from __future__ import annotations

import hashlib
import hmac
import secrets
import subprocess
import time
from dataclasses import dataclass


_BOOTSTRAP_KEY: bytes = secrets.token_bytes(32)  # in-memory only, rotasi tiap startup


@dataclass
class IdentityVerdict:
    is_spoofed: bool
    reason: str | None = None
    # reason "warm_lock" -> Grace Period: tahan di MEDIUM (Pending Key
    # Verification), commit di-WARM LOCK, bootstrap token diterbitkan
    # (Req 10.14-10.15). reason kini mencakup "expired_key".
    detail: dict | None = None


_VERIFY_TIMEOUT_S = 5
_GATED_WEIGHTS = frozenset({"CRITICAL", "HIGH"})
_GRACE_HOURS_DEFAULT = 72  # Req 10.15


def issue_bootstrap_token(author_email_hash: str, git_commit_hash: str,
                          grace_hours: int = _GRACE_HOURS_DEFAULT) -> str:
    """Terbitkan token bootstrap rotasi kunci (HMAC, single-use, kedaluwarsa).

    Token dikirim ke pengembang untuk validasi mandiri; redeem dengan
    kunci GPG baru dalam grace window menghapus WARM LOCK (Req 10.15).
    """
    payload = f"{author_email_hash}:{git_commit_hash}:{time.time() + grace_hours * 3600}"
    return hmac.new(_BOOTSTRAP_KEY, payload.encode(), hashlib.sha256).hexdigest() + "." + payload


def verify_commit_identity(
    git_commit_hash: str | None,
    severity_weight: str,
    author_email_hash: str | None = None,
    employee_directory: object | None = None,
    grace_hours: int = 72,
) -> IdentityVerdict:
    """GPG-verify commit. Hanya role CRITICAL/HIGH yang digate.

    Cryptographic Key Lifecycle Grace Period (Req 10.14-10.15):
    untrusted/expired key + email dikenal di direktori internal
    -> warm_lock, bukan alarm darurat; bootstrap token diterbitkan.
    """
    if severity_weight not in _GATED_WEIGHTS:
        return IdentityVerdict(is_spoofed=False)
    if not git_commit_hash:
        return IdentityVerdict(is_spoofed=True, reason="no_signature")
    try:
        result = subprocess.run(
            ["git", "verify-commit", git_commit_hash],
            capture_output=True, text=True, timeout=_VERIFY_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return IdentityVerdict(is_spoofed=True, reason="timeout")
    except (FileNotFoundError, OSError):
        return IdentityVerdict(is_spoofed=True, reason="git_unavailable")
    if result.returncode == 0:
        return IdentityVerdict(is_spoofed=False)
    stderr = (result.stderr or "").lower()
    if "no signature" in stderr or "not signed" in stderr:
        reason = "no_signature"
    elif "expired" in stderr:
        reason = "expired_key"
    elif "can't check signature" in stderr or "no public key" in stderr:
        reason = "untrusted_key"
    else:
        reason = "invalid_signature"
    if reason in ("untrusted_key", "expired_key") and employee_directory is not None:
        if author_email_hash and employee_directory.is_known(author_email_hash):
            token = issue_bootstrap_token(author_email_hash, git_commit_hash, grace_hours)
            return IdentityVerdict(is_spoofed=False, reason="warm_lock",
                                   detail={"bootstrap_token": token,
                                           "grace_hours": grace_hours})
    return IdentityVerdict(is_spoofed=True, reason=reason)
```

---

#### `hvp/matcher.py` — Threat Intelligence Multiplier

##### Objective

Pencocokan kontekstual per role: multiplier skor + boost keyakinan + modul khusus (OSINT calendar, supply-chain Lead Dev, sandbox-paksa HRD).

**Validates: Requirements 10.2–10.8, 10.10–10.12**

##### Logic Flow

```
ThreatReport(base_score, threat_vector) + HVP_Profile + ForensicContext
    ↓
[1. Role resolution] email-hash git author → path pattern
    → matched: apply HVP_Profile (multiplier + boost + routing)
    → NO MATCH: UNKNOWN_HIGH_RISK (Zero Trust — Req 10.9)
        base_score floor = 7.0 (high), force deep analysis,
        EventLog identity_resolved=False, zero_trust_escalation=True
    ↓
[2. Score] final = min(base * priority_multiplier + (2.0 jika threat_vector cocok), 10.0)
    → severity_from_score(final): 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical
    ↓
[3. Modul khusus per role]
    CEO (Critical, 2.0x): langsung → SMS+email+CP jika ≥ threshold
    LEAD_DEV (High, 1.5x): pola supply chain (registry/CI/manifest/secret repo)
        → skor ×1.2 tambahan, cap 100
    HVP_CALENDAR (Medium, 1.2x): OSINT — domain attendee ∉ trusted
        + (umur <365h atau typosquat) → Signal medium
    HRD_RECRUITMENT (Low, 1.0x): file eksternal → sandbox, abaikan Layer 3
    ↓
[4. Routing] final ≥ auto_escalation_threshold (≥ 9.0) → containment + channel profil
    UNKNOWN_HIGH_RISK → base_score floor 7.0 → full CrewAI Pipeline (no skip)
```

##### Input/Output Schema

```
Input:  base_score: float (CVSSv3 0.0-10.0), threat_vector: str, profile: HVP_Profile | None,
        forensic: ForensicContext, calendar_invite: dict | None
Output: MatchResult(final_score CVSSv3 0.0-10.0, severity_weight, targeted_asset_hit: bool,
        escalate: bool, channels: list[str], osint_signal: Signal | None,
        force_sandbox: bool)
```

##### Core Code Snippet

```python
# hvp/matcher.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass

SUPPLY_CHAIN_BOOST = 1.2
VECTOR_BOOST = 2.0  # CVSSv3 points (was 20 percentage points on 0-100 scale)
CVSS_MAX = 10.0


def severity_from_score(score: float) -> str:
    """CVSSv3 severity mapping: 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class MatchResult:
    final_score: float
    severity_weight: str
    targeted_asset_hit: bool
    escalate: bool
    channels: list[str]
    force_sandbox: bool = False


UNKNOWN_HIGH_RISK_PROFILE = object()  # sentinel — no multiplier, floor 7.0
UNKNOWN_HIGH_RISK_SCORE_FLOOR = 7.0   # CVSSv3 high (Zero Trust, Req 10.9)


def resolve_role(forensic_email: str | None, file_path: str,
                 profiles: list) -> object | None:
    """Resolve HVP profile. Returns matched profile or None (→ UNKNOWN_HIGH_RISK).

    Zero Trust: None here means HIGH RISK, never low risk (Ambiguitas 4, Req 10.9).
    """
    for profile in profiles:
        if forensic_email and any(p in forensic_email
                                  for p in profile.email_patterns):
            return profile
        if any(p in file_path for p in profile.path_patterns):
            return profile
    return None  # caller MUST treat None as UNKNOWN_HIGH_RISK


def apply_matcher(base_score: float, threat_vector: str, profile,
                  monitored_hit: bool, supply_chain_hit: bool = False) -> MatchResult:
    """All scores CVSSv3 0.0-10.0. Escalation at >= 9.0 triggers containment (Req 7)."""
    final = base_score * profile.priority_multiplier
    if threat_vector in profile.threat_vectors:
        final = min(final + VECTOR_BOOST, CVSS_MAX)
    if profile.role == "LEAD_DEV_DEVOPS" and supply_chain_hit:
        # ponytail: bobot statis; ganti model ML bila data supply-chain cukup
        final = min(final * SUPPLY_CHAIN_BOOST, CVSS_MAX)
    final = round(min(final, CVSS_MAX), 1)
    return MatchResult(
        final_score=final,
        severity_weight=severity_from_score(final),
        targeted_asset_hit=monitored_hit,
        escalate=final >= profile.auto_escalation_threshold,  # >= 9.0 enforced by Policy
        channels=list(profile.escalation_channels),
        force_sandbox=profile.role == "HRD_RECRUITMENT",
    )


def email_sha256(email: str) -> str:
    """Email author hanya disimpan sebagai hash (Req 10.11)."""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()
```

OSINT calendar (`check_invite_domains()` → Signal medium bila domain tak terpercaya + muda/typosquat, Req 10.12) ikut modul ini saat implementasi.

---

### Part 4b: DETACHED METADATA INDEXING (Zero-Knowledge Path Privacy)

#### Modules: `sdk/path_index.py`, local SDK agent (`sdk/local_agent.py`)

#### Objective

Keep the Control Plane blind to the developer's directory tree while keeping the
dashboard readable. The SDK transmits only `SHA-256(absolute_path)` for identity
mapping plus a `RelativeMaskedPath` (`[root]/<repo-relative-path>`) for display.
The absolute-path → hash map lives in a machine-local SQLite index owned by a
stateful local SDK agent; inverse resolution (hash → physical path) executes only
on the developer machine. A stolen server DB yields hashes, not paths.

**Validates: Requirements 15.2, 15.8, 15.9, 16.1**

#### Logic Flow

```
watchdog event (absolute path, SDK worker memory only)
    ↓
[path_index.register(absolute_path)]
    file_path_hash = SHA-256(abs)
    relative_masked_path = "[root]/" + repo_relative(abs)   # strip machine prefix
    local SQLite upsert {file_path_hash → absolute_path}    # NEVER uploaded
    ↓
SubmissionPayload → Control Plane carries ONLY hash + masked path
    ↓
dashboard shows "[root]/src/auth.py" (from masked path, never absolute)
    ↓ drill-down / patch-apply needed
local SDK agent resolves hash → absolute path IN-PROCESS (loopback only)
```

Repo-root anchoring: `repo_relative()` resolves against the enclosing git top-level
(`git rev-parse --show-toplevel`); non-git trees fall back to the configured
`watch_path`. Paths escaping the anchor are rejected (`..` traversal → `ValueError`).

#### Input/Output Schema (Pydantic / JSON)

```python
# sdk/path_index.py — wire + local models
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from pydantic import BaseModel, Field


class PathIdentity(BaseModel):
    """Identity material attached to every SubmissionPayload (Req 15.2)."""
    file_path_hash: str = Field(pattern=r"^[0-9a-f]{64}$")  # SHA-256 hex
    relative_masked_path: str = Field(pattern=r"^\[root\]/\S+$")  # e.g. [root]/src/auth.py


class LocalPathRecord(BaseModel):
    """Machine-local index row. NEVER serialized to the wire (Req 15.8)."""
    file_path_hash: str
    absolute_path: str  # local disk only


def derive_identity(absolute_path: str, anchor: str) -> PathIdentity:
    """Hash + masked display path. Raises ValueError on anchor escape."""
    rel = Path(absolute_path).resolve().relative_to(Path(anchor).resolve())
    if ".." in rel.parts:
        raise ValueError("path escapes anchor")
    return PathIdentity(
        file_path_hash=hashlib.sha256(absolute_path.encode("utf-8")).hexdigest(),
        relative_masked_path="[root]/" + rel.as_posix(),
    )


class LocalPathIndex:
    """Stateful machine-local agent store: hash → absolute path."""

    def __init__(self, db_path: str = ".pantheon/paths.db") -> None:
        self._db = sqlite3.connect(db_path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS paths"
            " (file_path_hash TEXT PRIMARY KEY, absolute_path TEXT NOT NULL)"
        )

    def register(self, absolute_path: str, anchor: str) -> PathIdentity:
        identity = derive_identity(absolute_path, anchor)
        self._db.execute(
            "INSERT OR REPLACE INTO paths VALUES (?, ?)",
            (identity.file_path_hash, absolute_path),
        )
        self._db.commit()
        return identity

    def resolve_local(self, file_path_hash: str) -> str | None:
        """Inverse resolution — loopback/local-process only (Req 15.9)."""
        row = self._db.execute(
            "SELECT absolute_path FROM paths WHERE file_path_hash = ?",
            (file_path_hash,),
        ).fetchone()
        return row[0] if row else None
```

```json
// SubmissionPayload.path_identity — the ONLY path material on the wire
{
  "file_path_hash": "9f2c…a41d",
  "relative_masked_path": "[root]/src/auth.py"
}
```

#### Server-Blindness Contract

- `SubmissionPayload`, `ForensicContext`, `EventLogEntry`, `ThreatReport`, WebSocket
  payloads: **hash + masked path only** — an absolute path string in any of these is a
  spec violation (caught by Property 21).
- `ForensicContext` gains `relative_masked_path: str`; its former raw `file_path`
  field is removed (Req 16.1 amended). HVP path-pattern matching (Req 10.10) and
  GPG-gated identity (Part 4) operate on the masked relative form.
- `POST /api/v1/scan {file_path}` (manual scan, § API Design) accepts a
  `relative_masked_path` or hash only — absolute paths rejected with 422.
- Dashboard drill-down / patch-apply calls the developer machine's local agent;
  the Control Plane proxies an opaque `resolve_request{file_path_hash}` and relays
  back only the operator-confirmed action, never the path.

#### Correctness Property (new)

**Property 24: Pipeline Worker stores never contain an absolute path.**
_For any_ `SubmissionPayload`, `EventLogEntry`, or WebSocket broadcast examined
server-side, no field matches an absolute-path pattern (`^[A-Za-z]:\\`, `^/`,
`^\\\\`); identity is carried by `file_path_hash` and display by
`relative_masked_path` only.

**Validates: Requirements 15.2, 15.8, 15.9**

---

### Part 5: Multi-Agent Outputs & Event Bus

Consolidated (Step 4): Part 5 absorbs all post-analysis output specs — decision routing,
server worker pool, JSONL SIEM writer, EventBus dispatch, WebSocketManager routing,
and dashboard alert contract. The former Part 7 (EventLog, EventBus, WebSocket
Pipeline) is folded here; no standalone Part 7 remains.

#### Modules: `pipeline/` (CrewAI Pipeline), `inspector/decision.py`, `control_plane/workers.py`, `control_plane/eventlog.py`, `control_plane/ws/`

---

#### `pipeline/` — CrewAI Workers (async, rate-limited)

##### Objective

Run Parser → Scanner → RedTeamer → Auditor sequentially per job, off the asyncio event loop, under layered LLM-cost guards (pre-filter → Sentry Gateway triage → concurrency semaphore → token bucket → per-call timeouts) so a single client cannot burn the Gemini free-tier quota (anti Denial-of-Wallet).

Terminology contract (Ambiguitas 3 resolved): entry-point triage is the pure-Python
**Sentry Gateway** (not an agent, no LLM calls); heavy async backend work is the
**CrewAI Pipeline** of exactly 4 agents. The names `SentryAgent` and
`TrafficCodeAnalyzer` are retired and SHALL NOT appear in code or new docs.

#### `gateway/sentry.py` — Sentry Gateway (pure-Python triage)

##### Objective

Single entry-point triage on the FastAPI server. Validates, deduplicates, and
fast-triages each job before it may enter the expensive CrewAI Pipeline. Pure Python,
no LLM calls, no agent framework — deterministic and cheap.

**Validates: Requirements 16.8**

##### Logic Flow

```
Pipeline Worker dequeues job {job_id, chunk, submitted_at, client_id}
    ↓
[Sentry Gateway — pure Python]
    validate SubmissionPayload schema → 422-style reject + EventLog
    dedupe: file_path_hash + evidence_hash seen? → drop duplicate + EventLog
    fast triage heuristics (no LLM): Layer-3 match_reason severity hint,
        evidence_hash blocklist, client rate flags
    ↓ clean → log triage result, release job, NO CrewAI invocation
    ↓ suspicious → forward to CrewAI Pipeline (run_in_executor)
```

##### Input/Output Schema

```
Input:  job dict {job_id, chunk: SubmissionPayload, submitted_at, client_id}
Output: TriageVerdict(clean | suspicious, reason: str)
Side effects (clean): EventLog triage entry, job released, zero LLM tokens spent
Side effects (suspicious): job handed to CrewAI Pipeline via run_in_executor
```

##### Core Code Snippet

```python
# gateway/sentry.py — pure Python, no LLM, no agent framework
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class TriageVerdict:
    disposition: Literal["clean", "suspicious"]
    reason: str


class SentryGateway:
    """Entry-point triage. Deterministic; safe to run on the event loop."""

    def __init__(self, blocklist: set[str] | None = None) -> None:
        self._seen: set[tuple[str, str]] = set()  # (file_path_hash, evidence_hash)
        self._blocklist = blocklist or set()

    def triage(self, job: dict) -> TriageVerdict:
        chunk = job["chunk"]
        key = (chunk.file_path_hash, chunk.evidence_hash)
        if key in self._seen:
            return TriageVerdict("clean", "duplicate_of_processed_job")
        self._seen.add(key)
        if chunk.evidence_hash in self._blocklist:
            return TriageVerdict("suspicious", "evidence_blocklist_hit")
        if chunk.match_reason in ("exec", "crypto", "auth"):
            return TriageVerdict("suspicious", f"critical_match:{chunk.match_reason}")
        return TriageVerdict("clean", "no_triage_signal")
```

#### CrewAI Pipeline — 4 agents, sequential, no exceptions

Parser Agent → Scanner Agent → RedTeamer Agent → Auditor Agent. Exactly these four
names, exactly this order (`AGENT_CHAIN`). Any future agent joins only via a spec
amendment; ad-hoc additions (e.g. a fifth "triage agent") are a spec violation
caught by Property 3.

**Validates: Requirements 2.1–2.7, 16.8–16.10**

##### Logic Flow

```
SERVER_SCAN_QUEUE job {job_id, chunk, submitted_at, client_id}
    ↓
Pipeline Worker (Semaphore(3) caps concurrent pipelines)
    ↓
Sentry Gateway triage → clean? → log + release, zero LLM tokens
    ↓ suspicious
TokenBucket.acquire() — 14 RPM shared (Gemini free tier)
    ↓
run_in_executor → crew.kickoff() — sync CrewAI, 30s hard timeout
    Parser → Scanner → RedTeamer → Auditor (sequential, async_execution=True)
    ↓ any agent raises → fail-closed: severity "high" + EventLog(agent_id, reason), chain stops
    ↓
ThreatReport → decision.route() → post_audit_hook()
```

Cost-guard layers, outermost first: L0–L3 pre-filter (Part 1) → Sentry Gateway triage skip (Req 16.8, suspicious-only deep analysis) → `Semaphore(3)` → token bucket 14 RPM → per-call timeouts (Gemini 15s, Joern 20s, sandbox 10s) → HTTP 429 backoff 60s + front re-queue.

##### Input/Output Schema

```
Input:  job dict {job_id: str, chunk: SubmissionPayload, submitted_at: str, client_id: str}
Output: ThreatReport {severity, matched_patterns, remediation_summary, patch_diff?,
        signals, agent_chain=["Parser","Scanner","RedTeamer","Auditor"],
        pipeline_duration_ms, patch_source}
Raises: never to caller — every failure path returns fail-closed ThreatReport(severity="high")
```

##### Core Code Snippet

```python
# pipeline/crew.py
from __future__ import annotations

import asyncio
import time

from crewai import Agent, Crew, Process, Task

from shared.models import ThreatReport

PIPELINE_TIMEOUT_S = 30
AGENT_CHAIN = ["Parser", "Scanner", "RedTeamer", "Auditor"]


def build_crew(payload: dict, tools: dict) -> Crew:
    """Four agents, strictly sequential. Each task feeds the next."""
    parser = Agent(role="Parser", goal="Normalize payload and detect language",
                   backstory="...", tools=[tools["parse"]], async_execution=True)
    scanner = Agent(role="Scanner", goal="SAST + CPG/GNN anomaly scan",
                    backstory="...", tools=[tools["semgrep"], tools["cpg_gnn"]],
                    async_execution=True)
    red = Agent(role="RedTeamer", goal="RAG intel + sandbox DAST on suspicious payloads",
                backstory="...", tools=[tools["rag"], tools["sandbox"]],
                async_execution=True)
    auditor = Agent(role="Auditor", goal="Consolidate findings into ThreatReport",
                    backstory="...", async_execution=True)
    tasks = [
        Task(description="parse", agent=parser, expected_output="ParsedArtifact"),
        Task(description="scan", agent=scanner, expected_output="ScanResult"),
        Task(description="redteam", agent=red, expected_output="RedTeamFindings"),
        Task(description="audit", agent=auditor, expected_output="ThreatReport"),
    ]
    return Crew(agents=[parser, scanner, red, auditor], tasks=tasks,
                process=Process.sequential)


def run_pipeline_sync(job: dict, tools: dict) -> ThreatReport:
    """Sync entry point — always called inside run_in_executor, never on the loop."""
    started = time.monotonic()
    try:
        crew = build_crew(job["chunk"], tools)
        # CrewAI kickoff is blocking; caller wraps this fn in wait_for(30s).
        result = crew.kickoff()
        return ThreatReport.from_crew_result(result, duration_ms=_elapsed_ms(started))
    except Exception as exc:  # fail-closed (Req 2.6): no partial chain is trusted
        return ThreatReport.fail_closed(reason=repr(exc), duration_ms=_elapsed_ms(started))
```

```python
# pipeline/static_scanner.py
from __future__ import annotations

import subprocess

from shared.models import Signal

JOERN_TIMEOUT_S = 20


def semgrep_scan(artifact: dict, rule_sets: list[str]) -> list[Signal]:
    """Pattern SAST. Non-zero exit → inconclusive, pipeline continues (Req 3.5)."""
    proc = subprocess.run(["semgrep", "--json", "--config", *rule_sets, artifact["path"]],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        return [Signal(severity="unknown", pattern_id="semgrep_error",
                       source="semgrep", confidence=0.0,
                       description="inconclusive: semgrep exit != 0")]
    return [Signal(severity=m["severity"], pattern_id=m["rule_id"], source="semgrep",
                   confidence=1.0, description=m["message"])
            for m in parse_semgrep_json(proc.stdout)]


def cpg_gnn_scan(artifact: dict, gnn: object, threshold: float) -> list[Signal]:
    """Data-flow anomaly via Joern CPG + GNN. Timeout → Semgrep-only (Req 4.5)."""
    if artifact["language"] not in ("python", "javascript", "typescript", "java"):
        return []
    try:
        cpg = subprocess.run(["joern", "--script", "cpg.sc", artifact["path"]],
                             capture_output=True, text=True, timeout=JOERN_TIMEOUT_S)
        score: float = gnn.infer(cpg.stdout)  # pre-trained model, loaded at startup
    except subprocess.TimeoutExpired:
        return []  # caller logs timeout to EventLog
    if score > threshold:
        return [Signal(severity="high", pattern_id="gnn_anomaly", source="gnn",
                       confidence=score, description=f"data-flow anomaly {score:.2f}")]
    return []
```

```python
# pipeline/red_teamer.py
from __future__ import annotations

import asyncio

GEMINI_TIMEOUT_S = 15
SANDBOX_TIMEOUT_S = 10


async def rag_exploit_intel(payload_summary: str, chroma, gemini, top_k: int = 5) -> dict:
    """ChromaDB top-K CVE/OWASP retrieval + Gemini summary (Req 6.1–6.2)."""
    docs = chroma.query(payload_summary, n_results=top_k)  # never more than K (Prop 8)
    try:
        summary = await asyncio.wait_for(gemini.summarize(docs, payload_summary),
                                         timeout=GEMINI_TIMEOUT_S)
    except (asyncio.TimeoutError, Exception):
        summary = None  # retrieval-only fallback, failure logged (Req 6.5)
    return {"rag_results": docs, "gemini_summary": summary}


async def sandbox_dast(payload: bytes, runner) -> dict:
    """Ephemeral isolated exec; 10s hard kill, partial artifacts kept (Req 5.4)."""
    try:
        return await asyncio.wait_for(runner.exec_isolated(payload),
                                      timeout=SANDBOX_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"timeout": True, "stdout": b"", "stderr": b"timeout after 10s"}
```

```python
# pipeline/auditor.py
from __future__ import annotations

from shared.models import ThreatReport


def consolidate(parsed: dict, scan_signals: list, red_findings: dict) -> ThreatReport:
    """Single owner of the final Severity + remediation summary (Req 2.5)."""
    severity = max_severity([s.severity for s in scan_signals] + ["low"])
    if red_findings.get("sandbox", {}).get("malicious"):
        severity = "critical"
    return ThreatReport(
        severity=severity,
        matched_patterns=[s.pattern_id for s in scan_signals],
        remediation_summary=build_remediation(scan_signals, red_findings),
        signals=scan_signals,
        agent_chain=["Parser", "Scanner", "RedTeamer", "Auditor"],
    )
```

---

#### `inspector/decision.py` — Severity Routing

##### Objective

Map the Auditor's final Severity to exactly one action. Critical/High act immediately without humans; Medium holds the payload and pulls a human in; Low passes.

**Validates: Requirements 7.1–7.6, 11.1–11.6**

##### Logic Flow

```
ThreatReport.severity
    ├── critical / high → Policy.severity_routing[sev] (default: block)
    │     runtime payload + block   → Gateway rejects, PolicyBlockError to Client
    │     source payload + patch    → Gemini diff; Gemini down → template patch (flagged)
    ├── medium → HOLD: Gateway pending queue (never forwarded) + escalation
    │     (email / Slack / HTTP POST, 60s timeout → Policy default block|allow)
    │     + WS summary → Red Alert popup (see amendment note below)
    └── low → allow; EventLog only
```

> **Spec amendment note:** the Medium → WebSocket push below is now covered by
> Requirement 14 AC#7/AC#12 (`requirements.md`, amended 2026-09-24).
> Design Part 5 and requirements are consistent.

##### Input/Output Schema

```
Input:  report: ThreatReport, job: dict (asset_type: "source_code" | "runtime_payload")
Output: action: "block" | "patch" | "hold_escalate" | "allow"
Side effects: Gateway reject / patch attach / pending-queue hold + escalation dispatch
```

##### Core Code Snippet

```python
# inspector/decision.py
from __future__ import annotations


def route(report, job: dict, policy) -> str:
    sev = report.severity
    if sev in ("critical", "high"):
        action = policy.severity_routing.get(sev, "block")
        if action == "patch" and job.get("asset_type") == "source_code":
            report.patch_diff, report.patch_source = generate_patch(report, policy)
        return action  # "block" | "patch" | "escalate"
    if sev == "medium":
        return "hold_escalate"  # Req 14 AC#7 — WS summary + Red Alert popup
    return "allow"


def generate_patch(report, policy) -> tuple[str | None, str | None]:
    try:
        return policy.gemini_client.patch(report.matched_patterns), "gemini"
    except Exception:
        # ponytail: template statis; ganti generator berbasis policy bila Gemini stabil
        return render_template_patch(report.matched_patterns), "template"
```

---

#### `control_plane/workers.py` — Server Worker Pool + `control_plane/eventlog.py` + `control_plane/ws/`

##### Objective

Drain `SERVER_SCAN_QUEUE` without ever blocking the loop: bounded concurrency, sub-50ms enqueue acknowledgement, async SIEM logging, and role-filtered real-time push so the operator dashboard red-alerts without refresh.

**Validates: Requirements 14.1–14.13, 15.3–15.4, 16.5–16.10**

##### Logic Flow

```
SERVER_SCAN_QUEUE (job stream per client_id)
    ↓
[Data Concatenation & Batching Routine] (Req 15.11 — Bulk Auto-Formatting Protection)
    collect jobs for client_id arriving within 2.0s window
    count > 1?
    ├── YES: pack jobs → BatchedSubmissionPayload(chunks=[masked_payload_1, masked_payload_2, ...])
    │        pass single batched payload array to Pipeline Worker
    └── NO:  pass single job directly to Pipeline Worker
    ↓
Pipeline Worker × N (Semaphore(3) bounds concurrent CrewAI runs)
    ↓
run_in_executor(run_pipeline_sync, batched_or_single_job) — CrewAI stays off the loop
    ↓ Sentry Gateway triage clean → log + skip CrewAI Pipeline
    ↓ else → decision.route() → post_audit_hook()
```

`eventlog.py` writes the full SIEM schema defined in Data Models (EventLog Entry);
`ws/` never receives raw paths, raw emails, or unmasked CRITICAL payloads for ADMIN
(Req 13.3–13.4, 14.3, 14.10).

##### Input/Output Schema

```
POST /api/v1/jobs → 200 {job_id, status: "queued"} | 503 {detail: "queue_full"}
WS /ws/events?token=<SessionToken> → invalid/expired → close 4001 (Req 14.8)
Dashboard popup (high/critical/medium): {severity, target_hvp, threats, action, final_score, ts}
```

##### Core Code Snippet

```python
# control_plane/workers.py
from __future__ import annotations

import asyncio

from control_plane.eventlog import write_async as log_write
from control_plane.ws import manager as ws_manager
from inspector.decision import route
from pipeline.crew import PIPELINE_TIMEOUT_S, run_pipeline_sync

PIPELINE_SEMAPHORE = asyncio.Semaphore(3)  # max 3 concurrent CrewAI runs (Req 16.9)
BATCH_WINDOW_S = 2.0  # 2-second collection window for bulk modifications (Req 15.11)


async def collect_batch(queue: asyncio.Queue, initial_job: dict, window_s: float = BATCH_WINDOW_S) -> list[dict]:
    """Batch jobs arriving for the same client_id within window_s."""
    batch = [initial_job]
    client_id = initial_job.get("client_id")
    end_time = asyncio.get_event_loop().time() + window_s
    while True:
        remaining = end_time - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            next_job = await asyncio.wait_for(queue.get(), timeout=remaining)
            if next_job.get("client_id") == client_id:
                batch.append(next_job)
            else:
                # Different client_id -> re-queue for other workers
                await queue.put(next_job)
                break
        except asyncio.TimeoutError:
            break
    return batch


async def pipeline_worker(queue: asyncio.Queue, ctx: dict) -> None:
    """Drain SERVER_SCAN_QUEUE with batching; never blocks the event loop."""
    loop = asyncio.get_event_loop()
    while True:
        first_job = await queue.get()
        try:
            batch = await collect_batch(queue, first_job)
            job_payload = batch[0] if len(batch) == 1 else {
                "job_id": batch[0]["job_id"],
                "batch_mode": True,
                "client_id": batch[0]["client_id"],
                "chunks": [j["chunk"] for j in batch],
                "submitted_at": batch[0]["submitted_at"],
            }
            async with PIPELINE_SEMAPHORE:
                await ctx["token_bucket"].acquire()  # 14 RPM shared
                report = await asyncio.wait_for(
                    loop.run_in_executor(None, run_pipeline_sync, job_payload, ctx["tools"]),
                    timeout=PIPELINE_TIMEOUT_S + 5,
                )
                action = route(report, job_payload, ctx["policy"])
                await post_audit_hook(report, job_payload, action, ctx)
        finally:
            queue.task_done()


async def post_audit_hook(report, job: dict, action: str, ctx: dict) -> None:
    entry = build_event_log_entry(report, job, action)  # full SIEM schema, § Data Models
    await log_write(entry)                       # aiofiles, non-blocking (Req 14.12)
    await ctx["event_bus"].put(entry)            # put_nowait; dispatch task broadcasts
    # dispatch task (EventBus loop) calls:
    #   await ws_manager.broadcast(entry, action)  # role-filtered per table above
```

```python
# control_plane/eventlog.py
from __future__ import annotations

import json

import aiofiles

LOG_PATH = "logs/pantheon.jsonl"


async def write_async(entry: dict) -> None:
    """Append one SIEM event as a single line. Never blocks the loop."""
    line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
    async with aiofiles.open(LOG_PATH, "a", encoding="utf-8") as f:
        await f.write(line + "\n")
```

```python
# control_plane/ws/routing.py
from __future__ import annotations


def ws_targets(entry: dict) -> set[str]:
    """Role-filtered broadcast targets. ADMIN never gets CEO high/critical (Req 14.6)."""
    sev, hvp = entry["severity_level"], entry["target_hvp"]
    if sev in ("high", "critical"):
        return {"SUPER_ADMIN"} if hvp == "CEO" else {"ADMIN", "SUPER_ADMIN"}
    if sev == "medium":
        # Req 14 AC#7/AC#12 — Red Alert popup for medium (summary payload only)
        return {"SUPER_ADMIN"} if hvp == "CEO" else {"ADMIN", "SUPER_ADMIN"}
    return set()  # low → EventLog only
```

## Appendix A: Consolidated Module Index (Step 4 — final architecture)

| Part | Modules | Covers |
| ---- | ------- | ------ |
| 1 | `sdk/background.py`, `sdk/pre_filter.py` | Watchdog events, L0–L3 filters, ScanQueue, HashDB gate |
| 2 | `sdk/forensics.py`, `shared/models.py`, `shared/policy.py` | ForensicExtractor, canonical dataclasses, Policy |
| 3 | `sdk/transport.py`, `control_plane/api/jobs.py`, `control_plane/rbac.py` | Ingestion, SessionToken, RBAC, masking enforcement |
| 4 | `hvp/identity.py`, `hvp/matcher.py` | GPG verify + grace period, threat multiplier, OSINT |
| 4b | `sdk/path_index.py`, `sdk/local_agent.py` | Detached Metadata Indexing, Zero-Knowledge paths |
| 5 | `gateway/sentry.py`, `pipeline/`, `inspector/decision.py`, `control_plane/workers.py`, `control_plane/eventlog.py`, `control_plane/ws/` | Triage, 4-agent pipeline, routing, SIEM writer, EventBus, WebSocket |
| — | `## Security Design`, `## Data Models`, `## API Design` | RBAC matrix, masking rules, canonical schemas (normative, not duplicated per-Part) |

Retired placeholders: Part 6 (folded into Part 3), Part 7 (folded into Part 5),
Part 8 (HashDB → Part 1, Policy → Part 2; no standalone Part 8 remains).
