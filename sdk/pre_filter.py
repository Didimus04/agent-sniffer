"""
sdk/pre_filter.py — Deterministic Pre-Filter (L0 + Layer 1 + Layer 2 + Layer 3)
Applies all deterministic filtering stages in a single module before LLM analysis.
"""
from __future__ import annotations

import ast
import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from shared.hashdb import HashDB
from shared.models import CodeChunk
from sdk.ics_parser import parse_ics

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
class FilterResult:
    passed: bool
    chunks: list[CodeChunk] = field(default_factory=list)
    skip_reason: str | None = None
    high_entropy_secret_detected: bool = False


# ── Shannon Entropy Helper ───────────────────────────────────────────────────

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
    """Evaluates tokens > 60 chars. Returns True if any token has H > 5.2 (Req 9.9)."""
    tokens = [tok for tok in content.split() if len(tok) > MIN_TOKEN_LENGTH]
    return any(calculate_shannon_entropy(tok) > SHANNON_ENTROPY_THRESHOLD for tok in tokens)


# ── L0 Helpers ───────────────────────────────────────────────────────────────

def _is_excluded_path(path: str) -> bool:
    return any(part in EXCLUDED_FOLDERS for part in Path(path).parts)


def _is_excluded_extension(path: str) -> bool:
    return Path(path).suffix.lower() in EXCLUDED_EXTENSIONS


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
    trusted_domains: list[str] | None = None,
) -> FilterResult:
    """
    Apply deterministic pre-filtering pipeline (L0, L1, L2, L3).
    Includes HRD Force Sandbox Protocol and ICS Bypass Gateway.
    """
    path_obj = Path(event_path)
    ext = path_obj.suffix.lower()

    # Force Sandbox Protocol for HRD_RECRUITMENT (Ambiguitas 7, Req 10.6):
    # CV/Resume documents bypass L0-L3 gates to prevent telemetry starvation.
    if asset_owner_role == "HRD_RECRUITMENT":
        try:
            content = path_obj.read_text(encoding="utf-8", errors="ignore")
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

    # Layer 1 — ICS Bypass Gateway (Ambiguitas 6, Req 9.1, 9.8)
    if ext == ".ics":
        try:
            content = path_obj.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return FilterResult(passed=False, skip_reason="read_error")
        ics_res = parse_ics(content, trusted_domains=trusted_domains)
        file_path_hash = hashlib.sha256(event_path.encode()).hexdigest()
        reason = "ics_anomaly" if ics_res.external_anomaly else "ics_clean"
        chunk = CodeChunk(
            file_path_hash=file_path_hash,
            function_name="<calendar_event>",
            source_text=content,
            match_reason=reason,
            asset_owner_role=asset_owner_role,
        )
        return FilterResult(passed=True, chunks=[chunk])

    # L0 — Extension exclusion
    if _is_excluded_extension(event_path):
        return FilterResult(passed=False, skip_reason="excluded_extension")

    # L0 — Read file
    try:
        content = path_obj.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FilterResult(passed=False, skip_reason="read_error")

    # L0 — Length boundary tokenizer & Shannon Entropy check
    if not _has_long_tokens(content):
        return FilterResult(passed=False, skip_reason="no_tokens_above_threshold")

    high_entropy = _has_high_entropy_tokens(content)

    # Layer 1 — Code extension allowlist
    if ext not in CODE_EXTENSIONS:
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

    # Layer 3 — AST/Regex criticality filter & Keyword Density
    chunks: list[CodeChunk] = []
    for name, body in changed:
        reason = _match_critical(body)
        if reason:
            chunks.append(CodeChunk(
                file_path_hash=file_path_hash,
                function_name=name,
                source_text=body,
                match_reason=reason,
                asset_owner_role=asset_owner_role,
            ))

    if not chunks:
        return FilterResult(passed=False, skip_reason="no_critical_patterns")

    return FilterResult(passed=True, chunks=chunks, high_entropy_secret_detected=high_entropy)
