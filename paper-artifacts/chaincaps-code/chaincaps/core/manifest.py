"""
ChainCaps Core: Tool Manifests

Developer-authored (or audited) manifests declaring each tool's
security-relevant properties:
- Effect type (what sink operations the tool can perform)
- Output budget policy (what sinks downstream data may authorize)
- Pass-through constraint
- Composition annotations
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .budget import Budget, SinkPrivilege, SinkType


@dataclass
class ToolManifest:
    """Security manifest for a tool.

    This replaces the raw NL description for security-critical decisions.
    The manifest is developer-authored, signed, and versioned.
    """
    name: str
    version: str = "1.0.0"

    # What sink effects this tool can physically perform
    exec_privileges: List[SinkPrivilege] = field(default_factory=list)

    # What budget policy to assign to this tool's outputs
    # If None, outputs inherit the meet of input budgets (transparent pass-through)
    output_budget_policy: Optional[Budget] = None

    # Pass-through constraint: limits what budgets pass through this tool
    # Budget.top() = no restriction (default for pure transforms)
    pass_through: Optional[Budget] = None

    # Is this a sink tool (performs side effects)?
    is_sink: bool = False

    # Is this a source tool (reads external data)?
    is_source: bool = False

    # Default source budget when this tool reads data
    default_source_budget: Optional[Budget] = None

    # Human-readable description (for audit only, NOT shown to planner)
    description: str = ""

    # Composition annotations
    requires_declassification: bool = False
    max_chain_depth: Optional[int] = None

    @property
    def content_hash(self) -> str:
        """Content-addressable hash for integrity verification."""
        content = json.dumps({
            "name": self.name,
            "version": self.version,
            "exec": [str(p) for p in self.exec_privileges],
            "is_sink": self.is_sink,
            "is_source": self.is_source,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# --- Standard tool manifests ---

STANDARD_MANIFESTS: Dict[str, ToolManifest] = {
    # --- Original tool names ---
    "read_file": ToolManifest(
        name="read_file",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
            SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
        ),
        description="Read a file from the filesystem",
    ),
    "list_directory": ToolManifest(
        name="list_directory",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
            SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
        ),
        description="List directory contents",
    ),
    "read_directory": ToolManifest(
        name="read_directory",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
            SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
        ),
        description="Read directory listing",
    ),
    "search_files": ToolManifest(
        name="search_files",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
            SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
        ),
        description="Search for files by pattern",
    ),
    "read_public_url": ToolManifest(
        name="read_public_url",
        is_source=True,
        default_source_budget=Budget.top(),
        description="Fetch content from a public URL",
    ),
    "db_query": ToolManifest(
        name="db_query",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
        ),
        description="Query a database and return results",
    ),
    "summarize": ToolManifest(
        name="summarize",
        description="Summarize text content",
    ),
    "format_output": ToolManifest(
        name="format_output",
        description="Format data for presentation",
    ),
    "send_http": ToolManifest(
        name="send_http",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="Send an HTTP request to an external endpoint",
    ),
    "send_email": ToolManifest(
        name="send_email",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_EMAIL, "*")],
        description="Send an email message",
    ),
    "write_file": ToolManifest(
        name="write_file",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.WRITE_FILE, "*")],
        description="Write content to a file",
    ),
    "execute_shell": ToolManifest(
        name="execute_shell",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.EXECUTE, "*")],
        description="Execute a shell command",
    ),
    "display_to_user": ToolManifest(
        name="display_to_user",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.DISPLAY, "*")],
        description="Display content to the user",
    ),
    "execute": ToolManifest(
        name="execute",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.EXECUTE, "*")],
        description="Execute a command (built-in sink)",
    ),
    # --- Realistic MCP server tool names ---
    "filesystem_read": ToolManifest(
        name="filesystem_read",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
            SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
        ),
        description="MCP filesystem server: read file",
    ),
    "filesystem_write": ToolManifest(
        name="filesystem_write",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.WRITE_FILE, "*")],
        description="MCP filesystem server: write file",
    ),
    "fetch_url": ToolManifest(
        name="fetch_url",
        is_source=True,
        is_sink=True,  # can also POST
        default_source_budget=Budget.top(),
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="MCP fetch server: fetch/POST URL",
    ),
    "postgres_query": ToolManifest(
        name="postgres_query",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
        ),
        description="MCP postgres server: query database",
    ),
    "slack_post_message": ToolManifest(
        name="slack_post_message",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="MCP Slack server: post message to channel",
    ),
    "github_create_issue": ToolManifest(
        name="github_create_issue",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="MCP GitHub server: create issue",
    ),
    "github_create_pr": ToolManifest(
        name="github_create_pr",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="MCP GitHub server: create pull request",
    ),
    "email_send": ToolManifest(
        name="email_send",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_EMAIL, "*")],
        description="Email tool: send email",
    ),
    "shell_exec": ToolManifest(
        name="shell_exec",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.EXECUTE, "*")],
        description="Shell tool: execute command",
    ),
    "memory_store": ToolManifest(
        name="memory_store",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.MEMORY_WRITE, "*")],
        description="MCP memory server: store value",
    ),
    "memory_retrieve": ToolManifest(
        name="memory_retrieve",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
        ),
        description="MCP memory server: retrieve value",
    ),
    "browser_navigate": ToolManifest(
        name="browser_navigate",
        is_sink=True,
        exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
        description="MCP browser server: navigate to URL",
    ),
    "browser_screenshot": ToolManifest(
        name="browser_screenshot",
        is_source=True,
        default_source_budget=Budget.from_sinks(
            SinkPrivilege(SinkType.DISPLAY),
        ),
        description="MCP browser server: take screenshot",
    ),
    # Transform tools
    "summarize_text": ToolManifest(
        name="summarize_text",
        description="Transform: summarize text",
    ),
    "translate_text": ToolManifest(
        name="translate_text",
        description="Transform: translate text",
    ),
    "format_data": ToolManifest(
        name="format_data",
        description="Transform: format data",
    ),
}


# ═══════════════════════════════════════════════════════════════════════
# Manifest Linting
# ═══════════════════════════════════════════════════════════════════════

# Keywords that suggest a tool may have source capabilities
_SOURCE_KEYWORDS = [
    "read", "get", "fetch", "search", "list", "query", "retrieve",
    "download", "screenshot", "browse", "scan", "lookup", "find",
]

# Keywords that suggest a tool may have sink capabilities
_SINK_KEYWORDS = [
    "write", "send", "post", "create", "delete", "update", "execute",
    "navigate", "click", "upload", "store", "publish", "push", "deploy",
]


@dataclass
class LintWarning:
    """A manifest linting warning."""
    tool_name: str
    severity: str  # "error", "warning", "info"
    code: str
    message: str


def lint_manifest(manifest: ToolManifest) -> List[LintWarning]:
    """Lint a tool manifest for common authoring errors.

    Checks:
    - L001: Sink tool with no exec_privileges
    - L002: Possible dual-role tool classified as single-role
    - L003: Source tool with wildcard budget (over-permissive)
    - L004: Sink tool with wildcard scope on all exec_privileges
    - L005: Tool name suggests source but classified as sink-only
    - L006: Tool name suggests sink but classified as source-only
    """
    warnings: List[LintWarning] = []
    lower = manifest.name.lower()

    # L001: Sink with no exec privileges
    if manifest.is_sink and not manifest.exec_privileges:
        warnings.append(LintWarning(
            manifest.name, "error", "L001",
            "Sink tool has no exec_privileges — sink check cannot determine "
            "what operation to authorize. Add at least one SinkPrivilege."))

    # L002: Dual-role detection
    has_source_kw = any(kw in lower for kw in _SOURCE_KEYWORDS)
    has_sink_kw = any(kw in lower for kw in _SINK_KEYWORDS)
    if has_source_kw and has_sink_kw:
        if not (manifest.is_source and manifest.is_sink):
            warnings.append(LintWarning(
                manifest.name, "warning", "L002",
                f"Tool name contains both source ({[k for k in _SOURCE_KEYWORDS if k in lower]}) "
                f"and sink ({[k for k in _SINK_KEYWORDS if k in lower]}) keywords — "
                f"consider marking as dual-role (is_source=True, is_sink=True)."))

    # L003: Over-permissive source budget
    if manifest.is_source and manifest.default_source_budget:
        budget = manifest.default_source_budget
        for priv in budget.privileges:
            if priv.scope == "*" and priv.operation != SinkType.DISPLAY:
                warnings.append(LintWarning(
                    manifest.name, "warning", "L003",
                    f"Source budget includes wildcard {priv.operation.name}(*) — "
                    f"consider scoping to a specific domain or path."))

    # L004: Wildcard scope on sink exec privileges
    if manifest.is_sink and manifest.exec_privileges:
        wildcards = [p for p in manifest.exec_privileges if p.scope == "*"]
        if wildcards and len(wildcards) == len(manifest.exec_privileges):
            warnings.append(LintWarning(
                manifest.name, "info", "L004",
                "All exec_privileges use wildcard scope — consider scoping "
                "to specific domains/paths for defense in depth."))

    # L005/L006: Name vs classification mismatch
    if has_source_kw and not has_sink_kw and manifest.is_sink and not manifest.is_source:
        warnings.append(LintWarning(
            manifest.name, "warning", "L005",
            f"Tool name suggests source (keywords: {[k for k in _SOURCE_KEYWORDS if k in lower]}) "
            f"but classified as sink-only. Verify classification."))

    if has_sink_kw and not has_source_kw and manifest.is_source and not manifest.is_sink:
        warnings.append(LintWarning(
            manifest.name, "warning", "L006",
            f"Tool name suggests sink (keywords: {[k for k in _SINK_KEYWORDS if k in lower]}) "
            f"but classified as source-only. Verify classification."))

    return warnings


def lint_all_manifests(manifests: Optional[Dict[str, ToolManifest]] = None,
                       ) -> Dict[str, List[LintWarning]]:
    """Lint all registered manifests and return warnings by tool."""
    if manifests is None:
        manifests = STANDARD_MANIFESTS
    results = {}
    for name, manifest in manifests.items():
        warnings = lint_manifest(manifest)
        if warnings:
            results[name] = warnings
    return results


# Built-in sink keyword heuristics for unknown tools (fail-closed).
# If an unknown tool's name contains any of these patterns, treat it as a
# potential sink with the corresponding privilege.  This addresses the
# open-world soundness gap: new/unmanifested tools that can exfiltrate
# data are caught even without explicit manifests.
_SINK_KEYWORD_MAP = {
    SinkType.SEND_HTTP: [
        "http", "post", "put", "patch", "upload", "webhook", "fetch",
        "request", "curl", "api_call", "slack", "discord", "mqtt",
        "publish", "s3_upload", "cloud_store",
    ],
    SinkType.SEND_EMAIL: [
        "email", "mail", "sendmail", "smtp", "notify", "message",
    ],
    SinkType.WRITE_FILE: [
        "write", "save", "dump", "export", "store_file",
    ],
    SinkType.EXECUTE: [
        "exec", "execute", "shell", "bash", "terminal", "run_command",
        "subprocess", "system", "eval",
    ],
    SinkType.DB_WRITE: [
        "insert", "update_db", "db_write", "db_insert",
    ],
    SinkType.MEMORY_WRITE: [
        "memory_write", "cache_set", "persist",
    ],
}


def _infer_sink_from_name(tool_name: str) -> Optional[SinkPrivilege]:
    """Heuristic: infer sink type from tool name keywords."""
    lower = tool_name.lower()
    for sink_type, keywords in _SINK_KEYWORD_MAP.items():
        for kw in keywords:
            if kw in lower:
                return SinkPrivilege(sink_type, "*")
    return None


def get_manifest(tool_name: str) -> ToolManifest:
    """Get a tool's security manifest.

    For known tools, returns the registered manifest.
    For unknown tools, applies fail-closed heuristics:
    - If the tool name contains sink-like keywords (send, exec, write,
      upload, etc.), it is treated as a potential sink.
    - Otherwise, it gets a conservative transform manifest with
      display-only source budget.
    """
    if tool_name in STANDARD_MANIFESTS:
        return STANDARD_MANIFESTS[tool_name]

    # Fail-closed: check if tool name looks like a sink
    inferred_sink = _infer_sink_from_name(tool_name)
    if inferred_sink is not None:
        return ToolManifest(
            name=tool_name,
            is_sink=True,
            exec_privileges=[inferred_sink],
            description=f"Unknown tool (inferred sink: {inferred_sink}): {tool_name}",
        )

    # Fail-closed default: unknown tool treated as potential sink with
    # all common egress types.  This ensures that new/unmanifested tools
    # cannot silently exfiltrate data even if their names are creative.
    return ToolManifest(
        name=tool_name,
        is_sink=True,
        exec_privileges=[
            SinkPrivilege(SinkType.SEND_HTTP, "*"),
            SinkPrivilege(SinkType.EXECUTE, "*"),
        ],
        description=f"Unknown tool (fail-closed): {tool_name}",
    )
