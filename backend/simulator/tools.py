"""
Mock agent tools with obvious, observable side effects for testing.

Nothing here touches the real network. ``send_external_request`` only RECORDS
that it would have sent a request. Every call is recorded so tests can prove a
tool was — or crucially, was NOT — invoked.
"""

from __future__ import annotations

from pathlib import Path

from adapter.registry import ToolRegistry


class ToolSandbox:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.calls: list[tuple[str, str]] = []
        self.reads: list[str] = []
        self.writes: list[str] = []
        self.deletes: list[str] = []
        self.sent: list[dict] = []

    # -- tools -------------------------------------------------------------
    def read_file(self, resource: str, payload=None, destination=None) -> str:
        self.calls.append(("read_file", resource))
        self.reads.append(resource)
        return f"// mock contents of {resource}"

    def write_file(self, resource: str, payload=None, destination=None) -> str:
        self.calls.append(("write_file", resource))
        p = self.root / Path(resource).name
        p.write_text(payload or "")
        self.writes.append(resource)
        return f"wrote {len(payload or '')} bytes to {resource}"

    def delete_file(self, resource: str, payload=None, destination=None) -> str:
        self.calls.append(("delete_file", resource))
        p = self.root / Path(resource).name
        if p.exists():
            p.unlink()
        self.deletes.append(resource)
        return f"deleted {resource}"

    def send_external_request(self, resource=None, payload=None, destination=None) -> str:
        target = destination or resource
        self.calls.append(("send_external_request", target))
        self.sent.append({"destination": target, "payload_len": len(payload or "")})
        return f"[MOCK] would have sent request to {target} (no real network call made)"

    # -- assertions helpers ------------------------------------------------
    def was_called(self, tool_name: str, resource: str) -> bool:
        return (tool_name, resource) in self.calls

    def call_count(self, tool_name: str, resource: str) -> int:
        return sum(1 for c in self.calls if c == (tool_name, resource))


def build_registry(sandbox: ToolSandbox) -> ToolRegistry:
    reg = ToolRegistry()
    reg.add("read_file", "read", "file", sandbox.read_file, "Read a file's contents")
    reg.add("write_file", "write", "file", sandbox.write_file, "Write/modify a file")
    reg.add("delete_file", "delete", "file", sandbox.delete_file, "Delete a file")
    reg.add("send_external_request", "transmit", "url", sandbox.send_external_request,
            "Send data to an external endpoint (mocked — no real network)")
    return reg
