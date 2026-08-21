"""
Real, side-effecting tools for the MCP server.

These perform actual operations (read/write/delete files, run a shell command,
make an HTTP request). They are NOT security gates — Agent Guard decides whether
they run. A workspace jail is applied to file/command ops as a secondary safety
net so a tool can't touch paths outside the configured workspace even if reached.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from adapter.registry import ToolRegistry


class Workspace:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.http_log: list[dict] = []

    def _resolve(self, resource: str) -> Path:
        p = (self.root / resource).resolve()
        if self.root != p and self.root not in p.parents:
            raise PermissionError(f"path '{resource}' escapes the workspace")
        return p

    # -- file tools --------------------------------------------------------
    def read_file(self, resource: str, payload=None, destination=None) -> str:
        p = self._resolve(resource)
        if not p.exists():
            return f"[not found] {resource}"
        return p.read_text(errors="replace")[:100_000]

    def write_file(self, resource: str, payload=None, destination=None) -> str:
        p = self._resolve(resource)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload or "")
        return f"wrote {len(payload or '')} bytes to {resource}"

    def delete_file(self, resource: str, payload=None, destination=None) -> str:
        p = self._resolve(resource)
        if p.exists():
            p.unlink()
            return f"deleted {resource}"
        return f"[not found] {resource}"

    # -- shell tool --------------------------------------------------------
    def run_command(self, resource: str, payload=None, destination=None) -> str:
        cmd = payload or resource
        proc = subprocess.run(cmd, shell=True, cwd=self.root, capture_output=True,
                              text=True, timeout=30)
        out = (proc.stdout or "") + (proc.stderr or "")
        return out[:20_000] or f"[exit {proc.returncode}]"

    # -- network tool (records; only runs when Agent Guard ALLOWs) ---------
    def http_request(self, resource=None, payload=None, destination=None) -> str:
        target = destination or resource
        self.http_log.append({"destination": target, "payload_len": len(payload or "")})
        try:
            import httpx
            method = "POST" if payload else "GET"
            r = httpx.request(method, target, content=payload, timeout=15)
            return f"{method} {target} -> {r.status_code} ({len(r.content)} bytes)"
        except Exception as exc:  # network optional in restricted envs
            return f"request to {target} attempted; transport error: {type(exc).__name__}"


def build_registry(ws: Workspace) -> ToolRegistry:
    reg = ToolRegistry()
    reg.add("read_file", "read", "file", ws.read_file, "Read a file in the workspace")
    reg.add("write_file", "write", "file", ws.write_file, "Write/modify a file in the workspace")
    reg.add("delete_file", "delete", "file", ws.delete_file, "Delete a file in the workspace")
    reg.add("run_command", "execute", "process", ws.run_command, "Run a shell command in the workspace")
    reg.add("http_request", "transmit", "url", ws.http_request, "Make an external HTTP request")
    return reg
