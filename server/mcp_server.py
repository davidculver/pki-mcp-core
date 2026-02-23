import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from ca.ca import extract_permissions, extract_username, _load_cert
from core.audit import AuditLogger


class PKIMCPServer:
    def __init__(self, ca_cert_path: Path, audit_log_path: Path = Path("audit.jsonl")):
        self.server = Server("pki-mcp-core")
        self.ca_cert = _load_cert(ca_cert_path)
        self.audit = AuditLogger(audit_log_path)

        self.current_user: str | None = None
        self.current_permissions: list[str] = []

        self._register_handlers()

    def authenticate(self, cert_pem: str):
        """Validate cert signature against CA and load user context."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
        except Exception as e:
            raise ValueError(f"invalid cert format: {e}")

        try:
            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            raise ValueError(f"cert signature invalid: {e}")

        self.current_user = extract_username(cert)
        self.current_permissions = extract_permissions(cert)

        print(f"✓ Authenticated: {self.current_user}")
        print(f"✓ Permissions:   {', '.join(self.current_permissions)}")

    def _register_handlers(self):

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="web_search",
                    description="Search the web for information",
                    inputSchema={
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                ),
                Tool(
                    name="summarization",
                    description="Summarize text content",
                    inputSchema={
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                ),
                Tool(
                    name="database_query",
                    description="Execute a database query",
                    inputSchema={
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"],
                    },
                ),
                Tool(
                    name="file_operations",
                    description="Perform file operations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "operation": {"type": "string", "description": "read, write, or delete"},
                        },
                        "required": ["path", "operation"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            if not self.current_user:
                self.audit.log_access("unknown", name, False, "no authenticated user", arguments)
                return _error("Authentication required", "no valid certificate presented")

            if name not in self.current_permissions:
                self.audit.log_access(
                    self.current_user, name, False,
                    f"not in cert permissions (allowed: {self.current_permissions})",
                    arguments,
                )
                return _error(
                    "Permission denied",
                    f"{self.current_user} is not authorized for {name}",
                )

            self.audit.log_access(self.current_user, name, True, "permitted by certificate", arguments)

            try:
                result = await _execute(name, arguments)
                return [TextContent(type="text", text=json.dumps(result))]
            except Exception as e:
                return _error("Tool execution failed", str(e))

    async def run(self):
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


async def _execute(name: str, args: dict) -> dict[str, Any]:
    if name == "web_search":
        q = args["query"]
        return {
            "tool": "web_search",
            "query": q,
            "results": [
                {"title": f"Result 1 for '{q}'", "url": "https://example.com/1",
                 "snippet": f"Mock result for {q}."},
                {"title": f"Result 2 for '{q}'", "url": "https://example.com/2",
                 "snippet": f"Another mock result for {q}."},
            ],
        }

    if name == "summarization":
        text = args["text"]
        return {
            "tool": "summarization",
            "original_length": len(text),
            "summary": f"[MOCK] Condensed version of {len(text)}-character input.",
        }

    if name == "database_query":
        return {
            "tool": "database_query",
            "query": args["sql"],
            "rows": [
                {"id": 1, "name": "Alice", "department": "Engineering"},
                {"id": 2, "name": "Bob", "department": "Research"},
                {"id": 3, "name": "Carol", "department": "Operations"},
            ],
            "row_count": 3,
        }

    if name == "file_operations":
        return {
            "tool": "file_operations",
            "path": args["path"],
            "operation": args["operation"],
            "status": "success",
        }

    raise ValueError(f"unknown tool: {name}")


def _error(title: str, detail: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": title, "message": detail}))]


async def main():
    if len(sys.argv) < 3:
        print("usage: python -m server.mcp_server <ca_cert> <user_cert>")
        sys.exit(1)

    server = PKIMCPServer(Path(sys.argv[1]))

    with open(sys.argv[2]) as f:
        cert_pem = f.read()

    try:
        server.authenticate(cert_pem)
    except ValueError as e:
        print(f"✗ Auth failed: {e}")
        sys.exit(1)

    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
