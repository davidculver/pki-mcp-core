import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import ollama
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


class PKIMCPClient:
    def __init__(self, cert_path: Path, server_command: list[str], ollama_base_url: str | None = None):
        self.cert_path = Path(cert_path)
        self.server_command = server_command

        with open(self.cert_path) as f:
            self.cert_pem = f.read()

        url = ollama_base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama = ollama.Client(host=url)

        self.session: ClientSession | None = None
        self.tools: list[dict] = []
        self._stdio_ctx = None
        self._session_ctx = None

    async def connect(self):
        params = StdioServerParameters(
            command=self.server_command[0],
            args=self.server_command[1:],
        )
        self._stdio_ctx = stdio_client(params)
        read_stream, write_stream = await self._stdio_ctx.__aenter__()

        self._session_ctx = ClientSession(read_stream, write_stream)
        self.session = await self._session_ctx.__aenter__()

        await self.session.initialize()

        tools_resp = await self.session.list_tools()
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema,
                },
            }
            for t in tools_resp.tools
        ]

        print(f"✓ Connected — tools: {[t['function']['name'] for t in self.tools]}")

    async def run_task(self, task: str) -> dict[str, Any]:
        if not self.session:
            raise RuntimeError("call connect() first")

        print(f"\n{'='*60}")
        print(f"TASK: {task}")
        print(f"{'='*60}\n")

        try:
            # llama3.1+ required — earlier llama3 builds reject tool definitions
            resp = self.ollama.chat(
                model="llama3.1:8b",
                messages=[{"role": "user", "content": task}],
                tools=self.tools,
            )
        except Exception as e:
            return {"error": "ollama request failed", "message": str(e)}

        tool_calls = resp.message.tool_calls
        if not tool_calls:
            return {"type": "text", "content": resp.message.content or ""}

        results = []
        for tc in tool_calls:
            name = tc["function"]["name"]
            args = tc["function"]["arguments"]

            print(f"Tool selected: {name}")
            print(f"Args: {json.dumps(args, indent=2)}\n")

            try:
                result = await self.session.call_tool(name, args)
                content = json.loads(result.content[0].text) if result.content else {}

                if "error" in content:
                    print(f"✗ DENIED: {content['message']}\n")
                    results.append({"tool": name, "status": "denied", "error": content})
                else:
                    print(f"✓ ALLOWED\n")
                    results.append({"tool": name, "status": "success", "result": content})

            except Exception as e:
                print(f"✗ ERROR: {e}\n")
                results.append({"tool": name, "status": "error", "message": str(e)})

        return {
            "type": "tool_execution",
            "task": task,
            "tool_calls": results,
        }

    async def close(self):
        if self._session_ctx:
            await self._session_ctx.__aexit__(None, None, None)
        if self._stdio_ctx:
            await self._stdio_ctx.__aexit__(None, None, None)


async def run_task(cert_path: Path, key_path: Path, ca_cert_path: Path, task: str) -> dict:
    """Run a single task as the user identified by cert_path."""
    cmd = ["python", "-m", "server.mcp_server", str(ca_cert_path), str(cert_path)]
    client = PKIMCPClient(cert_path=cert_path, server_command=cmd)

    try:
        await client.connect()
        return await client.run_task(task)
    finally:
        await client.close()


async def main():
    if len(sys.argv) < 5:
        print("usage: python -m client.agent_client <cert> <key> <ca_cert> <task>")
        sys.exit(1)

    result = await run_task(
        cert_path=Path(sys.argv[1]),
        key_path=Path(sys.argv[2]),
        ca_cert_path=Path(sys.argv[3]),
        task=sys.argv[4],
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
