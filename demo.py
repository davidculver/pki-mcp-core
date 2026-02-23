#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path

from ca.ca import CertificateAuthority
from client.agent_client import run_task
from core.audit import AuditLogger

USERS = {
    "alice": ["web_search", "summarization"],
    "bob":   ["web_search", "summarization", "database_query", "file_operations"],
    "carol": ["summarization"],
}

SCENARIOS = [
    ("alice", "Search the web for information about quantum computing",
     "SUCCESS — alice has web_search"),
    ("carol", "Query the database for all users in the engineering department",
     "DENIED  — carol only has summarization"),
    ("bob",   "Search for Python best practices and save the results to a file",
     "SUCCESS — bob has all permissions"),
]


async def main():
    print("=" * 80)
    print("PKI-MCP CORE DEMONSTRATION")
    print("=" * 80)

    ca = CertificateAuthority(Path("./pki"))
    certs_dir = Path("./certs")

    print("\nIssuing certificates")
    print("-" * 80)
    certs = {}
    for username, tools in USERS.items():
        cert_path, key_path = ca.issue_certificate(username, tools, certs_dir)
        certs[username] = {"cert": cert_path, "key": key_path}

    audit_log = Path("audit.jsonl")
    audit_log.unlink(missing_ok=True)

    print("\nRunning scenarios")
    print("-" * 80)

    for username, task, expected in SCENARIOS:
        print(f"\n[{username.upper()}] {expected}")
        await run_task(
            cert_path=certs[username]["cert"],
            key_path=certs[username]["key"],
            ca_cert_path=ca.ca_cert_path,
            task=task,
        )

    print("\nAudit log")
    print("-" * 80)
    AuditLogger(audit_log).print_log()

    print("=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.exit(1)
