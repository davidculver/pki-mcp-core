import json
from datetime import datetime
from pathlib import Path


class AuditLogger:
    def __init__(self, log_path: Path = Path("audit.jsonl")):
        self.log_path = Path(log_path)

    def log_access(self, user: str, tool: str, allowed: bool, reason: str, params: dict | None = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user": user,
            "tool_name": tool,
            "allowed": allowed,
            "reason": reason,
        }
        if params:
            entry["params"] = params

        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def read_log(self) -> list:
        if not self.log_path.exists():
            return []
        with open(self.log_path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def print_log(self):
        entries = self.read_log()
        if not entries:
            print("No audit log entries.")
            return

        print("\n" + "=" * 80)
        print("AUDIT LOG")
        print("=" * 80)

        for e in entries:
            status = "✓ ALLOWED" if e["allowed"] else "✗ DENIED"
            print(f"\n{e['timestamp']}")
            print(f"  User:   {e['user']}")
            print(f"  Tool:   {e['tool_name']}")
            print(f"  Status: {status}")
            print(f"  Reason: {e['reason']}")
            if "params" in e:
                print(f"  Params: {e['params']}")

        print("\n" + "=" * 80)
        print(f"Total entries: {len(entries)}")
        print("=" * 80 + "\n")
