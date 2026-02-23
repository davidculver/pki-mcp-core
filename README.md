# PKI-MCP Core

Certificate-based authentication and authorization for MCP tool access. Users present X.509 certificates encoding which tools they can call. Every access attempt is audited.

## Architecture

```
┌─────────────┐
│   User      │  Has X.509 cert with tool permissions
│  (alice)    │  encoded in custom extension (OID 1.3.6.1.4.1.99999.1)
└──────┬──────┘
       │
       │ Task: "Search for quantum computing"
       ▼
┌─────────────────────┐
│  Ollama (llama3)    │  Selects appropriate tool(s)
│  Tool Selection     │  based on task requirements
└──────┬──────────────┘
       │
       │ Tool call: web_search(query="quantum computing")
       ▼
┌─────────────────────┐
│   MCP Server        │  1. Validates cert against CA
│  (JSON-RPC/stdio)   │  2. Extracts user identity & permissions
│                     │  3. Enforces access control
│  Tools:             │  4. Logs to audit.jsonl
│   • web_search      │
│   • summarization   │  ✓ ALLOW or ✗ DENY
│   • database_query  │
│   • file_operations │
└─────────────────────┘
```

## How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Ensure Ollama is running with llama3
ollama pull llama3
ollama serve  # in separate terminal

# 3. Run the demo
python demo.py

# 4. View audit log
cat audit.jsonl
```

## Demo Scenarios

The demo creates three users with different permission levels:

- **alice**: `[web_search, summarization]` — Can search and summarize
- **bob**: `[web_search, summarization, database_query, file_operations]` — Full access
- **carol**: `[summarization]` — Limited to summarization only

Three scenarios demonstrate the enforcement:
1. Alice performs web search (allowed)
2. Carol attempts database query (denied)
3. Bob uses multiple tools (allowed)

## Audit Trail

Every tool access attempt is logged to `audit.jsonl`:

```json
{"timestamp": "2024-01-15T10:30:45Z", "user": "alice", "tool_name": "web_search", "allowed": true, "reason": "permitted by certificate", "params": {"query": "quantum computing"}}
{"timestamp": "2024-01-15T10:31:12Z", "user": "carol", "tool_name": "database_query", "allowed": false, "reason": "not in cert permissions (allowed: ['summarization'])", "params": {"sql": "SELECT * FROM users WHERE department = 'engineering'"}}
```

## Security Model

- **Hard enforcement**: Denied requests fail immediately with clear error messages
- **No fallbacks**: If certificate validation fails, access is denied
- **Immutable audit log**: All access attempts logged regardless of outcome
- **Certificate validation**: User certificates must be signed by trusted CA

## Project Status

This is a **research prototype** demonstrating certificate-based access control for LLM tool usage. It is not intended for production use. All tool implementations return mock data to focus on the enforcement layer.

## Requirements

- Python 3.10 or higher
- Ollama with llama3 model
- No Docker required
