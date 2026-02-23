# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PKI-MCP Core is a **research prototype** demonstrating certificate-based authentication and authorization for Model Context Protocol (MCP) tool access. Users present X.509 certificates with embedded tool permissions, and an MCP server enforces access control with comprehensive audit logging.

**Key Principle**: Hard enforcement. No fallbacks. Every access attempt is audited.

## Architecture

```
User Certificate → Ollama Tool Selection → MCP Server → Tool Execution
     (PKI)            (LLM-driven)       (Enforces)    (Mock impls)
```

### Flow
1. User has X.509 certificate issued by local CA
2. Certificate contains tool permissions in custom extension (OID: 1.3.6.1.4.1.99999.1)
3. User presents task to Ollama (llama3 model)
4. Ollama selects appropriate tool(s) based on task
5. MCP server validates certificate and checks permissions
6. Access allowed or denied, logged to `audit.jsonl`

## Project Structure

```
pki-mcp-core/
├── ca/
│   ├── __init__.py
│   └── ca.py                  # Certificate Authority - issues certs with permissions
├── server/
│   ├── __init__.py
│   └── mcp_server.py          # MCP JSON-RPC server with 4 tools
├── client/
│   ├── __init__.py
│   └── agent_client.py        # Ollama-driven client
├── core/
│   ├── __init__.py
│   └── audit.py               # Audit logger (JSONL format)
├── demo.py                    # Main demo orchestration
├── requirements.txt
├── README.md
├── .gitignore
└── CLAUDE.md                  # This file
```

## Key Components

### 1. Certificate Authority (`ca/ca.py`)

**Purpose**: Create local CA and issue user certificates with tool permissions.

**Key Functions**:
- `CertificateAuthority.__init__(ca_dir)`: Creates self-signed CA if needed
- `issue_certificate(username, allowed_tools, output_dir)`: Issues user cert with permissions
- `extract_permissions(cert)`: Extracts tool list from certificate extension
- `extract_username(cert)`: Gets username from certificate CN

**Custom Extension**:
- OID: `1.3.6.1.4.1.99999.1` (private enterprise number for prototype)
- Format: JSON `{"allowed_tools": ["tool1", "tool2", ...]}`
- Encoding: UTF-8 bytes in UnrecognizedExtension

**Certificate Validation**:
- User certificates signed by CA private key
- Server validates signature using CA public key
- RSA 2048-bit keys, SHA256 signatures

### 2. MCP Server (`server/mcp_server.py`)

**Purpose**: JSON-RPC server implementing 4 tools with certificate-based access control.

**Tools** (all return mock data):
- `web_search(query)`: Mock web search results
- `summarization(text)`: Mock text summary
- `database_query(sql)`: Mock database results
- `file_operations(path, operation)`: Mock file I/O

**Authentication Flow**:
1. Server receives user certificate path on startup
2. Validates certificate signature against CA
3. Extracts username and permissions
4. Stores in `current_user` and `current_permissions`

**Enforcement**:
- Every tool call checks `if name not in self.current_permissions`
- Denied: Returns error JSON, logs denial
- Allowed: Executes tool, logs success
- No silent failures or warnings

**Transport**: stdio (stdin/stdout JSON-RPC over MCP protocol)

### 3. Client (`client/agent_client.py`)

**Purpose**: Ollama-driven client that selects and executes tools via MCP.

**Key Features**:
- Loads user certificate and private key
- Connects to MCP server via stdio transport
- Calls Ollama with tool definitions
- Executes Ollama's selected tools through MCP
- Handles permission denials gracefully

**Ollama Integration**:
- Model: `llama3` (configurable via OLLAMA_BASE_URL env var)
- Tool definitions passed to Ollama matching MCP tools
- Ollama returns tool_calls in response
- Client executes each tool_call via MCP

### 4. Audit Logger (`core/audit.py`)

**Purpose**: Newline-delimited JSON audit log for all access attempts.

**Log Format**:
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "user": "alice",
  "tool_name": "web_search",
  "allowed": true,
  "reason": "permitted by certificate",
  "params": {"query": "..."}
}
```

**Key Methods**:
- `log_access(user, tool_name, allowed, reason, request_params)`: Write entry
- `read_log()`: Read all entries
- `print_log()`: Pretty-print audit trail

### 5. Demo (`demo.py`)

**Purpose**: Complete end-to-end demonstration of the system.

**Demo Users**:
- **alice**: `[web_search, summarization]`
- **bob**: `[web_search, summarization, database_query, file_operations]`
- **carol**: `[summarization]`

**Demo Scenarios**:
1. Alice searches web (allowed - has web_search)
2. Carol queries database (denied - only has summarization)
3. Bob uses multiple tools (allowed - has all permissions)

**Output**: Prints full audit log at end showing all allows and denials.

## Development Commands

### Setup
```bash
pip install -r requirements.txt
```

### Run Demo
```bash
# Ensure Ollama is running
ollama serve  # in separate terminal
ollama pull llama3

# Run complete demo
python demo.py
```

### View Audit Log
```bash
cat audit.jsonl
```

## Security Model

### Hard Enforcement
- **No fallbacks**: If cert validation fails, access denied
- **No silent failures**: Denials return clear error messages
- **No warnings**: Don't warn and allow - either allow or deny
- **Immutable audit**: All attempts logged regardless of outcome

### Certificate Validation
1. Load user certificate from PEM file
2. Verify signature using CA public key (RSA PKCS1v15)
3. Extract username from CN field
4. Extract permissions from custom extension
5. Store in server context for all subsequent tool calls

### Permission Checking
```python
if tool_name not in current_permissions:
    # LOG DENIAL
    return error_response
else:
    # LOG ALLOW
    execute_tool()
```

## Key Implementation Details

### X.509 Extension Encoding
```python
# Encoding permissions
permissions_data = json.dumps({"allowed_tools": ["tool1", "tool2"]})
permissions_extension = x509.UnrecognizedExtension(
    TOOL_PERMISSIONS_OID,
    permissions_data.encode("utf-8"),
)
```

### MCP Transport
- Uses stdio transport (stdin/stdout)
- Server command passed to client: `["python", "-m", "server.mcp_server", ca_cert, user_cert]`
- JSON-RPC messages over MCP protocol
- Async/await for all I/O operations

### Ollama Tool Format
```python
{
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web for information",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"}
            },
            "required": ["query"]
        }
    }
}
```

## Dependencies

- **cryptography**: X.509 certificate operations, RSA keys, signature verification
- **ollama**: Ollama Python SDK for LLM tool selection
- **mcp**: Model Context Protocol SDK for server/client

## Constraints

- Python 3.10+ (uses modern type hints like `str | None`)
- Ollama must be running with llama3 model
- No external databases (all tools return mock data)
- No Docker required
- Stdio transport only (not HTTP/SSE)

## Testing Approach

The demo serves as the primary test:
1. Creates CA and issues certificates
2. Runs three scenarios with different users
3. Validates audit log shows correct allows/denials
4. Manual verification of output

For development testing:
```bash
# Test CA certificate issuance
python -c "from ca.ca import CertificateAuthority; ca = CertificateAuthority('./test_pki'); print('CA created')"

# Test audit logging
python -c "from core.audit import AuditLogger; a = AuditLogger(); a.log_access('test', 'tool', True, 'test'); a.print_log()"
```

## Common Issues

### "No authenticated user"
- Server not receiving certificate path
- Certificate validation failed
- Check server command includes user cert path

### "Ollama request failed"
- Ollama not running: `ollama serve`
- Model not pulled: `ollama pull llama3`
- Wrong base URL: set `OLLAMA_BASE_URL` env var

### "Certificate validation failed"
- User cert not signed by expected CA
- Certificate expired
- Corrupted PEM file

### Import errors
- Missing `__init__.py` files
- Run from wrong directory (must be project root)
- Virtual environment not activated

## Design Decisions

### Why custom OID for permissions?
- Standard X.509 extensions don't fit this use case
- Custom extension allows arbitrary JSON data
- OID 1.3.6.1.4.1.99999.1 is in private enterprise range

### Why stdio transport?
- Simplest MCP transport to implement
- No HTTP server complexity
- Process-per-request model (like CGI)

### Why mock tool implementations?
- Focus is on enforcement layer, not real tool execution
- Reduces dependencies and external service requirements
- Makes demo deterministic and reproducible

### Why Ollama instead of OpenAI API?
- Runs locally without API keys
- Demonstrates this works with any LLM
- User has full control over model behavior

## Future Considerations

This is a research prototype. Production use would require:

- **Certificate lifecycle**: Issuance, renewal, revocation (CRL/OCSP)
- **Session management**: Multi-request sessions instead of process-per-request
- **Real tool implementations**: Actual web search, database access, etc.
- **Rate limiting**: Prevent abuse with per-user quotas
- **Audit analysis**: Tools to query and analyze audit logs
- **Multi-CA support**: Trust multiple CAs, certificate chains
- **HTTP transport**: REST API or SSE for web applications
- **Permission delegation**: Sub-permissions, temporary grants
- **Security audit**: External review of cryptographic implementation

## Project Status

**Current State**: Functional research prototype demonstrating core concept.

**What Works**:
- CA creation and certificate issuance with custom extensions
- Certificate validation and permission extraction
- MCP server with 4 tools and hard enforcement
- Ollama-driven tool selection
- Comprehensive audit logging
- End-to-end demo with 3 user scenarios

**What's Not Implemented**:
- Certificate revocation
- Multi-request sessions
- Real tool implementations (all mocked)
- Rate limiting
- Audit log analysis tools
- Production security hardening

## Code Style

- Type hints on all function signatures
- Docstrings for all public functions
- Async/await for all I/O operations
- Explicit error handling with clear messages
- Print statements for user feedback during demo
- Pathlib for all file operations

## How to Extend

### Add a new tool
1. Add tool definition in `server/mcp_server.py::_register_tools()`
2. Add implementation in `server/mcp_server.py::_execute_tool()`
3. Add tool name to user permissions when issuing certificate

### Support new transport
1. Modify `server/mcp_server.py::run()` to accept transport parameter
2. Add HTTP/SSE transport initialization
3. Update client command construction in `client/agent_client.py`

### Add permission metadata
1. Extend JSON in custom extension: `{"allowed_tools": [...], "metadata": {...}}`
2. Update `extract_permissions()` to return metadata
3. Use metadata in permission checking logic

## Contact and Support

This is a standalone research prototype. For questions or issues:
- Review this CLAUDE.md file
- Check README.md for usage instructions
- Examine code comments in implementation files
- Run demo.py to see working example
