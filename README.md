# WinDbg MCP

MCP server for Microsoft's Windows Debugger Engine (`DbgEng.dll`). Supports
dump analysis, live debugging, symbols, memory, breakpoints, execution, and
native WinDbg commands over stdio.

## Requirements

- Windows 10+
- Debugging Tools for Windows (x64 `dbgeng.dll`)
- Rust stable and `x86_64-pc-windows-msvc` (source builds only)

## Installation

```powershell
claude plugin marketplace add zxcvbbq/WinDbg-MCP
claude plugin install windbg-mcp@zxcvbbq

codex plugin marketplace add zxcvbbq/WinDbg-MCP
codex plugin add windbg-mcp@zxcvbbq
```

## Build from source

```powershell
cargo build --release --locked
& .\target\release\windbg-mcp.exe
```

Set `WINDBG_MCP_DEBUGGER_DIR` when `dbgeng.dll` is outside the standard SDK
path.

## Tools

Sessions: `open_dump`, `connect_frontend`, `connect_remote`, `discover_servers`,
`auto_connect`, `attach_process`, `launch_process`, `attach_remote_process`,
`launch_remote_process`, `attach_kernel`, `session_status`, `list_sessions`,
`close_session`.

Inspection: `list_processes`, `list_threads`, `select_thread`, `list_modules`,
`stack_trace`, `get_registers`, `evaluate`, `disassemble`, `symbol_from_address`,
`address_from_symbol`, `read_memory`, `write_memory`, `query_memory`,
`get_symbol_path`, `set_symbol_path`, `reload_symbols`.

Control: `list_breakpoints`, `set_breakpoint`, `set_breakpoint_enabled`,
`remove_breakpoint`, `execute`, `wait_for_event`, `execute_command`,
`start_command`, `command_status`.

Every tool uses an explicit `session_id`. Commands create files only when the
command itself requests it.

## Existing WinDbg sessions

In WinDbg:

```text
.server npipe:pipe=windbg_mcp
```

Then call `windbg.auto_connect` or `windbg.connect_frontend` with
`npipe:server=localhost,pipe=windbg_mcp`.

## Remote debugging

For an existing WinDbg or CDB session:

```text
.server tcp:port=5005
```

Use `windbg.connect_remote` with the host and port. For direct remote process
debugging, run `dbgsrv.exe -t tcp:port=5005` and use
`attach_remote_process` or `launch_remote_process`.
