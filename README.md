# WinDbg MCP

A Model Context Protocol server for Microsoft's Windows Debugger Engine
(`DbgEng.dll`). It provides structured dump analysis, live debugging, symbols,
memory, breakpoints, execution control, and native WinDbg commands over MCP
stdio.

## Requirements

- Windows 10 or newer
- Windows SDK **Debugging Tools for Windows** with x64 `dbgeng.dll`
- Rust stable with the `x86_64-pc-windows-msvc` target when building from source

The server dynamically loads the installed x64 Debugging Tools copy of
`dbgeng.dll`. Set `WINDBG_MCP_DEBUGGER_DIR` when it is installed elsewhere.

## Build from source

```powershell
cargo build --release --locked
& .\target\release\windbg-mcp.exe
```

The executable speaks MCP JSON-RPC on stdout; diagnostics are written to
stderr.

## Installation

Install from the published GitHub repository:

```powershell
claude plugin marketplace add zxcvbbq/WinDbg-MCP
claude plugin uninstall windbg-mcp@zxcvbbq
claude plugin install windbg-mcp@zxcvbbq

codex plugin marketplace add zxcvbbq/WinDbg-MCP
codex plugin remove windbg-mcp@zxcvbbq
codex plugin add windbg-mcp@zxcvbbq
```

## Tools

Session lifecycle:

- `windbg.health`, `windbg.engine_probe`
- `windbg.open_dump`, `windbg.connect_frontend`, `windbg.connect_remote`
- `windbg.discover_servers`, `windbg.auto_connect`
- `windbg.attach_process`, `windbg.launch_process`
- `windbg.attach_remote_process`, `windbg.launch_remote_process`
- `windbg.attach_kernel`
- `windbg.session_status`, `windbg.list_sessions`, `windbg.close_session`

Inspection and control:

- `windbg.list_processes`, `windbg.list_threads`, `windbg.select_thread`
- `windbg.list_modules`, `windbg.stack_trace`, `windbg.get_registers`
- `windbg.evaluate`, `windbg.disassemble`
- `windbg.symbol_from_address`, `windbg.address_from_symbol`
- `windbg.read_memory`, `windbg.write_memory`
- `windbg.query_memory`
- `windbg.get_symbol_path`, `windbg.set_symbol_path`, `windbg.reload_symbols`
- `windbg.list_breakpoints`, `windbg.set_breakpoint`, `windbg.set_breakpoint_enabled`, `windbg.remove_breakpoint`
- `windbg.execute`, `windbg.wait_for_event`, `windbg.execute_command`

All operations use an explicit `session_id`. Memory reads and writes are
bounded to 4096 bytes per request, and list and stack results are bounded to
256 items per page.

`windbg.execute_command` passes native WinDbg and extension commands directly
to DbgEng, including commands that execute, mutate, log, dump, carve, or use
the shell. Files are created only when the command requests them. Long-running
commands use a five-minute timeout by default; pass `timeout_ms` up to
`1800000` (30 minutes) when symbol loading or analysis needs longer.

## Existing WinDbg GUI sessions

The MCP uses DbgEng directly and does not require the WinDbg GUI for dump
analysis, process attachment, or process launch.

To control a session already open in WinDbg, expose that session as a local
debugging server from its command window:

```text
.server npipe:pipe=windbg_mcp
```

Then call `windbg.connect_frontend` with:

```json
{
  "connection": "npipe:server=localhost,pipe=windbg_mcp"
}
```

The returned session handle is used by every inspection and execution tool.
Closing the MCP session disconnects the MCP client without ending the WinDbg
session.

## Remote live debugging

`windbg.connect_remote` controls an existing WinDbg or CDB session on another
Windows host. In that debugger's command window, start a TCP debugging server:

```text
.server tcp:port=5005
```

Then connect from the MCP client:

```json
{
  "host": "192.168.1.20",
  "port": 5005
}
```

For one visible local WinDbg server, `windbg.auto_connect` discovers and joins
it. Use `windbg.discover_servers` when more than one server is running.

The remote GUI is not required for the MCP itself; it is only needed when you
want to share a session that is already open in WinDbg. For direct process
debugging without a GUI, start Microsoft's `dbgsrv.exe` on the target host,
then use `windbg.attach_remote_process` with its TCP port and the remote PID,
or `windbg.launch_remote_process` to start a process there. All subsequent
inspection and command tools work with the returned session ID.

```text
dbgsrv.exe -t tcp:port=5005
```

TCP debugging is unencrypted. Restrict the port with a firewall and use a
server password or a secured WinDbg transport when the network is not trusted.
