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

## Releases

Create a version tag to build and publish the Windows x64 release executable:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions publishes `windbg-mcp-x86_64-pc-windows-msvc.exe` and its
SHA-256 checksum in the repository's Releases tab.

To use a downloaded release directly:

```powershell
codex mcp add windbg -- C:\Path\To\windbg-mcp-x86_64-pc-windows-msvc.exe
claude mcp add --scope user windbg -- C:\Path\To\windbg-mcp-x86_64-pc-windows-msvc.exe
```

## Marketplace installation

The repository contains marketplace catalogs for both clients:

- Claude: `.claude-plugin/marketplace.json`
- Codex: `.agents/plugins/marketplace.json`

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
- `windbg.open_dump`, `windbg.connect_frontend`
- `windbg.attach_process`, `windbg.launch_process`
- `windbg.session_status`, `windbg.list_sessions`, `windbg.close_session`

Inspection and control:

- `windbg.list_processes`, `windbg.list_threads`, `windbg.select_thread`
- `windbg.list_modules`, `windbg.stack_trace`, `windbg.get_registers`
- `windbg.evaluate`, `windbg.disassemble`
- `windbg.symbol_from_address`, `windbg.address_from_symbol`
- `windbg.read_memory`, `windbg.write_memory`
- `windbg.get_symbol_path`, `windbg.set_symbol_path`, `windbg.reload_symbols`
- `windbg.list_breakpoints`, `windbg.set_breakpoint`, `windbg.remove_breakpoint`
- `windbg.execute`, `windbg.execute_command`

All operations use an explicit `session_id`. Memory reads and writes are
bounded to 4096 bytes per request, and list and stack results are bounded to
256 items per page.

`windbg.execute_command` passes native WinDbg and extension commands directly
to DbgEng, including commands that execute, mutate, log, dump, carve, or use
the shell. Files are created only when the command requests them.

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
