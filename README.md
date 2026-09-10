# WinDbg MCP

A greenfield Model Context Protocol server for Microsoft's Windows Debugger
Engine (`DbgEng.dll`). It exposes WinDbg inspection and control through MCP
stdio, with one isolated worker process per explicit debugger session.

## Requirements

- Windows 10 or newer
- Rust stable with the `x86_64-pc-windows-msvc` target
- Windows SDK **Debugging Tools for Windows** (x64 `dbgeng.dll`)
- A dump file, a local process, or an existing WinDbg debugging server

The server dynamically loads the installed x64 Debugging Tools copy of
`dbgeng.dll`. If it is installed in a nonstandard location, set
`WINDBG_MCP_DEBUGGER_DIR` to the directory containing that DLL.

## Build and run

```powershell
cargo build --release
& .\target\release\windbg-mcp.exe
```

The executable speaks MCP JSON-RPC on stdout; diagnostics are written to
stderr. Example client configuration:

```json
{
  "mcpServers": {
    "windbg": {
      "command": "E:\\Work\\mcp\\target\\release\\windbg-mcp.exe"
    }
  }
}
```

## Quick install for Codex and Claude Code

From this repository, run one PowerShell script:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

The script builds `target\release\windbg-mcp.exe`, removes any previous
`windbg` registration, and adds the executable to both Codex and Claude Code
user configuration when their CLIs are installed. Restart both clients after
installation. Use `-ServerName another-name` to choose a different MCP name,
or `-SkipBuild` when the release binary already exists.

This repository also contains native plugin manifests for marketplace-based
installation. After publishing it to GitHub, install it without editing a
configuration file manually:

```powershell
claude plugin marketplace add <owner>/windbg-mcp
claude plugin install windbg-mcp@windbg-mcp

codex plugin marketplace add <owner>/windbg-mcp
codex plugin add windbg-mcp@windbg-mcp
```

The Claude marketplace catalog is `.claude-plugin/marketplace.json`; its
`./` source points at this repository's plugin manifest. The Codex marketplace
catalog is `.agents/plugins/marketplace.json`; its local source points at the
same repository root, where `.codex-plugin/plugin.json` lives. The plugin
manifests start the server through Cargo from the installed plugin directory.
The direct installer is faster after the first build because it registers the
compiled release executable.

These commands use a community marketplace hosted by this repository. Listing
in an official vendor marketplace is a separate review/submission process and
is not required for private or team use.

## Tools

Session creation and lifecycle:

- `windbg.health`, `windbg.engine_probe`
- `windbg.open_dump`
- `windbg.connect_frontend`
- `windbg.attach_process`, `windbg.launch_process`
- `windbg.session_status`, `windbg.list_sessions`, `windbg.close_session`

Target and context inspection:

- `windbg.list_processes`, `windbg.list_threads`, `windbg.select_thread`
- `windbg.list_modules`, `windbg.stack_trace`, `windbg.get_registers`
- `windbg.evaluate`, `windbg.disassemble`
- `windbg.symbol_from_address`, `windbg.address_from_symbol`
- `windbg.read_memory`, `windbg.write_memory`

Symbols, breakpoints, and execution:

- `windbg.get_symbol_path`, `windbg.set_symbol_path`, `windbg.reload_symbols`
- `windbg.list_breakpoints`, `windbg.set_breakpoint`, `windbg.remove_breakpoint`
- `windbg.execute` (continue, step into, step over, step branch, break)
- `windbg.execute_command` (native WinDbg and extension commands with captured output)

All debugger operations take an explicit `session_id`; there is no hidden
global current session. Addresses are strings (`0x...` or decimal) so 64-bit
values remain exact in JavaScript MCP clients. Memory reads and writes are
bounded to 4096 bytes per request, and list/stack results are bounded to 256
items per page.

`windbg.execute_command` is a direct escape hatch for the complete WinDbg
command and extension ecosystem. Read-only commands such as `!analyze -v`,
`lm`, `k`, `u`, `dt`, `dx`, and `db` work, as do execution, mutation, logging,
dump, and shell commands. The MCP does not create files implicitly: commands
such as `.logopen`, `.dump`, or `.shell` create files only when the command
itself requests them.

Opening a dump, reading memory, evaluating expressions, or returning carved
bytes does not create files beside the dump. Symbol servers may populate their
configured cache when a `srv*` symbol path is used, and explicitly approved
WinDbg commands can write wherever their command line requests.

## Connect to the WinDbg frontend

In an active WinDbg command window, create a local named-pipe debugging server:

```text
.server npipe:pipe=windbg_mcp_demo
```

Then call `windbg.connect_frontend`:

```json
{
  "connection": "npipe:server=localhost,pipe=windbg_mcp_demo"
}
```

The returned session handle works with every inspection and control tool.
Closing it sends `DEBUG_END_DISCONNECT`, so the MCP client disconnects without
ending the WinDbg-owned debugging session. Only local `npipe` connections are
accepted; TCP, remote hosts, and password-bearing transports are deliberately
outside this server's trust boundary.

## Architecture and protocol

Each session runs in an isolated `--engine-worker` child process. DbgEng COM
objects stay on the worker's owning thread, while the parent maintains a
bounded asynchronous session table and newline-delimited private IPC. A worker
failure therefore cannot corrupt the MCP stdio stream or another session.

The server uses the current Rust MCP SDK, supports the 2026-07-28 MCP design
(including the legacy initialize fallback used by older clients), and returns
structured JSON tool results. Tool failures are reported as MCP tool errors.
