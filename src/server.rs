use rmcp::{
    ServerHandler,
    handler::server::wrapper::{Json, Parameters},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::{
    dbgeng,
    ipc::{
        BreakpointInfo, BreakpointList, CommandResult, ContextSelection, Disassembly,
        ExecutionAction, ExecutionResult, ExpressionValue, MemoryRead, MemoryWrite, ModuleList,
        ProcessList, RegisterList, StackTrace, SymbolLookup, SymbolPath, SymbolReload,
        TargetSummary, ThreadList,
    },
    sessions::SessionManager,
};

#[derive(Clone, Default)]
pub struct WindbgServer {
    sessions: SessionManager,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct HealthResult {
    pub server: String,
    pub version: String,
    pub protocol_target: String,
    pub transport: String,
    pub platform: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct EngineProbeResult {
    pub available: bool,
    pub backend: String,
    pub message: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenDumpParams {
    /// Absolute path to a .dmp, .mdmp, or .hdmp file on the Windows host.
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectFrontendParams {
    /// WinDbg debugging-server connection string. Use npipe:server=localhost,pipe=<name> for a
    /// local GUI session or tcp:server=<host>,port=<port> for a remote session.
    pub connection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectRemoteParams {
    /// Remote Windows host name or IP address running a WinDbg debugging server.
    pub host: String,
    /// TCP port exposed by the remote WinDbg debugging server.
    pub port: u16,
    /// Optional TCP server password.
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AttachProcessParams {
    /// Windows system process identifier.
    pub pid: u32,
    /// Use a noninvasive attach. This limits mutation and execution-control capabilities.
    #[serde(default)]
    pub noninvasive: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AttachRemoteProcessParams {
    /// Remote Windows host name or IP address running dbgsrv.exe.
    pub host: String,
    /// TCP port exposed by dbgsrv.exe.
    pub port: u16,
    /// Optional TCP process-server password.
    pub password: Option<String>,
    /// Windows system process identifier on the remote host.
    pub pid: u32,
    /// Use a noninvasive attach. This limits mutation and execution-control capabilities.
    #[serde(default)]
    pub noninvasive: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LaunchProcessParams {
    /// Windows command line. It is passed directly to DbgEng, not through a shell.
    pub command_line: String,
    /// Terminate the launched target when the MCP session closes; otherwise detach and leave it running.
    pub terminate_on_close: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LaunchRemoteProcessParams {
    /// Remote Windows host name or IP address running dbgsrv.exe.
    pub host: String,
    /// TCP port exposed by dbgsrv.exe.
    pub port: u16,
    /// Optional TCP process-server password.
    pub password: Option<String>,
    /// Windows command line executed on the remote host. It is passed directly to DbgEng.
    pub command_line: String,
    /// Terminate the launched target when the MCP session closes; otherwise detach and leave it running.
    pub terminate_on_close: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionParams {
    /// Explicit debugger session handle returned by an open, attach, launch, or frontend tool.
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OpenDumpResult {
    pub session_id: String,
    pub target: TargetSummary,
    pub retention: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadMemoryParams {
    /// Explicit debugger session handle.
    pub session_id: String,
    /// Virtual address as hexadecimal (0x...) or decimal text.
    pub address: String,
    /// Number of bytes to read, from 1 through 4096.
    pub length: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PageParams {
    pub session_id: String,
    /// Zero-based item offset. Defaults to zero.
    pub start: Option<u32>,
    /// Page size from 1 through 256. Defaults to 64.
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SelectThreadParams {
    pub session_id: String,
    /// DbgEng thread ID, not the operating-system thread ID.
    pub engine_id: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StackTraceParams {
    pub session_id: String,
    /// Maximum number of frames from 1 through 256. Defaults to 64.
    pub max_frames: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EvaluateParams {
    pub session_id: String,
    /// DbgEng expression, for example "poi(@rsp)" or "kernel32!CreateFileW".
    pub expression: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisassembleParams {
    pub session_id: String,
    /// Starting virtual address as hexadecimal (0x...) or decimal text.
    pub address: String,
    /// Instruction count from 1 through 256. Defaults to 16.
    pub count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddressParams {
    pub session_id: String,
    /// Virtual address as hexadecimal (0x...) or decimal text.
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SymbolParams {
    pub session_id: String,
    /// Qualified or unqualified DbgEng symbol expression.
    pub symbol: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteMemoryParams {
    pub session_id: String,
    /// Destination virtual address as hexadecimal (0x...) or decimal text.
    pub address: String,
    /// One to 4096 bytes encoded as hexadecimal; ASCII whitespace is ignored.
    pub hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetSymbolPathParams {
    pub session_id: String,
    /// DbgEng symbol path, including srv* stores if desired.
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReloadSymbolsParams {
    pub session_id: String,
    /// Optional module selector. Omit to reload all modules.
    pub module: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetBreakpointParams {
    pub session_id: String,
    /// Address or DbgEng symbol expression used as the breakpoint offset.
    pub expression: String,
    /// Remove the breakpoint automatically after it fires once.
    #[serde(default)]
    pub one_shot: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoveBreakpointParams {
    pub session_id: String,
    pub breakpoint_id: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteParams {
    pub session_id: String,
    pub action: ExecutionAction,
    /// Maximum event wait in milliseconds, up to 20000. Defaults to 5000.
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteCommandParams {
    pub session_id: String,
    /// A native WinDbg command or extension command, for example "!analyze -v", "lm", "k", or "u @rip".
    pub command: String,
    /// Maximum time to wait for DbgEng to finish the command in milliseconds. Defaults to 300000 (5 minutes), up to 1800000 (30 minutes).
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReadMemoryResult {
    pub session_id: String,
    pub memory: MemoryRead,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SessionResult<T> {
    pub session_id: String,
    pub data: T,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RemoveBreakpointResult {
    pub session_id: String,
    pub breakpoint_id: u32,
    pub removed: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SessionStatusResult {
    pub session_id: String,
    pub target: TargetSummary,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListSessionsResult {
    pub session_ids: Vec<String>,
    pub count: usize,
    pub maximum: usize,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CloseSessionResult {
    pub session_id: String,
    pub closed: bool,
}

#[tool_router]
impl WindbgServer {
    pub fn new() -> Self {
        Self::default()
    }

    #[tool(
        name = "windbg.health",
        description = "Report server, transport, platform, and protocol-target information without opening a debugger session"
    )]
    fn health(&self, Parameters(EmptyParams {}): Parameters<EmptyParams>) -> Json<HealthResult> {
        Json(HealthResult {
            server: "windbg-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_target: "2026-07-28".to_string(),
            transport: "stdio".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    #[tool(
        name = "windbg.engine_probe",
        description = "Verify that the Microsoft Windows Debugger Engine can be loaded and an IDebugClient5 can be created"
    )]
    async fn engine_probe(
        &self,
        Parameters(EmptyParams {}): Parameters<EmptyParams>,
    ) -> Json<EngineProbeResult> {
        let result = tokio::task::spawn_blocking(dbgeng::probe).await;
        Json(match result {
            Ok(Ok(())) => EngineProbeResult {
                available: true,
                backend: "DbgEng/IDebugClient5".to_string(),
                message: "Microsoft Debugger Engine initialized successfully".to_string(),
            },
            Ok(Err(error)) => EngineProbeResult {
                available: false,
                backend: "DbgEng/IDebugClient5".to_string(),
                message: error.to_string(),
            },
            Err(error) => EngineProbeResult {
                available: false,
                backend: "DbgEng/IDebugClient5".to_string(),
                message: format!("engine probe task failed: {error}"),
            },
        })
    }

    #[tool(
        name = "windbg.open_dump",
        description = "Open a Windows crash dump in an isolated DbgEng worker and return an explicit session handle. The dump is read-only; at most four sessions may be open."
    )]
    async fn open_dump(
        &self,
        Parameters(OpenDumpParams { path }): Parameters<OpenDumpParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .open_dump(&path)
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: "until windbg.close_session or MCP server exit".to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.connect_frontend",
        description = "Join an existing WinDbg session through a local named-pipe or remote TCP debugging server and return an explicit session handle. Use .server npipe:pipe=<name> or .server tcp:port=<port>. Closing the MCP session disconnects only this client."
    )]
    async fn connect_frontend(
        &self,
        Parameters(ConnectFrontendParams { connection }): Parameters<ConnectFrontendParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .connect_frontend(&connection)
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: "until windbg.close_session or MCP server exit".to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.connect_remote",
        description = "Connect to an existing WinDbg or CDB debugging server over TCP and return an explicit session handle. On the remote GUI, start a server with .server tcp:port=<port>."
    )]
    async fn connect_remote(
        &self,
        Parameters(ConnectRemoteParams {
            host,
            port,
            password,
        }): Parameters<ConnectRemoteParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .connect_remote(&host, port, password.as_deref())
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: "until windbg.close_session or MCP server exit".to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.attach_process",
        description = "Attach a new isolated DbgEng session to a local Windows process and stop at the initial event. Closing the session detaches without terminating the process."
    )]
    async fn attach_process(
        &self,
        Parameters(AttachProcessParams { pid, noninvasive }): Parameters<AttachProcessParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .attach_process(pid, noninvasive)
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: "until windbg.close_session or MCP server exit".to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.attach_remote_process",
        description = "Connect to dbgsrv.exe on a remote Windows host over TCP, attach to a process by PID, and return an explicit session handle."
    )]
    async fn attach_remote_process(
        &self,
        Parameters(AttachRemoteProcessParams {
            host,
            port,
            password,
            pid,
            noninvasive,
        }): Parameters<AttachRemoteProcessParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .attach_remote_process(&host, port, password.as_deref(), pid, noninvasive)
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: "until windbg.close_session or MCP server exit".to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.launch_process",
        description = "Launch a local Windows process under an isolated DbgEng session and stop at its initial event. The command line is passed directly to DbgEng, not to a shell."
    )]
    async fn launch_process(
        &self,
        Parameters(LaunchProcessParams {
            command_line,
            terminate_on_close,
        }): Parameters<LaunchProcessParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .launch_process(&command_line, terminate_on_close)
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: if terminate_on_close {
                        "target terminates on windbg.close_session or MCP server exit"
                    } else {
                        "target is detached on windbg.close_session or MCP server exit"
                    }
                    .to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.launch_remote_process",
        description = "Connect to dbgsrv.exe on a remote Windows host over TCP, launch a process there under DbgEng, and return an explicit session handle."
    )]
    async fn launch_remote_process(
        &self,
        Parameters(LaunchRemoteProcessParams {
            host,
            port,
            password,
            command_line,
            terminate_on_close,
        }): Parameters<LaunchRemoteProcessParams>,
    ) -> Result<Json<OpenDumpResult>, String> {
        self.sessions
            .launch_remote_process(
                &host,
                port,
                password.as_deref(),
                &command_line,
                terminate_on_close,
            )
            .await
            .map(|(session_id, target)| {
                Json(OpenDumpResult {
                    session_id,
                    target,
                    retention: if terminate_on_close {
                        "target terminates on windbg.close_session or MCP server exit"
                    } else {
                        "target is detached on windbg.close_session or MCP server exit"
                    }
                    .to_string(),
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.session_status",
        description = "Return target type, architecture, execution state, and instruction pointer for an explicit debugger session"
    )]
    async fn session_status(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<SessionStatusResult>, String> {
        self.sessions
            .status(&session_id)
            .await
            .map(|target| Json(SessionStatusResult { session_id, target }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.list_processes",
        description = "List processes in a debugger session with DbgEng IDs, Windows process IDs, data offsets, executable names, and current-context state"
    )]
    async fn list_processes(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<SessionResult<ProcessList>>, String> {
        self.sessions
            .list_processes(&session_id)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.list_threads",
        description = "List a page of threads in the current process with DbgEng IDs, Windows thread IDs, TEB addresses, and current-context state"
    )]
    async fn list_threads(
        &self,
        Parameters(PageParams {
            session_id,
            start,
            count,
        }): Parameters<PageParams>,
    ) -> Result<Json<SessionResult<ThreadList>>, String> {
        self.sessions
            .list_threads(&session_id, start.unwrap_or(0), count.unwrap_or(64))
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.select_thread",
        description = "Set the current DbgEng thread context used by register, stack, expression, and disassembly tools"
    )]
    async fn select_thread(
        &self,
        Parameters(SelectThreadParams {
            session_id,
            engine_id,
        }): Parameters<SelectThreadParams>,
    ) -> Result<Json<SessionResult<ContextSelection>>, String> {
        self.sessions
            .select_thread(&session_id, engine_id)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.list_modules",
        description = "List a page of loaded modules with names, address ranges, checksums, timestamps, and symbol-loading state"
    )]
    async fn list_modules(
        &self,
        Parameters(PageParams {
            session_id,
            start,
            count,
        }): Parameters<PageParams>,
    ) -> Result<Json<SessionResult<ModuleList>>, String> {
        self.sessions
            .list_modules(&session_id, start.unwrap_or(0), count.unwrap_or(64))
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.stack_trace",
        description = "Walk the current thread stack and return addresses, symbols, source locations, and the four frame parameters"
    )]
    async fn stack_trace(
        &self,
        Parameters(StackTraceParams {
            session_id,
            max_frames,
        }): Parameters<StackTraceParams>,
    ) -> Result<Json<SessionResult<StackTrace>>, String> {
        self.sessions
            .stack_trace(&session_id, max_frames.unwrap_or(64))
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.get_registers",
        description = "Return every native register for the current thread as lossless typed strings"
    )]
    async fn get_registers(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<SessionResult<RegisterList>>, String> {
        self.sessions
            .registers(&session_id)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.evaluate",
        description = "Evaluate a DbgEng expression in the current process and thread context and return its native typed value"
    )]
    async fn evaluate(
        &self,
        Parameters(EvaluateParams {
            session_id,
            expression,
        }): Parameters<EvaluateParams>,
    ) -> Result<Json<SessionResult<ExpressionValue>>, String> {
        self.sessions
            .evaluate(&session_id, &expression)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.disassemble",
        description = "Disassemble a bounded number of instructions from a virtual address using the target's active architecture"
    )]
    async fn disassemble(
        &self,
        Parameters(DisassembleParams {
            session_id,
            address,
            count,
        }): Parameters<DisassembleParams>,
    ) -> Result<Json<SessionResult<Disassembly>>, String> {
        let address = parse_address(&address)?;
        self.sessions
            .disassemble(&session_id, address, count.unwrap_or(16))
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.symbol_from_address",
        description = "Resolve a virtual address to its nearest symbol and source line when symbols are available"
    )]
    async fn symbol_from_address(
        &self,
        Parameters(AddressParams {
            session_id,
            address,
        }): Parameters<AddressParams>,
    ) -> Result<Json<SessionResult<SymbolLookup>>, String> {
        let address = parse_address(&address)?;
        self.sessions
            .symbol_from_address(&session_id, address)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.address_from_symbol",
        description = "Resolve a DbgEng symbol name to an exact virtual address and return matching source information when available"
    )]
    async fn address_from_symbol(
        &self,
        Parameters(SymbolParams { session_id, symbol }): Parameters<SymbolParams>,
    ) -> Result<Json<SessionResult<SymbolLookup>>, String> {
        self.sessions
            .address_from_symbol(&session_id, &symbol)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.read_memory",
        description = "Read 1-4096 bytes of virtual memory from an explicit stopped debugger session and return lossless hex plus an ASCII preview"
    )]
    async fn read_memory(
        &self,
        Parameters(ReadMemoryParams {
            session_id,
            address,
            length,
        }): Parameters<ReadMemoryParams>,
    ) -> Result<Json<ReadMemoryResult>, String> {
        let parsed_address = parse_address(&address)?;
        self.sessions
            .read_memory(&session_id, parsed_address, length)
            .await
            .map(|memory| Json(ReadMemoryResult { session_id, memory }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.write_memory",
        description = "Write 1-4096 explicitly supplied bytes to virtual memory. This mutates a live target or the debugger's dump view and should require user approval."
    )]
    async fn write_memory(
        &self,
        Parameters(WriteMemoryParams {
            session_id,
            address,
            hex,
        }): Parameters<WriteMemoryParams>,
    ) -> Result<Json<SessionResult<MemoryWrite>>, String> {
        let address = parse_address(&address)?;
        let bytes = parse_hex_bytes(&hex)?;
        self.sessions
            .write_memory(&session_id, address, bytes)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.get_symbol_path",
        description = "Return the DbgEng symbol search path for an explicit debugger session"
    )]
    async fn get_symbol_path(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<SessionResult<SymbolPath>>, String> {
        self.sessions
            .get_symbol_path(&session_id)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.set_symbol_path",
        description = "Replace the DbgEng symbol search path. srv* entries may cause network symbol downloads when symbols are resolved."
    )]
    async fn set_symbol_path(
        &self,
        Parameters(SetSymbolPathParams { session_id, path }): Parameters<SetSymbolPathParams>,
    ) -> Result<Json<SessionResult<SymbolPath>>, String> {
        self.sessions
            .set_symbol_path(&session_id, &path)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.reload_symbols",
        description = "Reload symbols for one module selector or all modules using the session's current symbol path"
    )]
    async fn reload_symbols(
        &self,
        Parameters(ReloadSymbolsParams { session_id, module }): Parameters<ReloadSymbolsParams>,
    ) -> Result<Json<SessionResult<SymbolReload>>, String> {
        self.sessions
            .reload_symbols(&session_id, module.as_deref())
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.list_breakpoints",
        description = "List code and data breakpoints with IDs, flags, offsets, expressions, thread matches, and pass counts"
    )]
    async fn list_breakpoints(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<SessionResult<BreakpointList>>, String> {
        self.sessions
            .list_breakpoints(&session_id)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.set_breakpoint",
        description = "Create and enable a code breakpoint from an address or symbol expression. This mutates debugger state and should require user approval."
    )]
    async fn set_breakpoint(
        &self,
        Parameters(SetBreakpointParams {
            session_id,
            expression,
            one_shot,
        }): Parameters<SetBreakpointParams>,
    ) -> Result<Json<SessionResult<BreakpointInfo>>, String> {
        self.sessions
            .set_breakpoint(&session_id, &expression, one_shot)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.remove_breakpoint",
        description = "Remove one debugger breakpoint by its DbgEng breakpoint ID. This mutates debugger state and should require user approval."
    )]
    async fn remove_breakpoint(
        &self,
        Parameters(RemoveBreakpointParams {
            session_id,
            breakpoint_id,
        }): Parameters<RemoveBreakpointParams>,
    ) -> Result<Json<RemoveBreakpointResult>, String> {
        self.sessions
            .remove_breakpoint(&session_id, breakpoint_id)
            .await
            .map(|breakpoint_id| {
                Json(RemoveBreakpointResult {
                    session_id,
                    breakpoint_id,
                    removed: true,
                })
            })
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.execute",
        description = "Continue, single-step, or break a live target and wait a bounded time for the next event. This changes target execution and should require user approval."
    )]
    async fn execute(
        &self,
        Parameters(ExecuteParams {
            session_id,
            action,
            timeout_ms,
        }): Parameters<ExecuteParams>,
    ) -> Result<Json<SessionResult<ExecutionResult>>, String> {
        self.sessions
            .execute(&session_id, action, timeout_ms.unwrap_or(5000))
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.execute_command",
        description = "Execute any native WinDbg or extension command through DbgEng and capture its output. The MCP does not create files implicitly; commands such as .logopen, .dump, or .shell create files only when the command itself requests it."
    )]
    async fn execute_command(
        &self,
        Parameters(ExecuteCommandParams {
            session_id,
            command,
            timeout_ms,
        }): Parameters<ExecuteCommandParams>,
    ) -> Result<Json<SessionResult<CommandResult>>, String> {
        self.sessions
            .execute_command(&session_id, &command, timeout_ms)
            .await
            .map(|data| Json(SessionResult { session_id, data }))
            .map_err(|error| error.to_string())
    }

    #[tool(
        name = "windbg.list_sessions",
        description = "List the explicit debugger session handles currently owned by this MCP server process"
    )]
    async fn list_sessions(
        &self,
        Parameters(EmptyParams {}): Parameters<EmptyParams>,
    ) -> Json<ListSessionsResult> {
        let session_ids = self.sessions.list_ids().await;
        Json(ListSessionsResult {
            count: session_ids.len(),
            session_ids,
            maximum: 4,
        })
    }

    #[tool(
        name = "windbg.close_session",
        description = "Close an explicit debugger session and stop its isolated worker process"
    )]
    async fn close_session(
        &self,
        Parameters(SessionParams { session_id }): Parameters<SessionParams>,
    ) -> Result<Json<CloseSessionResult>, String> {
        self.sessions
            .close(&session_id)
            .await
            .map(|()| {
                Json(CloseSessionResult {
                    session_id,
                    closed: true,
                })
            })
            .map_err(|error| error.to_string())
    }
}

#[tool_handler(
    name = "windbg-mcp",
    version = "0.1.3",
    instructions = "Structured local and remote access to Microsoft's Windows Debugger Engine. Debugger state is represented by explicit session handles; there is no implicit current session."
)]
impl ServerHandler for WindbgServer {}

fn parse_address(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("invalid_argument: address must not be empty".to_string());
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid_argument: invalid hexadecimal address '{value}'"))
    } else {
        value
            .parse::<u64>()
            .map_err(|_| format!("invalid_argument: invalid decimal address '{value}'"))
    }
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let compact = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);
    if compact.is_empty() {
        return Err("invalid_argument: hex payload must not be empty".to_string());
    }
    if compact.len() % 2 != 0 {
        return Err("invalid_argument: hex payload must contain complete bytes".to_string());
    }
    if compact.len() > 8192 {
        return Err("invalid_argument: write is limited to 4096 bytes".to_string());
    }
    (0..compact.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&compact[index..index + 2], 16)
                .map_err(|_| "invalid_argument: hex payload contains a non-hex byte".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_address, parse_hex_bytes};

    #[test]
    fn parses_hex_and_decimal_addresses() {
        assert_eq!(parse_address("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_address("4660").unwrap(), 0x1234);
    }

    #[test]
    fn rejects_invalid_address() {
        assert!(parse_address("not-an-address").is_err());
    }

    #[test]
    fn parses_hex_bytes_with_whitespace() {
        assert_eq!(parse_hex_bytes("0x41 42\n43").unwrap(), b"ABC");
    }

    #[test]
    fn rejects_partial_hex_byte() {
        assert!(parse_hex_bytes("abc").is_err());
    }
}
