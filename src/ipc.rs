use rmcp::schemars;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum WorkerRequest {
    OpenDump {
        path: String,
    },
    ConnectFrontend {
        connection: String,
    },
    AttachRemoteProcess {
        connection: String,
        pid: u32,
        noninvasive: bool,
    },
    LaunchRemoteProcess {
        connection: String,
        command_line: String,
        terminate_on_close: bool,
    },
    AttachProcess {
        pid: u32,
        noninvasive: bool,
    },
    LaunchProcess {
        command_line: String,
        terminate_on_close: bool,
    },
    Status,
    ListProcesses,
    ListThreads {
        start: u32,
        count: u32,
    },
    SelectThread {
        engine_id: u32,
    },
    ListModules {
        start: u32,
        count: u32,
    },
    StackTrace {
        max_frames: u32,
    },
    Registers,
    Evaluate {
        expression: String,
    },
    Disassemble {
        address: u64,
        count: u32,
    },
    SymbolFromAddress {
        address: u64,
    },
    AddressFromSymbol {
        symbol: String,
    },
    ReadMemory {
        address: u64,
        length: u32,
    },
    WriteMemory {
        address: u64,
        bytes: Vec<u8>,
    },
    GetSymbolPath,
    SetSymbolPath {
        path: String,
    },
    ReloadSymbols {
        module: Option<String>,
    },
    ListBreakpoints,
    SetBreakpoint {
        expression: String,
        one_shot: bool,
        kind: BreakpointKind,
        data_size: Option<u32>,
        access: Option<BreakpointAccess>,
        condition: Option<String>,
        pass_count: Option<u32>,
        match_thread: Option<u32>,
        enabled: bool,
    },
    RemoveBreakpoint {
        id: u32,
    },
    SetBreakpointEnabled {
        id: u32,
        enabled: bool,
    },
    Execute {
        action: ExecutionAction,
        timeout_ms: u32,
    },
    ExecuteCommand {
        command: String,
    },
    Close,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TargetSummary {
    pub source: String,
    pub target_kind: String,
    pub target_qualifier: String,
    pub architecture: String,
    pub processor_type: String,
    pub execution_status: String,
    pub instruction_pointer: Option<String>,
    pub current_process_engine_id: Option<u32>,
    pub current_process_system_id: Option<u32>,
    pub current_thread_engine_id: Option<u32>,
    pub current_thread_system_id: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DebugServerInfo {
    pub connection: String,
    pub server_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DebugServerList {
    pub machine: String,
    pub servers: Vec<DebugServerInfo>,
    pub raw_output: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakpointKind {
    Code,
    Data,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakpointAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MemoryRead {
    pub address: String,
    pub bytes_read: usize,
    pub hex: String,
    pub ascii: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MemoryWrite {
    pub address: String,
    pub bytes_written: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessInfo {
    pub engine_id: u32,
    pub system_id: u32,
    pub data_offset: Option<String>,
    pub executable: Option<String>,
    pub current: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProcessList {
    pub processes: Vec<ProcessInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ThreadInfo {
    pub engine_id: u32,
    pub system_id: u32,
    pub teb: Option<String>,
    pub current: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ThreadList {
    pub total: u32,
    pub start: u32,
    pub returned: usize,
    pub next_start: Option<u32>,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ContextSelection {
    pub current_process_engine_id: u32,
    pub current_process_system_id: u32,
    pub current_thread_engine_id: u32,
    pub current_thread_system_id: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ModuleInfo {
    pub index: u32,
    pub name: Option<String>,
    pub image_name: Option<String>,
    pub symbol_file: Option<String>,
    pub base: String,
    pub end: String,
    pub size: u32,
    pub timestamp: String,
    pub checksum: String,
    pub flags: String,
    pub symbol_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ModuleList {
    pub loaded_total: u32,
    pub unloaded_total: u32,
    pub start: u32,
    pub returned: usize,
    pub next_start: Option<u32>,
    pub modules: Vec<ModuleInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub displacement: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StackFrame {
    pub number: u32,
    pub instruction: String,
    pub return_offset: String,
    pub frame_offset: String,
    pub stack_offset: String,
    pub symbol: Option<String>,
    pub symbol_displacement: Option<String>,
    pub source: Option<SourceLocation>,
    pub parameters: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StackTrace {
    pub thread_engine_id: u32,
    pub thread_system_id: u32,
    pub frames: Vec<StackFrame>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RegisterValue {
    pub index: u32,
    pub name: String,
    pub value_type: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RegisterList {
    pub thread_engine_id: u32,
    pub registers: Vec<RegisterValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExpressionValue {
    pub expression: String,
    pub value_type: String,
    pub value: String,
    pub remainder_index: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DisassemblyInstruction {
    pub address: String,
    pub next_address: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Disassembly {
    pub instructions: Vec<DisassemblyInstruction>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SymbolLookup {
    pub address: String,
    pub symbol: Option<String>,
    pub displacement: Option<String>,
    pub source: Option<SourceLocation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SymbolPath {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SymbolReload {
    pub module: Option<String>,
    pub completed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BreakpointInfo {
    pub id: u32,
    pub kind: String,
    pub enabled: bool,
    pub one_shot: bool,
    pub deferred: bool,
    pub offset: Option<String>,
    pub expression: Option<String>,
    pub match_thread: Option<u32>,
    pub pass_count: u32,
    pub current_pass_count: u32,
    pub data_size: Option<u32>,
    pub access: Option<String>,
    pub command: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BreakpointList {
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAction {
    Continue,
    StepInto,
    StepOver,
    StepBranch,
    Break,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExecutionResult {
    pub action: ExecutionAction,
    pub execution_status: String,
    pub stopped: bool,
    pub timed_out: bool,
    pub event_type: Option<String>,
    pub event_process_engine_id: Option<u32>,
    pub event_thread_engine_id: Option<u32>,
    pub event_description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CommandResult {
    pub command: String,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub enum WorkerResponse {
    Opened(TargetSummary),
    Summary(TargetSummary),
    Processes(ProcessList),
    Threads(ThreadList),
    Context(ContextSelection),
    Modules(ModuleList),
    Stack(StackTrace),
    Registers(RegisterList),
    Expression(ExpressionValue),
    Disassembly(Disassembly),
    Symbol(SymbolLookup),
    Memory(MemoryRead),
    MemoryWritten(MemoryWrite),
    SymbolPath(SymbolPath),
    SymbolsReloaded(SymbolReload),
    Breakpoints(BreakpointList),
    Breakpoint(BreakpointInfo),
    BreakpointRemoved { id: u32 },
    Execution(ExecutionResult),
    CommandOutput(CommandResult),
    Closed,
    Error { code: String, message: String },
}
