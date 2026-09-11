use std::{
    ffi::c_void,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, Mutex, OnceLock},
};

use windows::{
    Win32::System::Diagnostics::Debug::{
        EXCEPTION_RECORD64,
        Extensions::{
            DEBUG_ANY_ID, DEBUG_ATTACH_DEFAULT, DEBUG_ATTACH_NONINVASIVE, DEBUG_BREAKPOINT_CODE,
            DEBUG_BREAKPOINT_DEFERRED, DEBUG_BREAKPOINT_ENABLED, DEBUG_BREAKPOINT_ONE_SHOT,
            DEBUG_CLASS_IMAGE_FILE, DEBUG_CLASS_KERNEL, DEBUG_CLASS_USER_WINDOWS,
            DEBUG_CONNECT_SESSION_NO_ANNOUNCE, DEBUG_CONNECT_SESSION_NO_VERSION,
            DEBUG_END_ACTIVE_DETACH, DEBUG_END_ACTIVE_TERMINATE, DEBUG_END_DISCONNECT,
            DEBUG_EVENT_BREAKPOINT, DEBUG_EVENT_CHANGE_DEBUGGEE_STATE,
            DEBUG_EVENT_CHANGE_ENGINE_STATE, DEBUG_EVENT_CHANGE_SYMBOL_STATE,
            DEBUG_EVENT_CREATE_PROCESS, DEBUG_EVENT_CREATE_THREAD, DEBUG_EVENT_EXCEPTION,
            DEBUG_EVENT_EXIT_PROCESS, DEBUG_EVENT_EXIT_THREAD, DEBUG_EVENT_LOAD_MODULE,
            DEBUG_EVENT_SERVICE_EXCEPTION, DEBUG_EVENT_SESSION_STATUS, DEBUG_EVENT_SYSTEM_ERROR,
            DEBUG_EVENT_UNLOAD_MODULE, DEBUG_EXECUTE_DEFAULT, DEBUG_INTERRUPT_ACTIVE,
            DEBUG_MODNAME_IMAGE, DEBUG_MODNAME_MODULE, DEBUG_MODNAME_SYMBOL_FILE,
            DEBUG_MODULE_PARAMETERS, DEBUG_OUTCTL_THIS_CLIENT, DEBUG_SERVERS_DEBUGGER,
            DEBUG_STACK_FRAME, DEBUG_STATUS_BREAK, DEBUG_STATUS_GO, DEBUG_STATUS_GO_HANDLED,
            DEBUG_STATUS_GO_NOT_HANDLED, DEBUG_STATUS_IGNORE_EVENT, DEBUG_STATUS_NO_DEBUGGEE,
            DEBUG_STATUS_RESTART_REQUESTED, DEBUG_STATUS_STEP_BRANCH, DEBUG_STATUS_STEP_INTO,
            DEBUG_STATUS_STEP_OVER, DEBUG_STATUS_TIMEOUT, DEBUG_STATUS_WAIT_INPUT,
            DEBUG_SYMTYPE_CODEVIEW, DEBUG_SYMTYPE_COFF, DEBUG_SYMTYPE_DEFERRED, DEBUG_SYMTYPE_DIA,
            DEBUG_SYMTYPE_EXPORT, DEBUG_SYMTYPE_NONE, DEBUG_SYMTYPE_PDB, DEBUG_SYMTYPE_SYM,
            DEBUG_VALUE, DEBUG_VALUE_FLOAT32, DEBUG_VALUE_FLOAT64, DEBUG_VALUE_FLOAT80,
            DEBUG_VALUE_FLOAT82, DEBUG_VALUE_FLOAT128, DEBUG_VALUE_INT8, DEBUG_VALUE_INT16,
            DEBUG_VALUE_INT32, DEBUG_VALUE_INT64, DEBUG_VALUE_INVALID, DEBUG_VALUE_VECTOR64,
            DEBUG_VALUE_VECTOR128, IDebugBreakpoint2, IDebugClient, IDebugClient5, IDebugControl7,
            IDebugDataSpaces4, IDebugEventCallbacksWide, IDebugEventCallbacksWide_Impl,
            IDebugOutputCallbacksWide, IDebugOutputCallbacksWide_Impl, IDebugRegisters2,
            IDebugSymbols5, IDebugSystemObjects4,
        },
    },
    Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        LoadLibraryExW,
    },
    core::{GUID, HRESULT, Interface, PCSTR, PCWSTR},
};

use crate::ipc::{
    BreakpointInfo, BreakpointList, CommandResult, ContextSelection, DebugServerInfo,
    DebugServerList, Disassembly, DisassemblyInstruction, ExecutionAction, ExecutionResult,
    ExpressionValue, MemoryRead, MemoryWrite, ModuleInfo, ModuleList, ProcessInfo, ProcessList,
    RegisterList, RegisterValue, SourceLocation, StackFrame, StackTrace, SymbolLookup, SymbolPath,
    SymbolReload, TargetSummary, ThreadInfo, ThreadList,
};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("DbgEng initialization failed: {0}")]
    Initialization(String),
    #[error("failed to open dump '{path}': {message}")]
    OpenDump { path: String, message: String },
    #[error("failed while waiting for the dump's initial event: {0}")]
    InitialEvent(String),
    #[error("failed to connect to WinDbg frontend '{connection}': {message}")]
    ConnectFrontend { connection: String, message: String },
    #[error("failed to connect to DbgEng process server '{connection}': {message}")]
    ConnectProcessServer { connection: String, message: String },
    #[error("DbgEng query failed: {0}")]
    Query(String),
}

type DebugCreateFn = unsafe extern "system" fn(*const GUID, *mut *mut c_void) -> HRESULT;
type DebugConnectWideFn =
    unsafe extern "system" fn(PCWSTR, *const GUID, *mut *mut c_void) -> HRESULT;

struct EngineApi {
    debug_create: DebugCreateFn,
    debug_connect_wide: DebugConnectWideFn,
    _path: PathBuf,
}

static ENGINE_API: OnceLock<Result<EngineApi, String>> = OnceLock::new();

fn engine_api() -> Result<&'static EngineApi, EngineError> {
    ENGINE_API
        .get_or_init(load_engine_api)
        .as_ref()
        .map_err(|message| EngineError::Initialization(message.clone()))
}

fn load_engine_api() -> Result<EngineApi, String> {
    let mut candidates = Vec::new();
    if let Some(directory) = std::env::var_os("WINDBG_MCP_DEBUGGER_DIR") {
        candidates.push(PathBuf::from(directory).join("dbgeng.dll"));
    }
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        candidates.push(
            PathBuf::from(program_files_x86).join(r"Windows Kits\10\Debuggers\x64\dbgeng.dll"),
        );
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates
            .push(PathBuf::from(program_files).join(r"Windows Kits\10\Debuggers\x64\dbgeng.dll"));
    }
    candidates.push(PathBuf::from(r"C:\Windows\System32\dbgeng.dll"));

    let mut failures = Vec::new();
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        match unsafe { load_engine_api_from(&path) } {
            Ok(api) => return Ok(api),
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    Err(if failures.is_empty() {
        "could not locate dbgeng.dll; install Debugging Tools for Windows or set WINDBG_MCP_DEBUGGER_DIR"
            .to_string()
    } else {
        format!(
            "could not load a usable dbgeng.dll ({})",
            failures.join("; ")
        )
    })
}

unsafe fn load_engine_api_from(path: &Path) -> Result<EngineApi, String> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(wide.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }
    .map_err(|error| error.to_string())?;
    let debug_create = unsafe {
        GetProcAddress(module, PCSTR(b"DebugCreate\0".as_ptr()))
            .ok_or_else(|| "DebugCreate export is missing".to_string())?
    };
    let debug_connect_wide = unsafe {
        GetProcAddress(module, PCSTR(b"DebugConnectWide\0".as_ptr()))
            .ok_or_else(|| "DebugConnectWide export is missing".to_string())?
    };
    Ok(EngineApi {
        debug_create: unsafe { std::mem::transmute(debug_create) },
        debug_connect_wide: unsafe { std::mem::transmute(debug_connect_wide) },
        _path: path.to_path_buf(),
    })
}

fn debug_create<T: Interface>() -> Result<T, EngineError> {
    let api = engine_api()?;
    let mut raw = ptr::null_mut();
    unsafe { (api.debug_create)(&T::IID, &mut raw) }
        .ok()
        .map_err(|error| EngineError::Initialization(error.to_string()))?;
    if raw.is_null() {
        return Err(EngineError::Initialization(
            "DebugCreate returned a null interface".to_string(),
        ));
    }
    Ok(unsafe { T::from_raw(raw) })
}

fn create_client() -> Result<IDebugClient5, EngineError> {
    debug_create::<IDebugClient>()?
        .cast::<IDebugClient5>()
        .map_err(|error| EngineError::Initialization(error.to_string()))
}

fn debug_connect_wide(connection: PCWSTR) -> Result<IDebugClient5, EngineError> {
    let api = engine_api()?;
    let mut raw = ptr::null_mut();
    unsafe { (api.debug_connect_wide)(connection, &IDebugClient::IID, &mut raw) }
        .ok()
        .map_err(|error| EngineError::Initialization(error.to_string()))?;
    if raw.is_null() {
        return Err(EngineError::Initialization(
            "DebugConnectWide returned a null interface".to_string(),
        ));
    }
    let client = unsafe { IDebugClient::from_raw(raw) };
    client
        .cast::<IDebugClient5>()
        .map_err(|error| EngineError::Initialization(error.to_string()))
}

#[windows::core::implement(IDebugEventCallbacksWide)]
struct EventCallbacks;

#[allow(non_snake_case)]
impl IDebugEventCallbacksWide_Impl for EventCallbacks_Impl {
    fn GetInterestMask(&self) -> windows::core::Result<u32> {
        Ok(DEBUG_EVENT_BREAKPOINT
            | DEBUG_EVENT_EXCEPTION
            | DEBUG_EVENT_CREATE_THREAD
            | DEBUG_EVENT_EXIT_THREAD
            | DEBUG_EVENT_CREATE_PROCESS
            | DEBUG_EVENT_EXIT_PROCESS
            | DEBUG_EVENT_LOAD_MODULE
            | DEBUG_EVENT_UNLOAD_MODULE
            | DEBUG_EVENT_SYSTEM_ERROR
            | DEBUG_EVENT_SESSION_STATUS
            | DEBUG_EVENT_CHANGE_DEBUGGEE_STATE
            | DEBUG_EVENT_CHANGE_ENGINE_STATE
            | DEBUG_EVENT_CHANGE_SYMBOL_STATE
            | DEBUG_EVENT_SERVICE_EXCEPTION)
    }

    fn Breakpoint(&self, _bp: windows::core::Ref<IDebugBreakpoint2>) -> windows::core::Result<()> {
        debugger_callback_status(DEBUG_STATUS_BREAK)
    }

    fn Exception(
        &self,
        _exception: *const EXCEPTION_RECORD64,
        _firstchance: u32,
    ) -> windows::core::Result<()> {
        debugger_callback_status(DEBUG_STATUS_BREAK)
    }

    fn CreateThread(
        &self,
        _handle: u64,
        _dataoffset: u64,
        _startoffset: u64,
    ) -> windows::core::Result<()> {
        // Thread creation is informational; stopping here would make every
        // normal continue operation break as soon as a target creates a
        // worker thread.
        Ok(())
    }

    fn ExitThread(&self, _exitcode: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn CreateProcessA(
        &self,
        _imagefilehandle: u64,
        _handle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        _modulename: &PCWSTR,
        _imagename: &PCWSTR,
        _checksum: u32,
        _timedatestamp: u32,
        _initialthreadhandle: u64,
        _threaddataoffset: u64,
        _startoffset: u64,
    ) -> windows::core::Result<()> {
        // DbgEng does not otherwise surface the initial process-create stop
        // through WaitForEvent on all retail engine builds. Returning BREAK
        // here mirrors the debugger's initial-stop behavior.
        debugger_callback_status(DEBUG_STATUS_BREAK)
    }

    fn ExitProcess(&self, _exitcode: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn LoadModule(
        &self,
        _imagefilehandle: u64,
        _baseoffset: u64,
        _modulesize: u32,
        _modulename: &PCWSTR,
        _imagename: &PCWSTR,
        _checksum: u32,
        _timedatestamp: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn UnloadModule(&self, _imagebasename: &PCWSTR, _baseoffset: u64) -> windows::core::Result<()> {
        Ok(())
    }

    fn SystemError(&self, _error: u32, _level: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn SessionStatus(&self, _status: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeDebuggeeState(&self, _flags: u32, _argument: u64) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeEngineState(&self, _flags: u32, _argument: u64) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeSymbolState(&self, _flags: u32, _argument: u64) -> windows::core::Result<()> {
        Ok(())
    }
}

#[windows::core::implement(IDebugOutputCallbacksWide)]
struct OutputCallbacks {
    buffer: Arc<Mutex<String>>,
}

#[allow(non_snake_case)]
impl IDebugOutputCallbacksWide_Impl for OutputCallbacks_Impl {
    fn Output(&self, _mask: u32, text: &PCWSTR) -> windows::core::Result<()> {
        if let Ok(text) = unsafe { text.to_string() }
            && let Ok(mut buffer) = self.buffer.lock()
        {
            if buffer.len() < 1_048_576 {
                buffer.push_str(&text);
                let length = buffer.len().min(1_048_576);
                buffer.truncate(length);
            }
        }
        Ok(())
    }
}

fn debugger_callback_status(status: u32) -> windows::core::Result<()> {
    // DbgEng event callbacks return DEBUG_STATUS_* values in the HRESULT slot.
    // The Win32 projection models the slot as Result<()>, so preserve the
    // positive status code through Error rather than collapsing it to S_OK.
    Err(windows::core::Error::from_hresult(HRESULT(status as i32)))
}

pub fn probe() -> Result<(), EngineError> {
    // DbgEng objects are deliberately kept inside this function. The Windows
    // projection marks them !Send and !Sync, matching DbgEng's thread-affinity
    // requirements. Session workers preserve this ownership model.
    let client = create_client()?;
    drop(client);
    Ok(())
}

pub fn discover_servers(machine: &str) -> Result<DebugServerList, EngineError> {
    let client = create_client()?;
    let output = Arc::new(Mutex::new(String::new()));
    let callbacks: IDebugOutputCallbacksWide = OutputCallbacks {
        buffer: Arc::clone(&output),
    }
    .into();
    unsafe { client.SetOutputCallbacksWide(&callbacks) }
        .map_err(|error| EngineError::Initialization(error.to_string()))?;

    let mut wide_machine: Vec<u16> = machine.encode_utf16().collect();
    wide_machine.push(0);
    unsafe {
        client.OutputServersWide(
            DEBUG_OUTCTL_THIS_CLIENT,
            PCWSTR(wide_machine.as_ptr()),
            DEBUG_SERVERS_DEBUGGER,
        )
    }
    .map_err(|error| EngineError::Query(error.to_string()))?;

    let raw_output = output
        .lock()
        .map(|mut value| std::mem::take(&mut *value))
        .unwrap_or_default();
    let servers = parse_server_output(&raw_output);
    Ok(DebugServerList {
        machine: machine.to_string(),
        servers,
        raw_output,
    })
}

fn parse_server_output(output: &str) -> Vec<DebugServerInfo> {
    let mut servers = Vec::new();
    for token in output.split_whitespace() {
        let token = token.trim_matches(|character: char| "\"'`<>(),".contains(character));
        let Some((transport, _)) = token.split_once(':') else {
            continue;
        };
        if !matches!(
            transport.to_ascii_lowercase().as_str(),
            "npipe" | "tcp" | "spipe" | "ssl" | "com"
        ) {
            continue;
        }
        if servers
            .iter()
            .any(|server: &DebugServerInfo| server.connection.eq_ignore_ascii_case(token))
        {
            continue;
        }
        servers.push(DebugServerInfo {
            connection: token.to_string(),
            server_type: "debugger".to_string(),
        });
    }
    servers
}

pub struct EngineSession {
    client: IDebugClient5,
    control: IDebugControl7,
    registers: IDebugRegisters2,
    data_spaces: IDebugDataSpaces4,
    symbols: IDebugSymbols5,
    system_objects: IDebugSystemObjects4,
    _event_callbacks: IDebugEventCallbacksWide,
    _output_callbacks: IDebugOutputCallbacksWide,
    output: Arc<Mutex<String>>,
    source: String,
    close_mode: CloseMode,
}

#[derive(Clone, Copy)]
enum CloseMode {
    OwnedTarget { terminate: bool },
    RemoteClient,
    ProcessServer { server: u64, terminate: bool },
}

impl EngineSession {
    pub fn open_dump(path: &Path) -> Result<Self, EngineError> {
        let client = create_client()?;
        let session = Self::from_client(
            client,
            path.display().to_string(),
            CloseMode::OwnedTarget { terminate: false },
        )?;

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);
        unsafe {
            session
                .client
                .OpenDumpFileWide(PCWSTR(wide_path.as_ptr()), 0)
        }
        .map_err(|error| EngineError::OpenDump {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;

        unsafe { session.control.WaitForEvent(0, u32::MAX) }.map_err(|error| {
            EngineError::InitialEvent(format_engine_error(
                error.to_string(),
                session.take_output(),
            ))
        })?;
        Ok(session)
    }

    pub fn connect_frontend(connection: &str) -> Result<Self, EngineError> {
        let mut wide_connection: Vec<u16> = connection.encode_utf16().collect();
        wide_connection.push(0);
        let client = debug_connect_wide(PCWSTR(wide_connection.as_ptr())).map_err(|error| {
            EngineError::ConnectFrontend {
                connection: connection.to_string(),
                message: error.to_string(),
            }
        })?;
        unsafe {
            client.ConnectSession(
                DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE,
                0,
            )
        }
        .map_err(|error| EngineError::ConnectFrontend {
            connection: connection.to_string(),
            message: error.to_string(),
        })?;
        Self::from_client(
            client,
            format!("windbg://{}", redact_connection(connection)),
            CloseMode::RemoteClient,
        )
    }

    pub fn attach_remote_process(
        connection: &str,
        pid: u32,
        noninvasive: bool,
    ) -> Result<Self, EngineError> {
        let client = create_client()?;
        let server = connect_process_server(&client, connection)?;
        let session = Self::from_client(
            client,
            format!(
                "process-server://{}/pid/{pid}",
                redact_connection(connection)
            ),
            CloseMode::ProcessServer {
                server,
                terminate: false,
            },
        )?;
        let flags = if noninvasive {
            DEBUG_ATTACH_NONINVASIVE
        } else {
            DEBUG_ATTACH_DEFAULT
        };
        unsafe { session.client.AttachProcess(server, pid, flags) }.map_err(|error| {
            EngineError::Initialization(format!(
                "failed to attach to remote process {pid}: {error}"
            ))
        })?;
        unsafe { session.control.WaitForEvent(0, u32::MAX) }.map_err(|error| {
            EngineError::InitialEvent(format_engine_error(
                error.to_string(),
                session.take_output(),
            ))
        })?;
        Ok(session)
    }

    pub fn launch_remote_process(
        connection: &str,
        command_line: &str,
        terminate_on_close: bool,
    ) -> Result<Self, EngineError> {
        let client = create_client()?;
        let server = connect_process_server(&client, connection)?;
        let session = Self::from_client(
            client,
            format!(
                "process-server://{}/{}",
                redact_connection(connection),
                command_line
            ),
            CloseMode::ProcessServer {
                server,
                terminate: terminate_on_close,
            },
        )?;
        let mut wide_command: Vec<u16> = command_line.encode_utf16().collect();
        wide_command.push(0);
        const DEBUG_CREATE_FLAGS: u32 = 0x0000_0002;
        unsafe {
            session.client.CreateProcessWide(
                server,
                PCWSTR(wide_command.as_ptr()),
                DEBUG_CREATE_FLAGS,
            )
        }
        .map_err(|error| {
            EngineError::Initialization(format!("failed to launch remote process: {error}"))
        })?;
        unsafe { session.control.WaitForEvent(0, u32::MAX) }.map_err(|error| {
            EngineError::InitialEvent(format_engine_error(
                error.to_string(),
                session.take_output(),
            ))
        })?;
        Ok(session)
    }

    pub fn attach_process(pid: u32, noninvasive: bool) -> Result<Self, EngineError> {
        let client = create_client()?;
        let session = Self::from_client(
            client,
            format!("pid://{pid}"),
            CloseMode::OwnedTarget { terminate: false },
        )?;
        let flags = if noninvasive {
            DEBUG_ATTACH_NONINVASIVE
        } else {
            DEBUG_ATTACH_DEFAULT
        };
        unsafe { session.client.AttachProcess(0, pid, flags) }.map_err(|error| {
            EngineError::Initialization(format!("failed to attach to process {pid}: {error}"))
        })?;
        unsafe { session.control.WaitForEvent(0, u32::MAX) }.map_err(|error| {
            EngineError::InitialEvent(format_engine_error(
                error.to_string(),
                session.take_output(),
            ))
        })?;
        Ok(session)
    }

    pub fn launch_process(
        command_line: &str,
        terminate_on_close: bool,
    ) -> Result<Self, EngineError> {
        let client = create_client()?;
        let session = Self::from_client(
            client,
            format!("process://{command_line}"),
            CloseMode::OwnedTarget {
                terminate: terminate_on_close,
            },
        )?;
        let mut wide_command: Vec<u16> = command_line.encode_utf16().collect();
        wide_command.push(0);
        // DEBUG_ONLY_THIS_PROCESS. Worker stdio handles have inheritance
        // disabled before this call so a console target cannot corrupt IPC.
        const DEBUG_CREATE_FLAGS: u32 = 0x0000_0002;
        unsafe {
            session
                .client
                .CreateProcessWide(0, PCWSTR(wide_command.as_ptr()), DEBUG_CREATE_FLAGS)
        }
        .map_err(|error| {
            EngineError::Initialization(format!("failed to launch process: {error}"))
        })?;
        unsafe { session.control.WaitForEvent(0, u32::MAX) }.map_err(|error| {
            EngineError::InitialEvent(format_engine_error(
                error.to_string(),
                session.take_output(),
            ))
        })?;
        Ok(session)
    }

    fn from_client(
        client: IDebugClient5,
        source: String,
        close_mode: CloseMode,
    ) -> Result<Self, EngineError> {
        let control = client
            .cast::<IDebugControl7>()
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let registers = client
            .cast::<IDebugRegisters2>()
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let data_spaces = client
            .cast::<IDebugDataSpaces4>()
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let symbols = client
            .cast::<IDebugSymbols5>()
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let system_objects = client
            .cast::<IDebugSystemObjects4>()
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let event_callbacks: IDebugEventCallbacksWide = EventCallbacks.into();
        unsafe { client.SetEventCallbacksWide(&event_callbacks) }
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        let output = Arc::new(Mutex::new(String::new()));
        let output_callbacks: IDebugOutputCallbacksWide = OutputCallbacks {
            buffer: Arc::clone(&output),
        }
        .into();
        unsafe { client.SetOutputCallbacksWide(&output_callbacks) }
            .map_err(|error| EngineError::Initialization(error.to_string()))?;
        Ok(Self {
            client,
            control,
            registers,
            data_spaces,
            symbols,
            system_objects,
            _event_callbacks: event_callbacks,
            _output_callbacks: output_callbacks,
            output,
            source,
            close_mode,
        })
    }

    pub fn summary(&self) -> Result<TargetSummary, EngineError> {
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let processor = unsafe { self.control.GetActualProcessorType() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let execution = unsafe { self.control.GetExecutionStatus() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let instruction_offset = unsafe { self.registers.GetInstructionOffset() }.ok();
        let current_process_engine_id = unsafe { self.system_objects.GetCurrentProcessId() }.ok();
        let current_process_system_id =
            unsafe { self.system_objects.GetCurrentProcessSystemId() }.ok();
        let current_thread_engine_id = unsafe { self.system_objects.GetCurrentThreadId() }.ok();
        let current_thread_system_id =
            unsafe { self.system_objects.GetCurrentThreadSystemId() }.ok();

        Ok(TargetSummary {
            source: self.source.clone(),
            target_kind: debuggee_class_name(class).to_string(),
            target_qualifier: format!("0x{qualifier:08x}"),
            architecture: processor_name(processor).to_string(),
            processor_type: format!("0x{processor:04x}"),
            execution_status: execution_status_name(execution).to_string(),
            instruction_pointer: instruction_offset.map(|offset| format!("0x{offset:016x}")),
            current_process_engine_id,
            current_process_system_id,
            current_thread_engine_id,
            current_thread_system_id,
        })
    }

    fn take_output(&self) -> String {
        let Ok(mut output) = self.output.lock() else {
            return String::new();
        };
        std::mem::take(&mut *output)
    }

    pub fn list_processes(&self) -> Result<ProcessList, EngineError> {
        let count = unsafe { self.system_objects.GetNumberProcesses() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let current = unsafe { self.system_objects.GetCurrentProcessId() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut engine_ids = vec![0u32; count as usize];
        let mut system_ids = vec![0u32; count as usize];
        unsafe {
            self.system_objects.GetProcessIdsByIndex(
                0,
                count,
                Some(engine_ids.as_mut_ptr()),
                Some(system_ids.as_mut_ptr()),
            )
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;

        let mut processes = Vec::with_capacity(count as usize);
        for (&engine_id, &system_id) in engine_ids.iter().zip(&system_ids) {
            let (data_offset, executable) =
                if unsafe { self.system_objects.SetCurrentProcessId(engine_id) }.is_ok() {
                    (
                        unsafe { self.system_objects.GetCurrentProcessDataOffset() }
                            .ok()
                            .map(hex_address),
                        self.current_process_executable(),
                    )
                } else {
                    (None, None)
                };
            processes.push(ProcessInfo {
                engine_id,
                system_id,
                data_offset,
                executable,
                current: engine_id == current,
            });
        }
        let _ = unsafe { self.system_objects.SetCurrentProcessId(current) };
        Ok(ProcessList { processes })
    }

    pub fn list_threads(&self, start: u32, count: u32) -> Result<ThreadList, EngineError> {
        let total = unsafe { self.system_objects.GetNumberThreads() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        if start > total {
            return Err(EngineError::Query(format!(
                "thread start {start} exceeds total {total}"
            )));
        }
        let count = count.min(total.saturating_sub(start));
        let current = unsafe { self.system_objects.GetCurrentThreadId() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut engine_ids = vec![0u32; count as usize];
        let mut system_ids = vec![0u32; count as usize];
        if count > 0 {
            unsafe {
                self.system_objects.GetThreadIdsByIndex(
                    start,
                    count,
                    Some(engine_ids.as_mut_ptr()),
                    Some(system_ids.as_mut_ptr()),
                )
            }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        }

        let mut threads = Vec::with_capacity(count as usize);
        for (&engine_id, &system_id) in engine_ids.iter().zip(&system_ids) {
            let teb = if unsafe { self.system_objects.SetCurrentThreadId(engine_id) }.is_ok() {
                unsafe { self.system_objects.GetCurrentThreadTeb() }
                    .ok()
                    .map(hex_address)
            } else {
                None
            };
            threads.push(ThreadInfo {
                engine_id,
                system_id,
                teb,
                current: engine_id == current,
            });
        }
        let _ = unsafe { self.system_objects.SetCurrentThreadId(current) };
        let next = start.saturating_add(count);
        Ok(ThreadList {
            total,
            start,
            returned: threads.len(),
            next_start: (next < total).then_some(next),
            threads,
        })
    }

    pub fn select_thread(&self, engine_id: u32) -> Result<ContextSelection, EngineError> {
        unsafe { self.system_objects.SetCurrentThreadId(engine_id) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        self.current_context()
    }

    pub fn list_modules(&self, start: u32, count: u32) -> Result<ModuleList, EngineError> {
        let mut loaded = 0;
        let mut unloaded = 0;
        unsafe { self.symbols.GetNumberModules(&mut loaded, &mut unloaded) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        if start > loaded {
            return Err(EngineError::Query(format!(
                "module start {start} exceeds loaded total {loaded}"
            )));
        }
        let count = count.min(loaded.saturating_sub(start));
        let mut modules = Vec::with_capacity(count as usize);
        for index in start..start.saturating_add(count) {
            let base = unsafe { self.symbols.GetModuleByIndex(index) }
                .map_err(|error| EngineError::Query(error.to_string()))?;
            let mut parameters = DEBUG_MODULE_PARAMETERS::default();
            unsafe {
                self.symbols
                    .GetModuleParameters(1, Some(&base), 0, &mut parameters)
            }
            .map_err(|error| EngineError::Query(error.to_string()))?;
            modules.push(ModuleInfo {
                index,
                name: self.module_name(DEBUG_MODNAME_MODULE, index, base),
                image_name: self.module_name(DEBUG_MODNAME_IMAGE, index, base),
                symbol_file: self.module_name(DEBUG_MODNAME_SYMBOL_FILE, index, base),
                base: hex_address(base),
                end: hex_address(base.saturating_add(parameters.Size as u64)),
                size: parameters.Size,
                timestamp: format!("0x{:08x}", parameters.TimeDateStamp),
                checksum: format!("0x{:08x}", parameters.Checksum),
                flags: format!("0x{:08x}", parameters.Flags),
                symbol_type: symbol_type_name(parameters.SymbolType).to_string(),
            });
        }
        let next = start.saturating_add(count);
        Ok(ModuleList {
            loaded_total: loaded,
            unloaded_total: unloaded,
            start,
            returned: modules.len(),
            next_start: (next < loaded).then_some(next),
            modules,
        })
    }

    pub fn stack_trace(&self, max_frames: u32) -> Result<StackTrace, EngineError> {
        let thread_engine_id = unsafe { self.system_objects.GetCurrentThreadId() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let thread_system_id = unsafe { self.system_objects.GetCurrentThreadSystemId() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut frames = vec![DEBUG_STACK_FRAME::default(); max_frames as usize];
        let mut filled = 0;
        unsafe {
            self.control
                .GetStackTrace(0, 0, 0, &mut frames, Some(&mut filled))
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        frames.truncate(filled as usize);
        let frames = frames
            .into_iter()
            .map(|frame| {
                let (symbol, displacement) = self.symbol_name(frame.InstructionOffset);
                StackFrame {
                    number: frame.FrameNumber,
                    instruction: hex_address(frame.InstructionOffset),
                    return_offset: hex_address(frame.ReturnOffset),
                    frame_offset: hex_address(frame.FrameOffset),
                    stack_offset: hex_address(frame.StackOffset),
                    symbol,
                    symbol_displacement: displacement.map(hex_address),
                    source: self.source_location(frame.InstructionOffset),
                    parameters: frame.Params.into_iter().map(hex_address).collect(),
                }
            })
            .collect();
        Ok(StackTrace {
            thread_engine_id,
            thread_system_id,
            frames,
        })
    }

    pub fn registers(&self) -> Result<RegisterList, EngineError> {
        let thread_engine_id = unsafe { self.system_objects.GetCurrentThreadId() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let count = unsafe { self.registers.GetNumberRegisters() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut values = vec![DEBUG_VALUE::default(); count as usize];
        if count > 0 {
            unsafe {
                self.registers
                    .GetValues(count, None, 0, values.as_mut_ptr())
            }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        }
        let registers = values
            .iter()
            .enumerate()
            .map(|(index, value)| RegisterValue {
                index: index as u32,
                name: self.register_name(index as u32),
                value_type: debug_value_type_name(value.Type).to_string(),
                value: debug_value_string(value),
            })
            .collect();
        Ok(RegisterList {
            thread_engine_id,
            registers,
        })
    }

    pub fn evaluate(&self, expression: &str) -> Result<ExpressionValue, EngineError> {
        let mut wide: Vec<u16> = expression.encode_utf16().collect();
        wide.push(0);
        let mut value = DEBUG_VALUE::default();
        let mut remainder = 0;
        unsafe {
            self.control.EvaluateWide(
                PCWSTR(wide.as_ptr()),
                DEBUG_VALUE_INVALID,
                &mut value,
                Some(&mut remainder),
            )
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        Ok(ExpressionValue {
            expression: expression.to_string(),
            value_type: debug_value_type_name(value.Type).to_string(),
            value: debug_value_string(&value),
            remainder_index: remainder,
        })
    }

    pub fn disassemble(&self, address: u64, count: u32) -> Result<Disassembly, EngineError> {
        let mut instructions = Vec::with_capacity(count as usize);
        let mut offset = address;
        for _ in 0..count {
            let mut buffer = vec![0u16; 2048];
            let mut used = 0;
            let mut end = offset;
            unsafe {
                self.control.DisassembleWide(
                    offset,
                    0,
                    Some(&mut buffer),
                    Some(&mut used),
                    &mut end,
                )
            }
            .map_err(|error| EngineError::Query(error.to_string()))?;
            let text = utf16_result(&buffer, used).trim().to_string();
            instructions.push(DisassemblyInstruction {
                address: hex_address(offset),
                next_address: hex_address(end),
                text,
            });
            if end <= offset {
                break;
            }
            offset = end;
        }
        Ok(Disassembly { instructions })
    }

    pub fn symbol_from_address(&self, address: u64) -> Result<SymbolLookup, EngineError> {
        let (symbol, displacement) = self.symbol_name(address);
        Ok(SymbolLookup {
            address: hex_address(address),
            symbol,
            displacement: displacement.map(hex_address),
            source: self.source_location(address),
        })
    }

    pub fn address_from_symbol(&self, symbol: &str) -> Result<SymbolLookup, EngineError> {
        let mut wide: Vec<u16> = symbol.encode_utf16().collect();
        wide.push(0);
        let address = unsafe { self.symbols.GetOffsetByNameWide(PCWSTR(wide.as_ptr())) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        self.symbol_from_address(address)
    }

    pub fn read_memory(&self, address: u64, length: u32) -> Result<MemoryRead, EngineError> {
        let mut bytes = vec![0u8; length as usize];
        let mut bytes_read = 0;
        unsafe {
            self.data_spaces.ReadVirtual(
                address,
                bytes.as_mut_ptr().cast(),
                length,
                Some(&mut bytes_read),
            )
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        bytes.truncate(bytes_read as usize);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");
        let ascii = bytes
            .iter()
            .map(|byte| match byte {
                0x20..=0x7e => char::from(*byte),
                _ => '.',
            })
            .collect();
        Ok(MemoryRead {
            address: format!("0x{address:016x}"),
            bytes_read: bytes.len(),
            hex,
            ascii,
        })
    }

    pub fn write_memory(&self, address: u64, bytes: &[u8]) -> Result<MemoryWrite, EngineError> {
        let mut written = 0;
        unsafe {
            self.data_spaces.WriteVirtual(
                address,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                Some(&mut written),
            )
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        Ok(MemoryWrite {
            address: hex_address(address),
            bytes_written: written as usize,
        })
    }

    pub fn get_symbol_path(&self) -> Result<SymbolPath, EngineError> {
        let mut buffer = vec![0u16; 32768];
        let mut used = 0;
        unsafe {
            self.symbols
                .GetSymbolPathWide(Some(&mut buffer), Some(&mut used))
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        Ok(SymbolPath {
            path: utf16_result(&buffer, used),
        })
    }

    pub fn set_symbol_path(&self, path: &str) -> Result<SymbolPath, EngineError> {
        let mut wide: Vec<u16> = path.encode_utf16().collect();
        wide.push(0);
        unsafe { self.symbols.SetSymbolPathWide(PCWSTR(wide.as_ptr())) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        self.get_symbol_path()
    }

    pub fn reload_symbols(&self, module: Option<&str>) -> Result<SymbolReload, EngineError> {
        let value = module.unwrap_or("");
        let mut wide: Vec<u16> = value.encode_utf16().collect();
        wide.push(0);
        unsafe { self.symbols.ReloadWide(PCWSTR(wide.as_ptr())) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        Ok(SymbolReload {
            module: module.map(str::to_string),
            completed: true,
        })
    }

    pub fn list_breakpoints(&self) -> Result<BreakpointList, EngineError> {
        let count = unsafe { self.control.GetNumberBreakpoints() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut breakpoints = Vec::with_capacity(count as usize);
        for index in 0..count {
            let breakpoint = unsafe { self.control.GetBreakpointByIndex2(index) }
                .map_err(|error| EngineError::Query(error.to_string()))?;
            breakpoints.push(self.breakpoint_info(&breakpoint)?);
        }
        Ok(BreakpointList { breakpoints })
    }

    pub fn set_breakpoint(
        &self,
        expression: &str,
        one_shot: bool,
    ) -> Result<BreakpointInfo, EngineError> {
        let breakpoint = unsafe {
            self.control
                .AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut wide: Vec<u16> = expression.encode_utf16().collect();
        wide.push(0);
        let flags = DEBUG_BREAKPOINT_ENABLED
            | if one_shot {
                DEBUG_BREAKPOINT_ONE_SHOT
            } else {
                0
            };
        let configured = unsafe {
            breakpoint
                .SetOffsetExpressionWide(PCWSTR(wide.as_ptr()))
                .and_then(|()| breakpoint.AddFlags(flags))
        };
        if let Err(error) = configured {
            if unsafe { self.control.RemoveBreakpoint2(&breakpoint) }.is_ok() {
                // DbgEng deletes breakpoint objects on removal; calling the
                // projected COM Release afterward dereferences freed memory.
                std::mem::forget(breakpoint);
            }
            return Err(EngineError::Query(error.to_string()));
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn remove_breakpoint(&self, id: u32) -> Result<u32, EngineError> {
        // DbgEng's versioned RemoveBreakpoint2 path has crashed in current
        // retail dbgeng.dll builds after a successful GetBreakpointById2.
        // The base interface removes the same engine object safely.
        let breakpoint = unsafe { self.control.GetBreakpointById(id) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        unsafe { self.control.RemoveBreakpoint(&breakpoint) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        // IDebugBreakpoint is COM-shaped but DbgEng explicitly owns its
        // lifetime. RemoveBreakpoint deletes it, so it must not be Released.
        std::mem::forget(breakpoint);
        Ok(id)
    }

    pub fn execute(
        &self,
        action: ExecutionAction,
        timeout_ms: u32,
    ) -> Result<ExecutionResult, EngineError> {
        match action {
            ExecutionAction::Break => unsafe { self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) },
            ExecutionAction::Continue => unsafe {
                self.control.SetExecutionStatus(DEBUG_STATUS_GO)
            },
            ExecutionAction::StepInto => unsafe {
                self.control.SetExecutionStatus(DEBUG_STATUS_STEP_INTO)
            },
            ExecutionAction::StepOver => unsafe {
                self.control.SetExecutionStatus(DEBUG_STATUS_STEP_OVER)
            },
            ExecutionAction::StepBranch => unsafe {
                self.control.SetExecutionStatus(DEBUG_STATUS_STEP_BRANCH)
            },
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;

        unsafe { self.control.WaitForEvent(0, timeout_ms) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let status = unsafe { self.control.GetExecutionStatus() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let stopped = status == DEBUG_STATUS_BREAK || status == DEBUG_STATUS_NO_DEBUGGEE;
        let timed_out = !stopped && status != DEBUG_STATUS_WAIT_INPUT;
        let event = stopped.then(|| self.last_event()).transpose()?;
        let (event_type, process_id, thread_id, description) = match event {
            Some((event_type, process_id, thread_id, description)) => (
                Some(event_type),
                Some(process_id),
                Some(thread_id),
                Some(description),
            ),
            None => (None, None, None, None),
        };
        Ok(ExecutionResult {
            action,
            execution_status: execution_status_name(status).to_string(),
            stopped,
            timed_out,
            event_type,
            event_process_engine_id: process_id,
            event_thread_engine_id: thread_id,
            event_description: description,
        })
    }

    pub fn execute_command(&self, command: &str) -> Result<CommandResult, EngineError> {
        // Keep command execution on the same DbgEng thread as every other
        // operation. Output is delivered through IDebugOutputCallbacksWide.
        self.take_output();
        let mut wide: Vec<u16> = command.encode_utf16().collect();
        wide.push(0);
        let result = unsafe {
            self.control.ExecuteWide(
                DEBUG_OUTCTL_THIS_CLIENT,
                PCWSTR(wide.as_ptr()),
                DEBUG_EXECUTE_DEFAULT,
            )
        };
        let output = self.take_output();
        if let Err(error) = result {
            return Err(EngineError::Query(format_engine_error(
                error.to_string(),
                output,
            )));
        }
        Ok(CommandResult {
            command: command.to_string(),
            truncated: output.len() >= 1_048_576,
            output,
        })
    }

    fn current_context(&self) -> Result<ContextSelection, EngineError> {
        Ok(ContextSelection {
            current_process_engine_id: unsafe { self.system_objects.GetCurrentProcessId() }
                .map_err(|error| EngineError::Query(error.to_string()))?,
            current_process_system_id: unsafe { self.system_objects.GetCurrentProcessSystemId() }
                .map_err(|error| EngineError::Query(error.to_string()))?,
            current_thread_engine_id: unsafe { self.system_objects.GetCurrentThreadId() }
                .map_err(|error| EngineError::Query(error.to_string()))?,
            current_thread_system_id: unsafe { self.system_objects.GetCurrentThreadSystemId() }
                .map_err(|error| EngineError::Query(error.to_string()))?,
        })
    }

    fn current_process_executable(&self) -> Option<String> {
        let mut buffer = vec![0u16; 32768];
        let mut used = 0;
        unsafe {
            self.system_objects
                .GetCurrentProcessExecutableNameWide(Some(&mut buffer), Some(&mut used))
        }
        .ok()?;
        Some(utf16_result(&buffer, used))
    }

    fn module_name(&self, which: u32, index: u32, base: u64) -> Option<String> {
        let mut buffer = vec![0u16; 32768];
        let mut used = 0;
        unsafe {
            self.symbols.GetModuleNameStringWide(
                which,
                index,
                base,
                Some(&mut buffer),
                Some(&mut used),
            )
        }
        .ok()?;
        Some(utf16_result(&buffer, used))
    }

    fn register_name(&self, index: u32) -> String {
        let mut buffer = vec![0u16; 256];
        let mut used = 0;
        if unsafe {
            self.registers
                .GetDescriptionWide(index, Some(&mut buffer), Some(&mut used), None)
        }
        .is_ok()
        {
            utf16_result(&buffer, used)
        } else {
            format!("register_{index}")
        }
    }

    fn symbol_name(&self, address: u64) -> (Option<String>, Option<u64>) {
        let mut buffer = vec![0u16; 32768];
        let mut used = 0;
        let mut displacement = 0;
        if unsafe {
            self.symbols.GetNameByOffsetWide(
                address,
                Some(&mut buffer),
                Some(&mut used),
                Some(&mut displacement),
            )
        }
        .is_ok()
        {
            (Some(utf16_result(&buffer, used)), Some(displacement))
        } else {
            (None, None)
        }
    }

    fn source_location(&self, address: u64) -> Option<SourceLocation> {
        let mut buffer = vec![0u16; 32768];
        let mut used = 0;
        let mut line = 0;
        let mut displacement = 0;
        unsafe {
            self.symbols.GetLineByOffsetWide(
                address,
                Some(&mut line),
                Some(&mut buffer),
                Some(&mut used),
                Some(&mut displacement),
            )
        }
        .ok()?;
        Some(SourceLocation {
            file: utf16_result(&buffer, used),
            line,
            displacement,
        })
    }

    fn breakpoint_info(
        &self,
        breakpoint: &IDebugBreakpoint2,
    ) -> Result<BreakpointInfo, EngineError> {
        let id =
            unsafe { breakpoint.GetId() }.map_err(|error| EngineError::Query(error.to_string()))?;
        let flags = unsafe { breakpoint.GetFlags() }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let mut break_type = 0;
        let mut processor_type = 0;
        unsafe { breakpoint.GetType(&mut break_type, &mut processor_type) }
            .map_err(|error| EngineError::Query(error.to_string()))?;
        let offset = unsafe { breakpoint.GetOffset() }.ok().map(hex_address);
        let mut expression_buffer = vec![0u16; 4096];
        let mut expression_used = 0;
        let expression = unsafe {
            breakpoint
                .GetOffsetExpressionWide(Some(&mut expression_buffer), Some(&mut expression_used))
        }
        .ok()
        .map(|()| utf16_result(&expression_buffer, expression_used));
        let match_thread = unsafe { breakpoint.GetMatchThreadId() }
            .ok()
            .filter(|value| *value != DEBUG_ANY_ID);
        Ok(BreakpointInfo {
            id,
            kind: if break_type == DEBUG_BREAKPOINT_CODE {
                "code".to_string()
            } else {
                "data".to_string()
            },
            enabled: flags & DEBUG_BREAKPOINT_ENABLED != 0,
            one_shot: flags & DEBUG_BREAKPOINT_ONE_SHOT != 0,
            deferred: flags & DEBUG_BREAKPOINT_DEFERRED != 0,
            offset,
            expression,
            match_thread,
            pass_count: unsafe { breakpoint.GetPassCount() }.unwrap_or(0),
            current_pass_count: unsafe { breakpoint.GetCurrentPassCount() }.unwrap_or(0),
        })
    }

    fn last_event(&self) -> Result<(String, u32, u32, String), EngineError> {
        let mut event_type = 0;
        let mut process_id = 0;
        let mut thread_id = 0;
        let mut buffer = vec![0u16; 4096];
        let mut used = 0;
        unsafe {
            self.control.GetLastEventInformationWide(
                &mut event_type,
                &mut process_id,
                &mut thread_id,
                None,
                0,
                None,
                Some(&mut buffer),
                Some(&mut used),
            )
        }
        .map_err(|error| EngineError::Query(error.to_string()))?;
        Ok((
            event_type_name(event_type).to_string(),
            process_id,
            thread_id,
            utf16_result(&buffer, used),
        ))
    }
}

impl Drop for EngineSession {
    fn drop(&mut self) {
        let flag = match self.close_mode {
            CloseMode::OwnedTarget { terminate: false } => DEBUG_END_ACTIVE_DETACH,
            CloseMode::OwnedTarget { terminate: true } => DEBUG_END_ACTIVE_TERMINATE,
            CloseMode::RemoteClient => DEBUG_END_DISCONNECT,
            CloseMode::ProcessServer {
                terminate: false, ..
            } => DEBUG_END_ACTIVE_DETACH,
            CloseMode::ProcessServer {
                terminate: true, ..
            } => DEBUG_END_ACTIVE_TERMINATE,
        };
        let _ = unsafe { self.client.EndSession(flag) };
        if let CloseMode::ProcessServer { server, .. } = self.close_mode {
            let _ = unsafe { self.client.DisconnectProcessServer(server) };
        }
    }
}

fn connect_process_server(client: &IDebugClient5, connection: &str) -> Result<u64, EngineError> {
    let mut wide_connection: Vec<u16> = connection.encode_utf16().collect();
    wide_connection.push(0);
    unsafe { client.ConnectProcessServerWide(PCWSTR(wide_connection.as_ptr())) }.map_err(|error| {
        EngineError::ConnectProcessServer {
            connection: redact_connection(connection),
            message: error.to_string(),
        }
    })
}

fn redact_connection(connection: &str) -> String {
    connection
        .split(',')
        .map(|option| {
            option
                .split_once('=')
                .filter(|(key, _)| key.trim().eq_ignore_ascii_case("password"))
                .map_or_else(
                    || option.to_string(),
                    |(key, _)| format!("{key}=<redacted>"),
                )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn debuggee_class_name(value: u32) -> &'static str {
    match value {
        DEBUG_CLASS_KERNEL => "kernel",
        DEBUG_CLASS_USER_WINDOWS => "user_windows",
        DEBUG_CLASS_IMAGE_FILE => "image_file",
        _ => "unknown",
    }
}

fn processor_name(value: u32) -> &'static str {
    match value {
        0x014c => "x86",
        0x01c0 | 0x01c4 => "arm",
        0x8664 => "x64",
        0xaa64 => "arm64",
        _ => "unknown",
    }
}

fn execution_status_name(value: u32) -> &'static str {
    match value {
        DEBUG_STATUS_GO => "running",
        DEBUG_STATUS_GO_HANDLED => "running_handled",
        DEBUG_STATUS_GO_NOT_HANDLED => "running_not_handled",
        DEBUG_STATUS_STEP_OVER => "step_over",
        DEBUG_STATUS_STEP_INTO => "step_into",
        DEBUG_STATUS_BREAK => "break",
        DEBUG_STATUS_NO_DEBUGGEE => "no_debuggee",
        DEBUG_STATUS_STEP_BRANCH => "step_branch",
        DEBUG_STATUS_IGNORE_EVENT => "ignore_event",
        DEBUG_STATUS_RESTART_REQUESTED => "restart_requested",
        DEBUG_STATUS_WAIT_INPUT => "wait_input",
        DEBUG_STATUS_TIMEOUT => "timeout",
        _ => "unknown",
    }
}

fn symbol_type_name(value: u32) -> &'static str {
    match value {
        DEBUG_SYMTYPE_NONE => "none",
        DEBUG_SYMTYPE_COFF => "coff",
        DEBUG_SYMTYPE_CODEVIEW => "codeview",
        DEBUG_SYMTYPE_PDB => "pdb",
        DEBUG_SYMTYPE_EXPORT => "exports",
        DEBUG_SYMTYPE_DEFERRED => "deferred",
        DEBUG_SYMTYPE_SYM => "sym",
        DEBUG_SYMTYPE_DIA => "dia",
        _ => "unknown",
    }
}

fn debug_value_type_name(value: u32) -> &'static str {
    match value {
        DEBUG_VALUE_INVALID => "invalid",
        DEBUG_VALUE_INT8 => "int8",
        DEBUG_VALUE_INT16 => "int16",
        DEBUG_VALUE_INT32 => "int32",
        DEBUG_VALUE_INT64 => "int64",
        DEBUG_VALUE_FLOAT32 => "float32",
        DEBUG_VALUE_FLOAT64 => "float64",
        DEBUG_VALUE_FLOAT80 => "float80",
        DEBUG_VALUE_FLOAT82 => "float82",
        DEBUG_VALUE_FLOAT128 => "float128",
        DEBUG_VALUE_VECTOR64 => "vector64",
        DEBUG_VALUE_VECTOR128 => "vector128",
        _ => "unknown",
    }
}

fn debug_value_string(value: &DEBUG_VALUE) -> String {
    unsafe {
        match value.Type {
            DEBUG_VALUE_INT8 => format!("0x{:02x}", value.Anonymous.I8),
            DEBUG_VALUE_INT16 => format!("0x{:04x}", value.Anonymous.I16),
            DEBUG_VALUE_INT32 => format!("0x{:08x}", value.Anonymous.I32),
            DEBUG_VALUE_INT64 => format!("0x{:016x}", value.Anonymous.Anonymous.I64),
            DEBUG_VALUE_FLOAT32 => value.Anonymous.F32.to_string(),
            DEBUG_VALUE_FLOAT64 => value.Anonymous.F64.to_string(),
            DEBUG_VALUE_VECTOR64 => bytes_to_hex(&value.Anonymous.RawBytes[..8]),
            DEBUG_VALUE_VECTOR128 => bytes_to_hex(&value.Anonymous.RawBytes[..16]),
            _ => bytes_to_hex(&value.Anonymous.RawBytes),
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn event_type_name(value: u32) -> &'static str {
    match value {
        DEBUG_EVENT_BREAKPOINT => "breakpoint",
        DEBUG_EVENT_EXCEPTION => "exception",
        DEBUG_EVENT_CREATE_THREAD => "create_thread",
        DEBUG_EVENT_EXIT_THREAD => "exit_thread",
        DEBUG_EVENT_CREATE_PROCESS => "create_process",
        DEBUG_EVENT_EXIT_PROCESS => "exit_process",
        DEBUG_EVENT_LOAD_MODULE => "load_module",
        DEBUG_EVENT_UNLOAD_MODULE => "unload_module",
        DEBUG_EVENT_SYSTEM_ERROR => "system_error",
        DEBUG_EVENT_SESSION_STATUS => "session_status",
        DEBUG_EVENT_CHANGE_DEBUGGEE_STATE => "change_debuggee_state",
        DEBUG_EVENT_CHANGE_ENGINE_STATE => "change_engine_state",
        DEBUG_EVENT_CHANGE_SYMBOL_STATE => "change_symbol_state",
        DEBUG_EVENT_SERVICE_EXCEPTION => "service_exception",
        _ => "unknown",
    }
}

fn hex_address(value: u64) -> String {
    format!("0x{value:016x}")
}

fn utf16_result(buffer: &[u16], reported_size: u32) -> String {
    let reported_size = reported_size as usize;
    let end = reported_size.min(buffer.len());
    let end = buffer[..end]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(end);
    String::from_utf16_lossy(&buffer[..end])
}

fn format_engine_error(error: String, output: String) -> String {
    let output = output.trim();
    if output.is_empty() {
        error
    } else {
        format!("{error}; engine output: {output}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_names_are_stable() {
        assert_eq!(processor_name(0x8664), "x64");
        assert_eq!(processor_name(0xaa64), "arm64");
        assert_eq!(processor_name(0xffff), "unknown");
    }
}
