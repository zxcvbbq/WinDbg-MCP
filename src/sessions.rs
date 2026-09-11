use std::{collections::HashMap, path::Path, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, anyhow, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore},
    time::timeout,
};
use uuid::Uuid;

use crate::ipc::{
    BreakpointInfo, BreakpointList, CommandResult, ContextSelection, Disassembly, ExecutionAction,
    ExecutionResult, ExpressionValue, MemoryRead, MemoryWrite, ModuleList, ProcessList,
    RegisterList, StackTrace, SymbolLookup, SymbolPath, SymbolReload, TargetSummary, ThreadList,
    WorkerRequest, WorkerResponse,
};

const WORKER_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_SESSIONS: usize = 4;

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<SessionEntry>>>>,
    slots: Arc<Semaphore>,
}

pub struct SessionEntry {
    id: String,
    worker: Mutex<WorkerConnection>,
    _slot: OwnedSemaphorePermit,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(MAX_SESSIONS)),
        }
    }
}

struct WorkerConnection {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl SessionManager {
    pub async fn open_dump(&self, supplied_path: &str) -> anyhow::Result<(String, TargetSummary)> {
        let path = validate_dump_path(supplied_path)?;

        self.start_session(WorkerRequest::OpenDump {
            path: path.display().to_string(),
        })
        .await
    }

    pub async fn connect_frontend(
        &self,
        supplied_connection: &str,
    ) -> anyhow::Result<(String, TargetSummary)> {
        let connection = validate_frontend_connection(supplied_connection)?;
        self.start_session(WorkerRequest::ConnectFrontend { connection })
            .await
    }

    pub async fn connect_remote(
        &self,
        host: &str,
        port: u16,
        password: Option<&str>,
    ) -> anyhow::Result<(String, TargetSummary)> {
        let connection = build_tcp_connection(host, port, password)?;
        self.start_session(WorkerRequest::ConnectFrontend { connection })
            .await
    }

    pub async fn attach_remote_process(
        &self,
        host: &str,
        port: u16,
        password: Option<&str>,
        pid: u32,
        noninvasive: bool,
    ) -> anyhow::Result<(String, TargetSummary)> {
        validate_pid(pid)?;
        let connection = build_tcp_connection(host, port, password)?;
        self.start_session(WorkerRequest::AttachRemoteProcess {
            connection,
            pid,
            noninvasive,
        })
        .await
    }

    pub async fn launch_remote_process(
        &self,
        host: &str,
        port: u16,
        password: Option<&str>,
        command_line: &str,
        terminate_on_close: bool,
    ) -> anyhow::Result<(String, TargetSummary)> {
        validate_text("command_line", command_line, 32766)?;
        let connection = build_tcp_connection(host, port, password)?;
        self.start_session(WorkerRequest::LaunchRemoteProcess {
            connection,
            command_line: command_line.to_string(),
            terminate_on_close,
        })
        .await
    }

    pub async fn attach_process(
        &self,
        pid: u32,
        noninvasive: bool,
    ) -> anyhow::Result<(String, TargetSummary)> {
        validate_pid(pid)?;
        self.start_session(WorkerRequest::AttachProcess { pid, noninvasive })
            .await
    }

    pub async fn launch_process(
        &self,
        command_line: &str,
        terminate_on_close: bool,
    ) -> anyhow::Result<(String, TargetSummary)> {
        validate_text("command_line", command_line, 32766)?;
        self.start_session(WorkerRequest::LaunchProcess {
            command_line: command_line.to_string(),
            terminate_on_close,
        })
        .await
    }

    async fn start_session(
        &self,
        open_request: WorkerRequest,
    ) -> anyhow::Result<(String, TargetSummary)> {
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| {
            anyhow!("session_limit: at most {MAX_SESSIONS} debugger sessions may be open")
        })?;

        let executable = std::env::current_exe().context("cannot locate the MCP executable")?;
        let mut child = Command::new(executable)
            .arg("--engine-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start DbgEng worker")?;
        let stdin = child.stdin.take().context("worker stdin was not piped")?;
        let stdout = child.stdout.take().context("worker stdout was not piped")?;
        let mut worker = WorkerConnection {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };

        let response = worker.request(&open_request).await?;
        let summary = match response {
            WorkerResponse::Opened(summary) => summary,
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response while opening session: {other:?}"),
        };

        let id = Uuid::new_v4().to_string();
        let entry = Arc::new(SessionEntry {
            id: id.clone(),
            worker: Mutex::new(worker),
            _slot: slot,
        });
        self.sessions.write().await.insert(id.clone(), entry);
        Ok((id, summary))
    }

    pub async fn status(&self, id: &str) -> anyhow::Result<TargetSummary> {
        match self.request(id, WorkerRequest::Status).await? {
            WorkerResponse::Summary(summary) => Ok(summary),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for status: {other:?}"),
        }
    }

    pub async fn list_processes(&self, id: &str) -> anyhow::Result<ProcessList> {
        match self.request(id, WorkerRequest::ListProcesses).await? {
            WorkerResponse::Processes(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for process list: {other:?}"),
        }
    }

    pub async fn list_threads(
        &self,
        id: &str,
        start: u32,
        count: u32,
    ) -> anyhow::Result<ThreadList> {
        validate_page("thread", count)?;
        match self
            .request(id, WorkerRequest::ListThreads { start, count })
            .await?
        {
            WorkerResponse::Threads(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for thread list: {other:?}"),
        }
    }

    pub async fn select_thread(
        &self,
        id: &str,
        engine_id: u32,
    ) -> anyhow::Result<ContextSelection> {
        match self
            .request(id, WorkerRequest::SelectThread { engine_id })
            .await?
        {
            WorkerResponse::Context(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for thread selection: {other:?}"),
        }
    }

    pub async fn list_modules(
        &self,
        id: &str,
        start: u32,
        count: u32,
    ) -> anyhow::Result<ModuleList> {
        validate_page("module", count)?;
        match self
            .request(id, WorkerRequest::ListModules { start, count })
            .await?
        {
            WorkerResponse::Modules(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for module list: {other:?}"),
        }
    }

    pub async fn stack_trace(&self, id: &str, max_frames: u32) -> anyhow::Result<StackTrace> {
        if !(1..=256).contains(&max_frames) {
            bail!("invalid_argument: max_frames must be between 1 and 256");
        }
        match self
            .request(id, WorkerRequest::StackTrace { max_frames })
            .await?
        {
            WorkerResponse::Stack(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for stack trace: {other:?}"),
        }
    }

    pub async fn registers(&self, id: &str) -> anyhow::Result<RegisterList> {
        match self.request(id, WorkerRequest::Registers).await? {
            WorkerResponse::Registers(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for registers: {other:?}"),
        }
    }

    pub async fn evaluate(&self, id: &str, expression: &str) -> anyhow::Result<ExpressionValue> {
        validate_text("expression", expression, 4096)?;
        match self
            .request(
                id,
                WorkerRequest::Evaluate {
                    expression: expression.to_string(),
                },
            )
            .await?
        {
            WorkerResponse::Expression(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for expression: {other:?}"),
        }
    }

    pub async fn disassemble(
        &self,
        id: &str,
        address: u64,
        count: u32,
    ) -> anyhow::Result<Disassembly> {
        if !(1..=256).contains(&count) {
            bail!("invalid_argument: instruction count must be between 1 and 256");
        }
        match self
            .request(id, WorkerRequest::Disassemble { address, count })
            .await?
        {
            WorkerResponse::Disassembly(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for disassembly: {other:?}"),
        }
    }

    pub async fn symbol_from_address(
        &self,
        id: &str,
        address: u64,
    ) -> anyhow::Result<SymbolLookup> {
        match self
            .request(id, WorkerRequest::SymbolFromAddress { address })
            .await?
        {
            WorkerResponse::Symbol(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for symbol lookup: {other:?}"),
        }
    }

    pub async fn address_from_symbol(
        &self,
        id: &str,
        symbol: &str,
    ) -> anyhow::Result<SymbolLookup> {
        validate_text("symbol", symbol, 4096)?;
        match self
            .request(
                id,
                WorkerRequest::AddressFromSymbol {
                    symbol: symbol.to_string(),
                },
            )
            .await?
        {
            WorkerResponse::Symbol(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for symbol lookup: {other:?}"),
        }
    }

    pub async fn read_memory(
        &self,
        id: &str,
        address: u64,
        length: u32,
    ) -> anyhow::Result<MemoryRead> {
        if !(1..=4096).contains(&length) {
            bail!("invalid_argument: length must be between 1 and 4096 bytes");
        }
        match self
            .request(id, WorkerRequest::ReadMemory { address, length })
            .await?
        {
            WorkerResponse::Memory(memory) => Ok(memory),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response while reading memory: {other:?}"),
        }
    }

    pub async fn write_memory(
        &self,
        id: &str,
        address: u64,
        bytes: Vec<u8>,
    ) -> anyhow::Result<MemoryWrite> {
        if bytes.is_empty() || bytes.len() > 4096 {
            bail!("invalid_argument: write must contain between 1 and 4096 bytes");
        }
        match self
            .request(id, WorkerRequest::WriteMemory { address, bytes })
            .await?
        {
            WorkerResponse::MemoryWritten(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for memory write: {other:?}"),
        }
    }

    pub async fn get_symbol_path(&self, id: &str) -> anyhow::Result<SymbolPath> {
        match self.request(id, WorkerRequest::GetSymbolPath).await? {
            WorkerResponse::SymbolPath(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for symbol path: {other:?}"),
        }
    }

    pub async fn set_symbol_path(&self, id: &str, path: &str) -> anyhow::Result<SymbolPath> {
        validate_text("path", path, 32766)?;
        match self
            .request(
                id,
                WorkerRequest::SetSymbolPath {
                    path: path.to_string(),
                },
            )
            .await?
        {
            WorkerResponse::SymbolPath(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for symbol path: {other:?}"),
        }
    }

    pub async fn reload_symbols(
        &self,
        id: &str,
        module: Option<&str>,
    ) -> anyhow::Result<SymbolReload> {
        if let Some(module) = module {
            validate_text("module", module, 4096)?;
        }
        match self
            .request(
                id,
                WorkerRequest::ReloadSymbols {
                    module: module.map(str::to_string),
                },
            )
            .await?
        {
            WorkerResponse::SymbolsReloaded(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for symbol reload: {other:?}"),
        }
    }

    pub async fn list_breakpoints(&self, id: &str) -> anyhow::Result<BreakpointList> {
        match self.request(id, WorkerRequest::ListBreakpoints).await? {
            WorkerResponse::Breakpoints(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for breakpoints: {other:?}"),
        }
    }

    pub async fn set_breakpoint(
        &self,
        id: &str,
        expression: &str,
        one_shot: bool,
    ) -> anyhow::Result<BreakpointInfo> {
        validate_text("expression", expression, 4096)?;
        match self
            .request(
                id,
                WorkerRequest::SetBreakpoint {
                    expression: expression.to_string(),
                    one_shot,
                },
            )
            .await?
        {
            WorkerResponse::Breakpoint(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for breakpoint: {other:?}"),
        }
    }

    pub async fn remove_breakpoint(&self, id: &str, breakpoint_id: u32) -> anyhow::Result<u32> {
        match self
            .request(id, WorkerRequest::RemoveBreakpoint { id: breakpoint_id })
            .await?
        {
            WorkerResponse::BreakpointRemoved { id } => Ok(id),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response while removing breakpoint: {other:?}"),
        }
    }

    pub async fn execute(
        &self,
        id: &str,
        action: ExecutionAction,
        timeout_ms: u32,
    ) -> anyhow::Result<ExecutionResult> {
        if timeout_ms > 20_000 {
            bail!("invalid_argument: timeout_ms must be at most 20000");
        }
        match self
            .request(id, WorkerRequest::Execute { action, timeout_ms })
            .await?
        {
            WorkerResponse::Execution(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for execution: {other:?}"),
        }
    }

    pub async fn execute_command(
        &self,
        id: &str,
        command: &str,
        timeout_ms: Option<u32>,
    ) -> anyhow::Result<CommandResult> {
        validate_text("command", command, 4096)?;
        let timeout = command_timeout(timeout_ms)?;
        let request = WorkerRequest::ExecuteCommand {
            command: command.trim().to_string(),
        };
        let response = self.request_with_timeout(id, request, timeout).await;
        if let Err(error) = &response {
            if error.to_string().contains("DbgEng worker timed out") {
                self.abort_session(id).await;
                return Err(anyhow!(
                    "command_timeout: DbgEng did not finish within {} ms; the debugger session was closed to recover. Retry with a larger timeout_ms",
                    timeout.as_millis()
                ));
            }
        }
        match response? {
            WorkerResponse::CommandOutput(value) => Ok(value),
            WorkerResponse::Error { code, message } => bail!("{code}: {message}"),
            other => bail!("unexpected worker response for command: {other:?}"),
        }
    }

    pub async fn close(&self, id: &str) -> anyhow::Result<()> {
        let entry = self
            .sessions
            .write()
            .await
            .remove(id)
            .ok_or_else(|| anyhow!("stale_session: unknown session_id '{id}'"))?;
        debug_assert_eq!(entry.id, id);
        let mut worker = entry.worker.lock().await;
        match worker.request(&WorkerRequest::Close).await {
            Ok(WorkerResponse::Closed) => {}
            Ok(WorkerResponse::Error { code, message }) => bail!("{code}: {message}"),
            Ok(other) => bail!("unexpected worker response while closing: {other:?}"),
            Err(error) => {
                let _ = worker.child.start_kill();
                return Err(error);
            }
        }
        timeout(Duration::from_secs(5), worker.child.wait())
            .await
            .context("worker did not exit after closing")??;
        Ok(())
    }

    pub async fn list_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.sessions.read().await.keys().cloned().collect();
        ids.sort();
        ids
    }

    async fn request(&self, id: &str, request: WorkerRequest) -> anyhow::Result<WorkerResponse> {
        self.request_with_timeout(id, request, WORKER_TIMEOUT).await
    }

    async fn request_with_timeout(
        &self,
        id: &str,
        request: WorkerRequest,
        timeout_duration: Duration,
    ) -> anyhow::Result<WorkerResponse> {
        let entry = self
            .sessions
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("stale_session: unknown session_id '{id}'"))?;
        entry
            .worker
            .lock()
            .await
            .request_with_timeout(&request, timeout_duration)
            .await
    }

    async fn abort_session(&self, id: &str) {
        let Some(entry) = self.sessions.write().await.remove(id) else {
            return;
        };
        let mut worker = entry.worker.lock().await;
        let _ = worker.child.start_kill();
    }
}

impl WorkerConnection {
    async fn request(&mut self, request: &WorkerRequest) -> anyhow::Result<WorkerResponse> {
        self.request_with_timeout(request, WORKER_TIMEOUT).await
    }

    async fn request_with_timeout(
        &mut self,
        request: &WorkerRequest,
        timeout_duration: Duration,
    ) -> anyhow::Result<WorkerResponse> {
        let mut encoded = serde_json::to_vec(request).context("failed to encode worker request")?;
        encoded.push(b'\n');
        self.stdin
            .write_all(&encoded)
            .await
            .context("failed to send request to worker")?;
        self.stdin
            .flush()
            .await
            .context("failed to flush worker request")?;

        let mut line = String::new();
        let bytes = timeout(timeout_duration, self.stdout.read_line(&mut line))
            .await
            .context("DbgEng worker timed out")??;
        if bytes == 0 {
            bail!("DbgEng worker exited without a response");
        }
        serde_json::from_str(&line).context("worker returned invalid JSON")
    }
}

fn command_timeout(timeout_ms: Option<u32>) -> anyhow::Result<Duration> {
    let timeout = timeout_ms
        .map(|milliseconds| Duration::from_millis(u64::from(milliseconds)))
        .unwrap_or(DEFAULT_COMMAND_TIMEOUT);
    if timeout.is_zero() {
        bail!("invalid_argument: timeout_ms must be greater than zero");
    }
    if timeout > MAX_COMMAND_TIMEOUT {
        bail!(
            "invalid_argument: timeout_ms must be at most {}",
            MAX_COMMAND_TIMEOUT.as_millis()
        );
    }
    Ok(timeout)
}

fn validate_dump_path(supplied: &str) -> anyhow::Result<std::path::PathBuf> {
    if supplied.trim().is_empty() {
        bail!("invalid_argument: dump path must not be empty");
    }
    let path = Path::new(supplied);
    if !path.is_absolute() {
        bail!("invalid_argument: dump path must be absolute");
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "dmp" | "mdmp" | "hdmp") {
        bail!("invalid_argument: expected a .dmp, .mdmp, or .hdmp file");
    }
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("invalid_argument: cannot access dump '{}'", path.display()))?;
    if !canonical.is_file() {
        bail!("invalid_argument: dump path is not a file");
    }
    Ok(canonical)
}

fn validate_frontend_connection(supplied: &str) -> anyhow::Result<String> {
    let supplied = supplied.trim();
    let (transport, options) = supplied
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid_argument: expected an npipe or tcp connection string"))?;
    if transport.eq_ignore_ascii_case("tcp") {
        return validate_tcp_connection_options(options);
    }
    if !transport.eq_ignore_ascii_case("npipe") {
        bail!("invalid_argument: supported frontend transports are npipe and tcp");
    }

    let mut server = None;
    let mut pipe = None;
    for option in options.split(',') {
        let (key, value) = option
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid_argument: malformed npipe option '{option}'"))?;
        match key.trim().to_ascii_lowercase().as_str() {
            "server" if server.is_none() => server = Some(value.trim()),
            "pipe" if pipe.is_none() => pipe = Some(value.trim()),
            _ => bail!("invalid_argument: unsupported or duplicate npipe option '{key}'"),
        }
    }

    let server = server.ok_or_else(|| anyhow!("invalid_argument: npipe server is required"))?;
    let local_name = std::env::var("COMPUTERNAME").unwrap_or_default();
    if !(server == "."
        || server.eq_ignore_ascii_case("localhost")
        || (!local_name.is_empty() && server.eq_ignore_ascii_case(&local_name)))
    {
        bail!("invalid_argument: npipe connections must target this computer");
    }
    let pipe = pipe.ok_or_else(|| anyhow!("invalid_argument: npipe pipe is required"))?;
    if pipe.is_empty()
        || pipe.len() > 128
        || !pipe
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
    {
        bail!(
            "invalid_argument: pipe must be 1-128 ASCII letters, digits, dots, hyphens, or underscores"
        );
    }

    Ok(format!("npipe:server={server},pipe={pipe}"))
}

fn build_tcp_connection(host: &str, port: u16, password: Option<&str>) -> anyhow::Result<String> {
    validate_tcp_host(host)?;
    if port == 0 {
        bail!("invalid_argument: port must be between 1 and 65535");
    }
    validate_tcp_password(password)?;
    Ok(format!(
        "tcp:server={},port={}{}",
        host.trim(),
        port,
        password.map_or_else(String::new, |value| format!(",password={value}"))
    ))
}

fn validate_tcp_connection_options(options: &str) -> anyhow::Result<String> {
    let mut host = None;
    let mut port = None;
    let mut password = None;
    for option in options.split(',') {
        let (key, value) = option
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid_argument: malformed tcp option '{option}'"))?;
        match key.trim().to_ascii_lowercase().as_str() {
            "server" if host.is_none() => host = Some(value.trim()),
            "port" if port.is_none() => port = Some(value.trim()),
            "password" if password.is_none() => password = Some(value.trim()),
            _ => bail!("invalid_argument: unsupported or duplicate tcp option '{key}'"),
        }
    }
    let host = host.ok_or_else(|| anyhow!("invalid_argument: tcp server is required"))?;
    let port_text = port.ok_or_else(|| anyhow!("invalid_argument: tcp port is required"))?;
    let port = port_text
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid_argument: tcp port must be between 1 and 65535"))?;
    build_tcp_connection(host, port, password)
}

fn validate_tcp_host(host: &str) -> anyhow::Result<()> {
    let host = host.trim();
    if host.is_empty() || host.len() > 255 {
        bail!("invalid_argument: host must be 1-255 characters");
    }
    if host.chars().any(|character| {
        character.is_ascii_whitespace()
            || character.is_ascii_control()
            || matches!(character, ',' | '=' | '\0')
    }) {
        bail!("invalid_argument: host contains an unsupported character");
    }
    Ok(())
}

fn validate_tcp_password(password: Option<&str>) -> anyhow::Result<()> {
    let Some(password) = password else {
        return Ok(());
    };
    if password.is_empty()
        || password.len() > 12
        || !password
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        bail!("invalid_argument: password must be 1-12 ASCII letters or digits");
    }
    Ok(())
}

fn validate_pid(pid: u32) -> anyhow::Result<()> {
    if pid == 0 {
        bail!("invalid_argument: pid must be greater than zero");
    }
    if pid == std::process::id() {
        bail!("invalid_argument: the MCP server cannot debug itself");
    }
    Ok(())
}

fn validate_page(label: &str, count: u32) -> anyhow::Result<()> {
    if !(1..=256).contains(&count) {
        bail!("invalid_argument: {label} count must be between 1 and 256");
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: usize) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        bail!("invalid_argument: {label} must not be empty");
    }
    if value.encode_utf16().count() > maximum {
        bail!("invalid_argument: {label} is too long");
    }
    if value.contains('\0') {
        bail!("invalid_argument: {label} must not contain a NUL character");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_path_must_be_absolute() {
        let error = validate_dump_path("relative.dmp").unwrap_err();
        assert!(error.to_string().contains("must be absolute"));
    }

    #[test]
    fn dump_path_requires_known_extension() {
        let error = validate_dump_path("C:\\temp\\dump.txt").unwrap_err();
        assert!(error.to_string().contains(".dmp"));
    }

    #[test]
    fn frontend_connection_accepts_local_named_pipe() {
        let value = validate_frontend_connection("npipe:server=localhost,pipe=windbg_mcp-1")
            .expect("local named pipe should be valid");
        assert_eq!(value, "npipe:server=localhost,pipe=windbg_mcp-1");
    }

    #[test]
    fn frontend_connection_accepts_tcp_transport() {
        let value = validate_frontend_connection("tcp:server=10.0.0.5,port=5005").unwrap();
        assert_eq!(value, "tcp:server=10.0.0.5,port=5005");
    }

    #[test]
    fn tcp_connection_rejects_injection_characters() {
        let error = build_tcp_connection("10.0.0.5,evil", 5005, None).unwrap_err();
        assert!(error.to_string().contains("unsupported character"));
    }

    #[test]
    fn tcp_connection_accepts_password() {
        let value = build_tcp_connection("debug-host", 5005, Some("secret123")).unwrap();
        assert_eq!(value, "tcp:server=debug-host,port=5005,password=secret123");
    }

    #[test]
    fn tcp_connection_rejects_invalid_password() {
        let error = build_tcp_connection("debug-host", 5005, Some("not valid!")).unwrap_err();
        assert!(error.to_string().contains("password must be"));
    }

    #[test]
    fn frontend_connection_rejects_remote_host() {
        let error = validate_frontend_connection("npipe:server=remote,pipe=debug").unwrap_err();
        assert!(error.to_string().contains("this computer"));
    }

    #[test]
    fn command_timeout_defaults_to_five_minutes() {
        assert_eq!(command_timeout(None).unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn command_timeout_rejects_zero_and_values_over_thirty_minutes() {
        assert!(
            command_timeout(Some(0))
                .unwrap_err()
                .to_string()
                .contains("greater than zero")
        );
        assert!(
            command_timeout(Some(1_800_001))
                .unwrap_err()
                .to_string()
                .contains("at most 1800000")
        );
    }
}
