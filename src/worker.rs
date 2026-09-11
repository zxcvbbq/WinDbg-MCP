use std::{
    io::{self, BufRead, BufReader, BufWriter, Write},
    os::windows::io::AsRawHandle,
    path::Path,
};

use anyhow::Context;
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};

use crate::{
    dbgeng::EngineSession,
    ipc::{WorkerRequest, WorkerResponse},
};

pub fn run() -> anyhow::Result<()> {
    prevent_debuggee_stdio_inheritance();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let mut engine: Option<EngineSession> = None;
    let mut line = String::new();

    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .context("failed to read worker request")?
            == 0
        {
            break;
        }

        let request = match serde_json::from_str::<WorkerRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut writer,
                    &WorkerResponse::Error {
                        code: "invalid_request".to_string(),
                        message: error.to_string(),
                    },
                )?;
                continue;
            }
        };

        let response = match request {
            WorkerRequest::OpenDump { .. }
            | WorkerRequest::ConnectFrontend { .. }
            | WorkerRequest::AttachRemoteProcess { .. }
            | WorkerRequest::LaunchRemoteProcess { .. }
            | WorkerRequest::AttachProcess { .. }
            | WorkerRequest::LaunchProcess { .. }
                if engine.is_some() =>
            {
                WorkerResponse::Error {
                    code: "session_already_open".to_string(),
                    message: "this worker already owns a debugger session".to_string(),
                }
            }
            WorkerRequest::OpenDump { path } => match EngineSession::open_dump(Path::new(&path)) {
                Ok(session) => match session.summary() {
                    Ok(summary) => {
                        engine = Some(session);
                        WorkerResponse::Opened(summary)
                    }
                    Err(error) => WorkerResponse::Error {
                        code: "engine_query_failed".to_string(),
                        message: error.to_string(),
                    },
                },
                Err(error) => WorkerResponse::Error {
                    code: "open_dump_failed".to_string(),
                    message: error.to_string(),
                },
            },
            WorkerRequest::ConnectFrontend { connection } => {
                match EngineSession::connect_frontend(&connection) {
                    Ok(session) => match session.summary() {
                        Ok(summary) => {
                            engine = Some(session);
                            WorkerResponse::Opened(summary)
                        }
                        Err(error) => WorkerResponse::Error {
                            code: "engine_query_failed".to_string(),
                            message: error.to_string(),
                        },
                    },
                    Err(error) => WorkerResponse::Error {
                        code: "connect_frontend_failed".to_string(),
                        message: error.to_string(),
                    },
                }
            }
            WorkerRequest::AttachProcess { pid, noninvasive } => open_engine(
                &mut engine,
                EngineSession::attach_process(pid, noninvasive),
                "attach_process_failed",
            ),
            WorkerRequest::AttachRemoteProcess {
                connection,
                pid,
                noninvasive,
            } => open_engine(
                &mut engine,
                EngineSession::attach_remote_process(&connection, pid, noninvasive),
                "attach_remote_process_failed",
            ),
            WorkerRequest::LaunchProcess {
                command_line,
                terminate_on_close,
            } => open_engine(
                &mut engine,
                EngineSession::launch_process(&command_line, terminate_on_close),
                "launch_process_failed",
            ),
            WorkerRequest::LaunchRemoteProcess {
                connection,
                command_line,
                terminate_on_close,
            } => open_engine(
                &mut engine,
                EngineSession::launch_remote_process(
                    &connection,
                    &command_line,
                    terminate_on_close,
                ),
                "launch_remote_process_failed",
            ),
            WorkerRequest::Status => match engine.as_ref() {
                Some(session) => match session.summary() {
                    Ok(summary) => WorkerResponse::Summary(summary),
                    Err(error) => WorkerResponse::Error {
                        code: "engine_query_failed".to_string(),
                        message: error.to_string(),
                    },
                },
                None => WorkerResponse::Error {
                    code: "no_session".to_string(),
                    message: "the worker has no open debugger session".to_string(),
                },
            },
            WorkerRequest::ReadMemory { address, length } => match engine.as_ref() {
                Some(session) => match session.read_memory(address, length) {
                    Ok(memory) => WorkerResponse::Memory(memory),
                    Err(error) => WorkerResponse::Error {
                        code: "read_memory_failed".to_string(),
                        message: error.to_string(),
                    },
                },
                None => WorkerResponse::Error {
                    code: "no_session".to_string(),
                    message: "the worker has no open debugger session".to_string(),
                },
            },
            WorkerRequest::ListProcesses => with_engine(
                engine.as_ref(),
                "list_processes_failed",
                EngineSession::list_processes,
                WorkerResponse::Processes,
            ),
            WorkerRequest::ListThreads { start, count } => with_engine(
                engine.as_ref(),
                "list_threads_failed",
                |session| session.list_threads(start, count),
                WorkerResponse::Threads,
            ),
            WorkerRequest::SelectThread { engine_id } => with_engine(
                engine.as_ref(),
                "select_thread_failed",
                |session| session.select_thread(engine_id),
                WorkerResponse::Context,
            ),
            WorkerRequest::ListModules { start, count } => with_engine(
                engine.as_ref(),
                "list_modules_failed",
                |session| session.list_modules(start, count),
                WorkerResponse::Modules,
            ),
            WorkerRequest::StackTrace { max_frames } => with_engine(
                engine.as_ref(),
                "stack_trace_failed",
                |session| session.stack_trace(max_frames),
                WorkerResponse::Stack,
            ),
            WorkerRequest::Registers => with_engine(
                engine.as_ref(),
                "registers_failed",
                EngineSession::registers,
                WorkerResponse::Registers,
            ),
            WorkerRequest::Evaluate { expression } => with_engine(
                engine.as_ref(),
                "evaluate_failed",
                |session| session.evaluate(&expression),
                WorkerResponse::Expression,
            ),
            WorkerRequest::Disassemble { address, count } => with_engine(
                engine.as_ref(),
                "disassemble_failed",
                |session| session.disassemble(address, count),
                WorkerResponse::Disassembly,
            ),
            WorkerRequest::SymbolFromAddress { address } => with_engine(
                engine.as_ref(),
                "symbol_lookup_failed",
                |session| session.symbol_from_address(address),
                WorkerResponse::Symbol,
            ),
            WorkerRequest::AddressFromSymbol { symbol } => with_engine(
                engine.as_ref(),
                "symbol_lookup_failed",
                |session| session.address_from_symbol(&symbol),
                WorkerResponse::Symbol,
            ),
            WorkerRequest::WriteMemory { address, bytes } => with_engine(
                engine.as_ref(),
                "write_memory_failed",
                |session| session.write_memory(address, &bytes),
                WorkerResponse::MemoryWritten,
            ),
            WorkerRequest::GetSymbolPath => with_engine(
                engine.as_ref(),
                "symbol_path_failed",
                EngineSession::get_symbol_path,
                WorkerResponse::SymbolPath,
            ),
            WorkerRequest::SetSymbolPath { path } => with_engine(
                engine.as_ref(),
                "symbol_path_failed",
                |session| session.set_symbol_path(&path),
                WorkerResponse::SymbolPath,
            ),
            WorkerRequest::ReloadSymbols { module } => with_engine(
                engine.as_ref(),
                "reload_symbols_failed",
                |session| session.reload_symbols(module.as_deref()),
                WorkerResponse::SymbolsReloaded,
            ),
            WorkerRequest::ListBreakpoints => with_engine(
                engine.as_ref(),
                "list_breakpoints_failed",
                EngineSession::list_breakpoints,
                WorkerResponse::Breakpoints,
            ),
            WorkerRequest::SetBreakpoint {
                expression,
                one_shot,
            } => with_engine(
                engine.as_ref(),
                "set_breakpoint_failed",
                |session| session.set_breakpoint(&expression, one_shot),
                WorkerResponse::Breakpoint,
            ),
            WorkerRequest::RemoveBreakpoint { id } => with_engine(
                engine.as_ref(),
                "remove_breakpoint_failed",
                |session| session.remove_breakpoint(id),
                |id| WorkerResponse::BreakpointRemoved { id },
            ),
            WorkerRequest::Execute { action, timeout_ms } => with_engine(
                engine.as_ref(),
                "execution_failed",
                |session| session.execute(action, timeout_ms),
                WorkerResponse::Execution,
            ),
            WorkerRequest::ExecuteCommand { command } => with_engine(
                engine.as_ref(),
                "command_failed",
                |session| session.execute_command(&command),
                WorkerResponse::CommandOutput,
            ),
            WorkerRequest::Close => {
                drop(engine.take());
                write_response(&mut writer, &WorkerResponse::Closed)?;
                break;
            }
        };

        write_response(&mut writer, &response)?;
    }

    Ok(())
}

fn prevent_debuggee_stdio_inheritance() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    for raw in [
        stdin.as_raw_handle(),
        stdout.as_raw_handle(),
        stderr.as_raw_handle(),
    ] {
        let handle = HANDLE(raw);
        let _ = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) };
    }
}

fn open_engine(
    slot: &mut Option<EngineSession>,
    result: Result<EngineSession, crate::dbgeng::EngineError>,
    code: &str,
) -> WorkerResponse {
    match result {
        Ok(session) => match session.summary() {
            Ok(summary) => {
                *slot = Some(session);
                WorkerResponse::Opened(summary)
            }
            Err(error) => WorkerResponse::Error {
                code: "engine_query_failed".to_string(),
                message: error.to_string(),
            },
        },
        Err(error) => WorkerResponse::Error {
            code: code.to_string(),
            message: error.to_string(),
        },
    }
}

fn with_engine<T>(
    engine: Option<&EngineSession>,
    code: &str,
    operation: impl FnOnce(&EngineSession) -> Result<T, crate::dbgeng::EngineError>,
    response: impl FnOnce(T) -> WorkerResponse,
) -> WorkerResponse {
    let Some(engine) = engine else {
        return WorkerResponse::Error {
            code: "no_session".to_string(),
            message: "the worker has no open debugger session".to_string(),
        };
    };
    match operation(engine) {
        Ok(value) => response(value),
        Err(error) => WorkerResponse::Error {
            code: code.to_string(),
            message: error.to_string(),
        },
    }
}

fn write_response(writer: &mut impl Write, response: &WorkerResponse) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, response).context("failed to encode worker response")?;
    writer
        .write_all(b"\n")
        .context("failed to terminate worker response")?;
    writer.flush().context("failed to flush worker response")
}
