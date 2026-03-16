use log::{error, info};
use std::env;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use clap::Parser;
use libturnstile::{AccessRequestError, Operation, TurnstileTracer};

use crate::common::{ProcPidFd, handle_child_result};

mod common;

/// Trace file operations of a program using libturnstile
#[derive(Parser)]
#[command(name = "fstrace")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Write output to a file instead of stderr
	#[arg(short = 'o', value_name = "FILE")]
	output: Option<String>,

	/// Add timestamps to each output line
	#[arg(short = 't', long = "timestamps")]
	timestamps: bool,

	/// Print a simplified "rwx" representation of what accesses are
	/// required
	#[arg(long = "rwx")]
	rwx: bool,

	/// Program to trace and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

#[derive(Debug)]
pub struct Context {
	tracer: TurnstileTracer,
	pidfd: OnceLock<ProcPidFd>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	common::init_logger();

	let cli = Cli::parse();

	let mut output: Box<dyn Write + Send> = match &cli.output {
		Some(path) => Box::new(
			std::fs::File::options()
				.create(true)
				.append(true)
				.open(path)?,
		),
		None => Box::new(std::io::stderr()),
	};

	let context = Arc::new(Context {
		tracer: TurnstileTracer::new()?,
		pidfd: OnceLock::new(),
	});

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	// spawn blocks until execve succeeds, but execve is intercepted by
	// seccomp-unotify, so we must be processing notifications via
	// yield_request before calling spawn.
	let context_for_thread = Arc::clone(&context);
	std::thread::spawn(move || {
		let context = context_for_thread;
		loop {
			match context.tracer.yield_request() {
				Ok(Some((access_request, mut ctx))) => {
					if cli.timestamps {
						let now = SystemTime::now()
							.duration_since(SystemTime::UNIX_EPOCH)
							.unwrap_or_default();
						if let Err(e) =
							write!(output, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())
						{
							error!("error writing to log: {}", e);
							return;
						}
					}
					let pid = ctx.sreq().pid;
					let comm = std::fs::read(format!("/proc/{}/comm", pid))
						.map(|r| r.trim_ascii().escape_ascii().to_string())
						.unwrap_or_else(|_| String::from("???"));
					if let Err(e) = match access_request.operation() {
						Operation::FsOperation(fs_op) if cli.rwx => {
							let rwxp = fs_op.as_rwx_permissions();
							match &rwxp[..] {
								[p] => writeln!(output, "{}[{}] {}", comm, pid, p),
								[p1, p2] => {
									writeln!(output, "{}[{}] {}; {}", comm, pid, p1, p2)
								}
								_ => panic!(
									"unexpected number of permissions returned by as_rwx_permissions()"
								),
							}
						}
						Operation::FsOperation(fs_op) => {
							writeln!(output, "{}[{}] {}", comm, pid, fs_op)
						}
						_ => Ok(()),
					} {
						error!("error writing to log: {}", e);
						return;
					}
					if let Err(e) = ctx.send_continue() {
						error!("error sending continue response: {}", e);
					}
				}
				Ok(None) => {}
				Err(e) => {
					if let Some(pidfd) = context.pidfd.get() {
						match pidfd.is_alive() {
							Ok(alive) => {
								if !alive {
									break;
								}
							}
							Err(e) => {
								error!("error checking if child process is alive: {}", e);
							}
						}
					}
					if let AccessRequestError::InvalidSyscallData(_) = e {
						continue;
					}
					error!("yield_request: {}", e);
				}
			}
		}
	});

	let child_result = context.tracer.run_command(&mut cmd);
	handle_child_result(child_result, &context.pidfd)
}
