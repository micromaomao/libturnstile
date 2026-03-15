use log::{error, info};
use std::env;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use clap::Parser;
use libturnstile::{AccessRequestError, TurnstileTracer};

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

	/// Program to trace and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

#[derive(Debug)]
pub struct Context {
	tracer: TurnstileTracer,
	pidfd: OnceLock<libc::c_int>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut log_builder = env_logger::builder();
	if env::var_os("RUST_LOG").is_none() {
		log_builder.filter_level(log::LevelFilter::Info);
	} else {
		log_builder.parse_default_env();
	}
	log_builder.init();

	let cli = Cli::parse();

	let mut output: Box<dyn Write + Send> = match &cli.output {
		Some(path) => Box::new(std::fs::File::create(path)?),
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
						}
					}
					let pid = ctx.sreq().pid;
					let comm = std::fs::read(format!("/proc/{}/comm", pid))
						.map(|r| String::from_utf8_lossy(&r).trim().to_string())
						.unwrap_or_else(|_| String::from("???"));
					if let Err(e) =
						writeln!(output, "{}[{}] {}", comm, pid, access_request.operation())
					{
						error!("error writing to log: {}", e);
					}
					if let Err(e) = ctx.send_continue() {
						error!("error sending continue response: {}", e);
					}
				}
				Ok(None) => {}
				Err(e) => {
					if let Some(&pidfd) = context.pidfd.get() {
						let status_fd = unsafe {
							libc::openat(
								pidfd,
								c"status".as_ptr(),
								libc::O_RDONLY | libc::O_CLOEXEC,
							)
						};
						if status_fd < 0 {
							break;
						}
						let mut status_file = unsafe { std::fs::File::from_raw_fd(status_fd) };
						let mut status_contents = String::new();
						if let Err(_) =
							std::io::Read::read_to_string(&mut status_file, &mut status_contents)
						{
							break;
						}
						if status_contents.contains("State:\tZ") {
							break;
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
	match child_result {
		Ok(mut child) => {
			let pidfd = unsafe {
				libc::open(
					format!("/proc/{}\0", child.id()).as_ptr() as *const libc::c_char,
					libc::O_RDONLY | libc::O_CLOEXEC,
				)
			};
			if pidfd < 0 {
				error!("error opening pidfd: {}", std::io::Error::last_os_error());
				_ = child.kill();
				std::process::exit(1);
			}
			context.pidfd.set(pidfd).unwrap();
			let status = child.wait()?;
			if status.success() {
				info!("child process exited with status {}", status);
			} else {
				error!("child process exited with status {}", status);
			}
			std::process::exit(status.code().unwrap_or(1));
		}
		Err(e) => {
			error!("error spawning child: {}", e);
			std::process::exit(1);
		}
	}
}
