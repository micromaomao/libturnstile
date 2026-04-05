use clap::Parser;
use libturnstile::access::fs::{ForeignFd, FsOperation, FsTarget, RwxPermission};
use libturnstile::{AccessRequestError, TurnstileTracer, access::Operation};
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use std::{env, io};

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

	/// Only print attempted writes
	#[arg(short = 'w', long = "only-writes")]
	only_writes: bool,

	/// Exclude paths with any of these prefixes.  Relative paths are resolved to their absolute paths.
	#[arg(short = 'e', long = "exclude", value_name = "PREFIX")]
	exclude: Vec<OsString>,

	/// Exclude paths with any of these prefixes if the request is read-only.  Relative paths are resolved to their absolute paths.
	#[arg(short = 'E', long = "exclude-ro", value_name = "PREFIX")]
	exclude_ro: Vec<OsString>,

	/// Include only paths with any of these prefixes.  Relative paths are resolved to their absolute paths.
	#[arg(short = 'i', long = "include", value_name = "PREFIX")]
	include: Vec<OsString>,

	/// Exclude read requests under any paths that are in PATH
	#[arg(long = "exclude-read-on-env-path")]
	exclude_read_on_env_path: bool,

	/// Exclude readlink requests for any parents of any excluded paths (i.e. what realpath does)
	#[arg(long = "exclude-readlink-for-parents-of-excluded-paths")]
	exclude_readlink_for_parents_of_excluded_paths: bool,

	/// Only print the first access for each file
	#[arg(short = 'u', long = "unique")]
	unique: bool,

	/// Program to trace and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

impl Cli {
	fn need_path(&self, request_is_ro: bool) -> bool {
		if self.unique {
			return true;
		}
		if !self.exclude.is_empty() || !self.include.is_empty() {
			return true;
		}
		if request_is_ro && !self.exclude_ro.is_empty() {
			return true;
		}
		false
	}
}

fn path_has_prefix(path: &OsString, prefix: &OsString) -> bool {
	path.as_encoded_bytes()
		.starts_with(prefix.as_encoded_bytes())
}

fn filter(
	cli: &Cli,
	fs_op: &FsOperation,
	rwx: &RwxPermission,
	unique_hs: &mut HashSet<OsString>,
) -> io::Result<bool> {
	if cli.only_writes && !rwx.write {
		return Ok(false);
	}
	if cli.need_path(!rwx.write) {
		let rough_target_path = match rwx.target.realpath() {
			Ok(p) => p,
			Err(e) => {
				let dfd = rwx.target.dfd();
				let mut p = match dfd.readlink() {
					Err(e) => {
						error!("Child process passed an invalid file descriptor: {}", e);
						return Ok(true);
					}
					Ok(p) => p,
				}
				.into_encoded_bytes();
				if p.last().copied() != Some(b'/') && !rwx.target.path().is_empty() {
					p.push(b'/');
				}
				p.extend_from_slice(rwx.target.path().to_bytes());
				OsString::from_vec(p)
			}
		};
		if cli
			.exclude
			.iter()
			.any(|prefix| path_has_prefix(&rough_target_path, prefix))
		{
			return Ok(false);
		}
		if rwx.write
			&& cli
				.exclude_ro
				.iter()
				.any(|prefix| path_has_prefix(&rough_target_path, prefix))
		{
			return Ok(false);
		}
		if !cli.include.is_empty()
			&& !cli
				.include
				.iter()
				.any(|prefix| path_has_prefix(&rough_target_path, prefix))
		{
			return Ok(false);
		}
		if let FsOperation::FsReadlink(_) = fs_op
			&& cli.exclude_readlink_for_parents_of_excluded_paths
		{
			for excluded_path in cli.exclude.iter().chain(cli.exclude_ro.iter()) {
				if path_has_prefix(excluded_path, &rough_target_path) {
					return Ok(false);
				}
			}
		}
		if cli.unique {
			return Ok(unique_hs.insert(rough_target_path));
		}
	}
	Ok(true)
}

fn turn_into_absolute_paths(paths: &mut [OsString]) -> io::Result<()> {
	for path in paths {
		match std::fs::canonicalize(&path) {
			Ok(realpath) => *path = realpath.into_os_string(),
			Err(e) => {
				if path.as_encoded_bytes().starts_with(b"/") {
					warn!("Error opening path {:?}: {}. Using as-is.", path, e);
				} else {
					error!("Error opening path {:?}: {}", path, e);
					return Err(e);
				}
			}
		}
	}
	Ok(())
}

#[derive(Debug)]
pub struct Context {
	tracer: TurnstileTracer,
	pidfd: OnceLock<ProcPidFd>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	common::init_logger();

	let mut cli = Cli::parse();

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

	turn_into_absolute_paths(&mut cli.exclude)?;
	turn_into_absolute_paths(&mut cli.include)?;

	if cli.exclude_read_on_env_path {
		if let Some(env_path) = env::var_os("PATH") {
			for p in env_path.as_encoded_bytes().split(|&b| b == b':') {
				let p = OsStr::from_bytes(p);
				if !p.is_empty() {
					let rp = std::fs::canonicalize(p).map(|s| s.into_os_string());
					let rp = rp.unwrap_or_else(|e| {
						warn!("Error opening path {:?} from PATH: {}. Using as-is.", p, e);
						p.to_owned()
					});
					cli.exclude.push(rp);
				}
			}
		} else {
			warn!(
				"Environment variable PATH is not set, so --exclude-read-on-env-path has no effect"
			);
		}
	}

	let mut cmd = Command::new(program);
	cmd.args(args);

	// spawn blocks until execve succeeds, but execve is intercepted by
	// seccomp-unotify, so we must be processing notifications via
	// yield_request before calling spawn.
	let context_for_thread = Arc::clone(&context);
	std::thread::spawn(move || {
		let context = context_for_thread;
		let mut unique_hs = HashSet::new();
		loop {
			match context.tracer.yield_request() {
				Ok(Some((access_request, mut ctx))) => {
					let fs_op = match access_request.operation() {
						Operation::FsOperation(fs_op) => fs_op,
						_ => continue,
					};
					let rwxp = fs_op.as_rwx_permissions();
					let mut any_true = false;
					for f in rwxp.iter() {
						match filter(&cli, fs_op, f, &mut unique_hs) {
							Ok(true) => {
								any_true = true;
								break;
							}
							Ok(false) => {}
							Err(e) => {
								error!("Error evaluating filter on access request: {}", e);
							}
						}
					}
					if !any_true {
						if let Err(e) = ctx.send_continue() {
							error!("error sending continue response: {}", e);
						}
						continue;
					}
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
					let write_res = if cli.rwx {
						match &rwxp[..] {
							[p] => writeln!(output, "{}[{}] {}", comm, pid, p),
							[p1, p2] => {
								writeln!(output, "{}[{}] {}; {}", comm, pid, p1, p2)
							}
							_ => panic!(
								"unexpected number of permissions returned by as_rwx_permissions()"
							),
						}
					} else {
						writeln!(output, "{}[{}] {}", comm, pid, fs_op)
					};
					if let Err(e) = write_res {
						error!("error writing to log: {}", e);
						return;
					}
					if let Err(e) = ctx.send_continue() {
						error!("error sending continue response: {}", e);
					}
				}
				Ok(None) => {}
				Err(e) => {
					std::thread::sleep(Duration::from_millis(20));
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
