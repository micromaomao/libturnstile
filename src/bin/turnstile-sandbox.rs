use std::{
	env,
	ffi::{CStr, CString, OsStr, OsString},
	fmt::write,
	io::{self, Write},
	os::{
		fd::AsRawFd,
		unix::{ffi::OsStrExt, process::CommandExt},
	},
	path::PathBuf,
	process::{Command, ExitStatus},
	sync::{Arc, Mutex, OnceLock, atomic::AtomicBool},
	thread::{self, sleep},
	time::Duration,
};

use clap::Parser;
use libturnstile::{
	AccessRequestError, BindMountSandbox, ManagedBindMountSandbox, ManagedMountPoint,
	MountAttributes, TurnstileTracer,
	access::{
		Operation,
		fs::{FsOperation, RwxPermission},
	},
	fstree::FsTree,
};
use log::{debug, error, info};

use crate::common::{ProcPidFd, handle_child_result};

mod common;

/// A simple interactive sandbox using libturnstile
#[derive(Parser)]
#[command(name = "turnstile-sandbox")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Block the sandboxed process from creating more unprivileged user
	/// namespaces.
	#[arg(long = "block-nested-userns")]
	block_nested_userns: bool,

	/// Configuration for this sandbox.  Changes to this file will be
	/// live-reloaded.
	#[arg(required = true)]
	config: PathBuf,

	/// If set, the sandbox will log denials but always allow the
	/// operation to continue.
	#[arg(long = "permissive")]
	permissive: bool,

	/// Program to run and its arguments
	#[arg(required = true)]
	command: Vec<OsString>,
}

#[derive(Debug, Default)]
struct DenialLogNode {
	need_write: bool,
	need_exec: bool,
}

#[derive(Debug)]
struct Context {
	/// The sandbox used for running the target command.
	sandbox: ManagedBindMountSandbox,
	/// We resolve currently not-allowed paths in a separate sandbox that
	/// will have / mounted to /, except where a host path is mounted to a
	/// different location within the sandbox.
	path_res_sandbox: ManagedBindMountSandbox,
	tracer: TurnstileTracer,
	pidfd: OnceLock<ProcPidFd>,
	should_exit: AtomicBool,
	permissive: bool,
}

fn tracing_thread(context: &'static Context) {
	if let Err(e) = context.tracer.receive_notify_fd() {
		error!("error receiving notify fd: {}", e);
		std::process::exit(1);
	}
	let mut denials = FsTree::<DenialLogNode>::new();
	let resolve_sandbox_root = match context.path_res_sandbox.root_in_sandbox() {
		Ok(fd) => fd,
		Err(e) => {
			error!("error getting root in path resolution sandbox: {}", e);
			std::process::exit(1);
		}
	};
	loop {
		if context
			.should_exit
			.load(std::sync::atomic::Ordering::Relaxed)
		{
			break;
		}
		match context.tracer.yield_request() {
			Ok(Some((request, mut req_ctx))) => {
				debug!("got request: {:?}", request);
				let mut send_eperm = false;
				match request.operation() {
					Operation::FsOperation(fsop) => {
						let rwxps = fsop.as_rwx_permissions();
						if req_ctx.still_valid().ok() != Some(true) {
							debug!("request is no longer valid");
							continue;
						}
						for rwxp in rwxps {
							macro_rules! check_req_valid {
								() => {
									if req_ctx.still_valid().ok() != Some(true) {
										debug!("request is no longer valid");
										break;
									}
								};
							}
							let t_local =
								match rwxp.target.in_root(resolve_sandbox_root.as_raw_fd()) {
									Ok(t) => t,
									Err(e) => {
										check_req_valid!();
										error!(
											"error reopening target dfd in real root for {}: {}",
											rwxp, e
										);
										break;
									}
								};
							let target_fd = if rwxp.is_dir_op {
								t_local.open_target_dir().map(|x| x.0)
							} else {
								t_local.open_target()
							};
							check_req_valid!();
							if let Err(e) = target_fd {
								match e.kind() {
									io::ErrorKind::NotFound => {
										debug!("target not found for {}: {}", rwxp, e);
									}
									io::ErrorKind::PermissionDenied => {
										debug!(
											"permission denied opening target for {}: {}",
											rwxp, e
										);
									}
									_ => {
										error!(
											"error opening target in real root for {}: {}",
											rwxp, e
										);
									}
								}
								break;
							}
							let abspath = match target_fd.unwrap().readlink() {
								Ok(path) => {
									let mut bytes = path.into_encoded_bytes();
									bytes.push(b'\0');
									CString::from_vec_with_nul(bytes).unwrap()
								}
								Err(e) => {
									check_req_valid!();
									error!("error reading link for {}: {}", rwxp, e);
									break;
								}
							};
							match context
								.sandbox
								.check_covered(&abspath, rwxp.write, rwxp.exec)
							{
								Ok((true, _)) => {}
								Ok((false, mut existing_mnt)) => {
									check_req_valid!();
									info!(
										"{}[{}] need fs permission {}{}{} on {}",
										req_ctx
											.comm()
											.unwrap_or_else(|_| OsString::from("???"))
											.to_string_lossy(),
										req_ctx.pid(),
										if rwxp.read { "r" } else { "-" },
										if rwxp.write { "w" } else { "-" },
										if rwxp.exec { "x" } else { "-" },
										t_local,
									);
									let d = denials.get_mut_or_insert(
										OsStr::from_bytes(abspath.as_bytes()),
										DenialLogNode::default,
									);
									d.need_write |= rwxp.write;
									d.need_exec |= rwxp.exec;
									send_eperm = true;
									if context.permissive {
										send_eperm = false;
										if abspath.as_bytes() == b"/" {
											// TODO
											debug!("skipping mount update on /");
											break;
										}
										if let Some(mp) = &existing_mnt
											&& mp.host_path != abspath
										{
											existing_mnt = None;
										}
										let mut mp =
											existing_mnt.unwrap_or_else(|| ManagedMountPoint {
												host_path: abspath.clone(),
												attrs: MountAttributes {
													readonly: true,
													noexec: true,
												},
											});
										if rwxp.write {
											mp.attrs.readonly = false;
										}
										if rwxp.exec {
											mp.attrs.noexec = false;
										}
										match context.sandbox.add_or_update_mount(
											OsStr::from_bytes(abspath.as_bytes()),
											mp,
										) {
											Ok(()) => {}
											Err(e) => {
												error!(
													"error updating mount for {:?}: {}",
													abspath, e
												);
											}
										}
									}
								}
								Err(e) => {
									check_req_valid!();
									error!("error checking if {} is covered: {}", rwxp, e);
								}
							}
						}
					}
					_ => {}
				}
				if send_eperm {
					req_ctx.send_error(-libc::EPERM).unwrap_or_else(|e| {
						if req_ctx.still_valid().ok() == Some(true) {
							error!("error sending EPERM: {}", e);
						} else {
							debug!("request is no longer valid");
						}
					});
				} else {
					req_ctx.send_continue().unwrap_or_else(|e| {
						if req_ctx.still_valid().ok() == Some(true) {
							error!("error continuing request: {}", e);
						} else {
							debug!("request is no longer valid");
						}
					});
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
	if !denials.is_empty() {
		let mut stdout = std::io::stdout().lock();
		write!(stdout, "Denials:\n").unwrap();
		denials.walk_top_down(|path, val| {
			write!(
				stdout,
				"  r{}{} {:?}\n",
				if val.need_write { "w" } else { "-" },
				if val.need_exec { "x" } else { "-" },
				path
			)
			.unwrap();
		});
		stdout.flush().unwrap();
	}
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	common::init_logger();

	let cli = Cli::parse();

	let sandbox = ManagedBindMountSandbox::new(cli.block_nested_userns)?;
	let path_res_sandbox = ManagedBindMountSandbox::new(true)?;

	let context = Box::leak(Box::new(Context {
		sandbox,
		path_res_sandbox,
		tracer: TurnstileTracer::new()?,
		pidfd: OnceLock::new(),
		should_exit: AtomicBool::new(false),
		permissive: cli.permissive,
	}));

	// todo: default for now
	context.sandbox.update_mounts_from_list([
		(
			OsStr::new("/usr"),
			ManagedMountPoint {
				host_path: CString::new("/usr").unwrap(),
				attrs: MountAttributes {
					readonly: true,
					noexec: false,
				},
			},
		),
		(
			OsStr::new("/bin"),
			ManagedMountPoint {
				host_path: CString::new("/bin").unwrap(),
				attrs: MountAttributes {
					readonly: true,
					noexec: false,
				},
			},
		),
		(
			OsStr::new("/lib"),
			ManagedMountPoint {
				host_path: CString::new("/lib").unwrap(),
				attrs: MountAttributes {
					readonly: true,
					noexec: false,
				},
			},
		),
		(
			OsStr::new("/lib64"),
			ManagedMountPoint {
				host_path: CString::new("/lib64").unwrap(),
				attrs: MountAttributes {
					readonly: true,
					noexec: false,
				},
			},
		),
		(
			OsStr::new("/proc"),
			ManagedMountPoint {
				host_path: CString::new("/proc").unwrap(),
				attrs: MountAttributes {
					readonly: true,
					noexec: true,
				},
			},
		),
	])?;

	context.path_res_sandbox.update_mounts_from_list([(
		OsStr::new("/"),
		ManagedMountPoint {
			host_path: CString::new("/").unwrap(),
			attrs: MountAttributes {
				readonly: true,
				noexec: true,
			},
		},
	)])?;

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);
	unsafe {
		cmd.pre_exec(|| {
			context
				.tracer
				.install_filters(true)
				.map_err(|e| io::ErrorKind::Other.into())
		});
	}
	let tracing_thread = thread::spawn(|| tracing_thread(context));
	let mut res = match context.sandbox.run_command(&mut cmd) {
		Ok(child) => child,
		Err(e) => {
			error!("error running command: {}", e);
			context
				.should_exit
				.store(true, std::sync::atomic::Ordering::Relaxed);
			tracing_thread.join().unwrap();
			std::process::exit(1);
		}
	};
	let child_pid = res.id();
	info!("Spawned child process with pid {}", child_pid);
	context.pidfd.set(ProcPidFd::from_pid(child_pid)?).unwrap();
	let res = res.wait()?;
	if res.success() {
		info!("Child process exited successfully");
	} else {
		error!("Child process exited with error: {:?}", res);
	}
	context
		.should_exit
		.store(true, std::sync::atomic::Ordering::Relaxed);
	tracing_thread.join().unwrap();
	Ok(())
}
