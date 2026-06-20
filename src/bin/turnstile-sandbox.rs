use std::{
	collections::VecDeque,
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
	AccessRequestError, BindMountSandbox, CommonPlaceholderData, ManagedBindMountSandbox,
	ManagedMountPoint, ManagedPlaceholder, MountAttributes, PlaceholderDirData,
	PlaceholderFileData, PlaceholderSymlinkData, TurnstileTracer,
	access::{
		Operation,
		fs::{FsOperation, RwxPermission},
	},
	fstree::FsTree,
};
use log::{debug, error, info};

use crate::common::{ProcPidFd, handle_child_result};
use crate::config::Config;

mod common;
mod config;

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
	need_read: bool,
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

/// Stat `host_path` (no symlink following) and build a placeholder of
/// the matching type so that the path becomes resolvable inside the
/// sandbox without granting any actual read/write/exec permission on
/// the underlying inode.  Used for "resolve-only" access patterns such
/// as `realpath` / `readlink` on intermediate path components.
fn build_resolve_placeholder(host_path: &CStr) -> Result<ManagedPlaceholder, io::Error> {
	let mut stat: libc::stat = unsafe { std::mem::zeroed() };
	let res = unsafe {
		libc::fstatat(
			libc::AT_FDCWD,
			host_path.as_ptr(),
			&mut stat,
			libc::AT_SYMLINK_NOFOLLOW,
		)
	};
	if res != 0 {
		return Err(io::Error::last_os_error());
	}
	let common = CommonPlaceholderData::from_stat(&stat);
	let kind = stat.st_mode & libc::S_IFMT;
	Ok(match kind {
		libc::S_IFDIR => ManagedPlaceholder::PlaceholderDir(PlaceholderDirData {
			common,
			mode: stat.st_mode,
		}),
		libc::S_IFLNK => {
			let target = std::fs::read_link(OsStr::from_bytes(host_path.to_bytes()))?;
			let target_cstr = CString::new(target.into_os_string().into_encoded_bytes())
				.map_err(|_| io::Error::other("symlink target contains NUL byte"))?;
			ManagedPlaceholder::PlaceholderSymlink(PlaceholderSymlinkData {
				common,
				target: target_cstr,
			})
		}
		_ => ManagedPlaceholder::PlaceholderFile(PlaceholderFileData {
			common,
			mode: stat.st_mode,
			len: stat.st_size as u64,
		}),
	})
}

/// Compute the path the traced process intended (before kernel symlink
/// resolution) by combining the readlinked dfd with the original path.
fn intent_host_path(target: &libturnstile::access::fs::FsTarget) -> Result<CString, io::Error> {
	let mut bytes = target.dfd().readlink()?.into_encoded_bytes();
	let path_bytes = target.path().to_bytes();
	if !path_bytes.is_empty() {
		if !bytes.ends_with(b"/") {
			bytes.push(b'/');
		}
		bytes.extend_from_slice(path_bytes);
	}
	if bytes.is_empty() {
		bytes.push(b'/');
	}
	if bytes.contains(&0) {
		return Err(io::Error::other("intent path contains NUL byte"));
	}
	bytes.push(0);
	Ok(CString::from_vec_with_nul(bytes).expect("appended NUL"))
}

/// Walk the *ancestor* components of `intent_path` on the host.  For
/// every symlink encountered we record a symlink placeholder in the
/// sandbox that mirrors the host (same target), and continue
/// resolution through the symlink.  The leaf component is never
/// touched.
///
/// This makes sure that an app accessing e.g. `/home/user1/file` (where
/// `/home/user1` is a host symlink to `/home/user2`) sees the same
/// symlink inside the sandbox, with the underlying placeholder / mount
/// living at `/home/user2/file`.
fn mirror_intent_path_symlinks(
	sandbox: &ManagedBindMountSandbox,
	intent_path: &CStr,
) -> Result<(), io::Error> {
	let bytes = intent_path.to_bytes();
	if !bytes.starts_with(b"/") {
		return Ok(());
	}
	let comps: Vec<&[u8]> = bytes
		.split(|&b| b == b'/')
		.filter(|c| !c.is_empty())
		.collect();
	if comps.len() < 2 {
		// Only a leaf (or empty) - no ancestor components to walk.
		return Ok(());
	}
	let mut resolved: Vec<u8> = Vec::new();
	let mut remaining: VecDeque<Vec<u8>> = comps[..comps.len() - 1]
		.iter()
		.map(|c| c.to_vec())
		.collect();
	let mut iters = 0;
	while let Some(comp) = remaining.pop_front() {
		iters += 1;
		if iters > 256 {
			return Err(io::Error::from_raw_os_error(libc::ELOOP));
		}
		if comp == b"." {
			continue;
		}
		if comp == b".." {
			if let Some(p) = resolved.iter().rposition(|&b| b == b'/') {
				resolved.truncate(p);
			}
			continue;
		}
		let mut candidate = resolved.clone();
		candidate.push(b'/');
		candidate.extend_from_slice(&comp);
		let candidate_c = CString::new(candidate.clone())
			.map_err(|_| io::Error::other("NUL byte in path component"))?;
		let mut stat: libc::stat = unsafe { std::mem::zeroed() };
		let res = unsafe {
			libc::fstatat(
				libc::AT_FDCWD,
				candidate_c.as_ptr(),
				&mut stat,
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if res != 0 {
			return Err(io::Error::last_os_error());
		}
		let kind = stat.st_mode & libc::S_IFMT;
		if kind == libc::S_IFLNK {
			let target = std::fs::read_link(OsStr::from_bytes(&candidate))?;
			let target_bytes = target.into_os_string().into_encoded_bytes();
			let target_cstr = CString::new(target_bytes.clone())
				.map_err(|_| io::Error::other("symlink target contains NUL byte"))?;
			let placeholder = ManagedPlaceholder::PlaceholderSymlink(PlaceholderSymlinkData {
				common: CommonPlaceholderData::from_stat(&stat),
				target: target_cstr,
			});
			sandbox
				.add_or_update_placeholder(OsStr::from_bytes(&candidate), placeholder)
				.map_err(io::Error::other)?;
			if target_bytes.starts_with(b"/") {
				resolved.clear();
			}
			let target_comps: Vec<Vec<u8>> = target_bytes
				.split(|&b| b == b'/')
				.filter(|c| !c.is_empty())
				.map(|c| c.to_vec())
				.collect();
			for c in target_comps.into_iter().rev() {
				remaining.push_front(c);
			}
		} else {
			resolved = candidate;
		}
	}
	Ok(())
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
							// Mirror any host symlinks in the path's
							// ancestors so the original (pre-resolution)
							// path the app used keeps working inside the
							// sandbox.
							match intent_host_path(&rwxp.target) {
								Ok(intent) => {
									if let Err(e) =
										mirror_intent_path_symlinks(&context.sandbox, &intent)
									{
										debug!(
											"could not mirror symlinks for intent path {:?}: {}",
											intent, e
										);
									}
								}
								Err(e) => {
									debug!("could not compute intent path for {}: {}", rwxp, e);
								}
							}
							if !rwxp.read && !rwxp.write && !rwxp.exec {
								// Resolve-only access (e.g. realpath /
								// readlink on intermediate path
								// components, stat-only lookup).  No
								// permission to grant, but we do need to
								// make the path resolvable inside the
								// sandbox by mirroring the host entry's
								// type as a placeholder.
								if abspath.as_bytes() != b"/" {
									match build_resolve_placeholder(&abspath) {
										Ok(ph) => {
											if let Err(e) =
												context.sandbox.add_or_update_placeholder(
													OsStr::from_bytes(abspath.as_bytes()),
													ph,
												) {
												error!(
													"error adding resolve placeholder for {:?}: {}",
													abspath, e
												);
											} else {
												debug!(
													"added resolve placeholder for {:?}",
													abspath
												);
											}
										}
										Err(e) => {
											debug!(
												"could not build resolve placeholder for {:?}: {}",
												abspath, e
											);
										}
									}
								}
								continue;
							}
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
									d.need_read |= rwxp.read;
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
				if req_ctx.still_valid().ok() != Some(true) {
					debug!("request is no longer valid; skipping response");
					continue;
				}
				// Finalize via the sandbox, which transparently upgrades
				// the traced process's fd view on allow, or fails the
				// syscall on deny.
				let handle = context.sandbox.new_request_handle(request, req_ctx);
				let res = if send_eperm {
					handle.deny(libc::EPERM)
				} else {
					handle.allow()
				};
				if let Err(e) = res {
					// The most common cause here is the request having
					// been invalidated by the target exiting, which is
					// benign; the dispatch logs genuine failures itself.
					debug!("error finalizing request (likely no longer valid): {}", e);
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
		let mut rules: std::collections::BTreeMap<String, String> =
			std::collections::BTreeMap::new();
		denials.walk_top_down(|path, val| {
			let mut perms = String::new();
			if val.need_read {
				perms.push('r');
			}
			if val.need_write {
				perms.push('w');
			}
			if val.need_exec {
				perms.push('x');
			}
			// Translate $ to $$ so the path round-trips through the
			// config's path expander.  Lossy UTF-8 conversion is used for
			// the rare case of non-UTF-8 paths since YAML strings are
			// fundamentally Unicode; serde_yaml_ng will handle quoting and
			// escaping the resulting string for arbitrary code points.
			let path_str = path.to_string_lossy().replace('$', "$$");
			rules.insert(path_str, perms);
		});
		// Wrap in a top-level `rules:` map so the output can be copy-pasted
		// directly into a config file.
		#[derive(serde::Serialize)]
		struct DenialsConfig<'a> {
			rules: &'a std::collections::BTreeMap<String, String>,
		}
		let yaml = serde_yaml_ng::to_string(&DenialsConfig { rules: &rules })
			.expect("serializing String->String map should not fail");
		let mut stdout = std::io::stdout().lock();
		write!(stdout, "Denials:\n{}", yaml).unwrap();
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

	// Load mounts from the user-provided config file, replacing the
	// previously hard-coded default initial mount list.
	let cfg = Config::load(&cli.config)?;
	let resolved_mounts = cfg.resolve_mounts()?;
	if resolved_mounts.is_empty() {
		info!(
			"config file {:?} has no rules; sandbox will start empty",
			cli.config
		);
	}
	context.sandbox.update_mounts_from_list(
		resolved_mounts
			.iter()
			.map(|m| (m.sandbox_path.as_os_str(), m.mount.clone())),
	)?;

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
	let res = context.sandbox.run_command(&mut cmd);
	context.tracer.close_child_sock();
	let mut res = match res {
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
