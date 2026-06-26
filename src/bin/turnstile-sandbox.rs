use std::{
	collections::VecDeque,
	env,
	ffi::{CStr, CString, OsStr, OsString},
	fmt::write,
	io::{self, Write},
	os::{
		fd::{AsRawFd, BorrowedFd},
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
	AccessRequestError, BindMountSandbox, BindMountSandboxError, CommonPlaceholderData,
	ManagedBindMountSandbox, ManagedMountPoint, ManagedPlaceholder, ManagedTreeEntry,
	MountAttributes, PlaceholderDirData, PlaceholderFileData, PlaceholderSymlinkData,
	RequestContext, TracerOptions, TurnstileTracer,
	access::{
		AccessRequest, Operation,
		fs::{ForeignFd, FsOperation, FsTarget, RwxPermission},
	},
	fstree::FsTree,
};
use log::{debug, error, info};

use crate::common::{ProcPidFd, handle_child_result};
use crate::config::Config;
use crate::prompter::{Action, PrompterRequest, PrompterResponse, run_prompter};

mod common;
mod config;
mod prompter;

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
	/// live-reloaded. TODO implement live reload
	#[arg(required = true)]
	config: PathBuf,

	/// If set, the sandbox will log denials in the form of a policy yaml,
	/// but always allow the operation to continue.  This is mutually
	/// exclusive with `--prompter`.
	#[arg(long = "permissive")]
	permissive: bool,

	/// If set, on access denials the sandbox will launch the given
	/// program and wait for it to make a decision.  The program is
	/// expected to accept as input a JSON object, and output a JSON
	/// object.  See src/bin/prompter.rs for the object's specification,
	/// and an example implementation at `prompter/main.py`.  This is
	/// mutually exclusive with `--permissive`.
	#[arg(long = "prompter")]
	prompter: Option<String>,

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
	/// If set, on otherwise-denied access requests the sandbox launches
	/// this program and lets it decide what to do.  See
	/// [`prompter`](crate::prompter).  Mutually exclusive with
	/// `permissive`.
	prompter: Option<String>,
	/// Path to the config file, forwarded to the prompter and used when
	/// it requests a config reload.
	config_path: PathBuf,
	/// The original command line used to launch this sandbox, forwarded
	/// to the prompter.
	sandbox_cmd: Vec<String>,
	/// Randomly generated ID identifying this sandbox instance, forwarded
	/// to the prompter so it can group requests coming from the same
	/// sandbox.
	sandbox_id: u64,
}

/// Generate a random `u64` to identify this sandbox instance using
/// `getrandom()`.
fn random_sandbox_id() -> u64 {
	let mut buf = [0u8; 8];
	let ret = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
	if ret != buf.len() as isize {
		panic!("getrandom failed: {}", io::Error::last_os_error());
	}
	u64::from_ne_bytes(buf)
}

/// Stat `host_path` (no symlink following) and build a ManagedPlaceholder
/// that mirrors that path.
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
		libc::S_IFDIR => ManagedPlaceholder::Dir(PlaceholderDirData {
			common,
			mode: stat.st_mode,
		}),
		libc::S_IFLNK => {
			let target = std::fs::read_link(OsStr::from_bytes(host_path.to_bytes()))?;
			let target_cstr = CString::new(target.into_os_string().into_encoded_bytes())
				.map_err(|_| io::Error::other("symlink target contains NUL byte"))?;
			ManagedPlaceholder::Symlink(PlaceholderSymlinkData {
				common,
				target: target_cstr,
			})
		}
		_ => ManagedPlaceholder::File(PlaceholderFileData {
			common,
			mode: stat.st_mode,
			len: stat.st_size as u64,
		}),
	})
}

/// Walk the *ancestor* components of a user-supplied path (the raw
/// `path` as passed by the app, resolved against `dfd`) on the host.
/// For every symlink encountered we record a symlink placeholder in the
/// sandbox that mirrors the host (same target), and continue resolution
/// through the symlink.  The leaf component is never touched.
///
/// `dfd` is the base the path resolves against (the target's dfd,
/// already reopened in the host-mapped root); its `readlink()` gives the
/// starting resolved path, on top of which `path` is walked one
/// component at a time.
///
/// `follow_final` says whether the final (leaf) component is followed by
/// the kernel when it is a symlink (i.e. the access was *not*
/// `AT_SYMLINK_NOFOLLOW`).  When true, the leaf is walked just like an
/// ancestor, so a symlink leaf (e.g. `/etc/localtime`) is mirrored and
/// resolution continues into its target; when false, the leaf is left
/// untouched (the mount / placeholder flow handles the symlink itself).
///
/// This makes sure that an app accessing e.g. `/home/user1/file` (where
/// `/home/user1` is a host symlink to `/home/user2`) sees the same
/// symlink inside the sandbox, with the underlying placeholder / mount
/// living at `/home/user2/file`.
fn create_symlinks_for_user_path(
	sandbox: &ManagedBindMountSandbox,
	dfd: &ForeignFd,
	path: &CStr,
	follow_final: bool,
) -> Result<(), io::Error> {
	// Seed the resolved prefix with the dfd's canonical (symlink-free)
	// path.  Root becomes empty so candidates below are built as
	// "/comp"; a non-root path keeps no trailing slash.
	let dfd_path = dfd.readlink()?.into_encoded_bytes();
	if !dfd_path.starts_with(b"/") {
		return Ok(());
	}
	debug!(
		"create_symlinks_for_user_path: dfd={:?} path={:?}",
		OsStr::from_bytes(&dfd_path),
		path
	);
	let mut resolved: Vec<u8> = if dfd_path == b"/" {
		Vec::new()
	} else {
		dfd_path
	};
	// Walk the components of `path`.  Ancestor components are always
	// followed; the final (leaf) component is only walked when
	// `follow_final` is set, otherwise it is left untouched (handled by
	// the mount / placeholder flow).
	let path_comps: Vec<&[u8]> = path
		.to_bytes()
		.split(|&b| b == b'/')
		.filter(|c| !c.is_empty())
		.collect();
	if path_comps.is_empty() {
		// Empty path (AT_EMPTY_PATH): the dfd itself is the target.
		return Ok(());
	}
	let walk_upto = if follow_final {
		path_comps.len()
	} else {
		path_comps.len() - 1
	};
	let mut remaining: VecDeque<Vec<u8>> =
		path_comps[..walk_upto].iter().map(|c| c.to_vec()).collect();
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
			// Pop the last component off `resolved`. This way of handling
			// .. is safe because none of the components of `resolved` are
			// symlinks.
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
			let err = io::Error::last_os_error();
			// A missing trailing component (nothing left to resolve) is
			// fine: e.g. the leaf of an `O_CREAT` open doesn't exist yet,
			// and there are no further symlinks to mirror.  A missing
			// component with more still to walk is a genuinely unresolvable
			// path.
			if err.kind() == io::ErrorKind::NotFound && remaining.is_empty() {
				return Ok(());
			}
			return Err(err);
		}
		let kind = stat.st_mode & libc::S_IFMT;
		if kind == libc::S_IFLNK {
			let target = std::fs::read_link(OsStr::from_bytes(&candidate))?;
			let target_bytes = target.into_os_string().into_encoded_bytes();
			let target_cstr = CString::new(target_bytes.clone())
				.map_err(|_| io::Error::other("symlink target contains NUL byte"))?;
			debug!(
				"{:?} symlinks to {:?}",
				OsStr::from_bytes(&candidate),
				target_cstr
			);
			// Don't do anything if the symlink is already covered by a
			// mount or created as a placeholder,
			let covered = check_covered_or_placeholder(sandbox, &candidate_c, false, false, true)
				.map(|(covered, _)| covered)
				.unwrap_or(false);
			if !covered {
				let placeholder = ManagedPlaceholder::Symlink(PlaceholderSymlinkData {
					common: CommonPlaceholderData::from_stat(&stat),
					target: target_cstr,
				});
				sandbox
					.add_or_update_placeholder(OsStr::from_bytes(&candidate), placeholder)
					.map_err(io::Error::other)?;
			}
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
			debug!("walked to {:?}", OsStr::from_bytes(&candidate));
			resolved = candidate;
		}
	}
	Ok(())
}

/// Determine whether `abspath` is already covered for an access.
///
/// A path is covered if it sits under a mount that already grants the
/// required access (`need_write` / `need_exec`).  Additionally, when
/// `resolve_only` is true, a path that merely has a placeholder is also
/// considered covered.
///
/// Returns `(covered, existing_mount)`, same as
/// [`ManagedBindMountSandbox::check_covered`].  When the placeholder
/// lookup errors it is logged and the mount-only result is returned.
fn check_covered_or_placeholder(
	sandbox: &ManagedBindMountSandbox,
	abspath: &CStr,
	need_write: bool,
	need_exec: bool,
	resolve_only: bool,
) -> Result<(bool, Option<ManagedMountPoint>), BindMountSandboxError> {
	assert!(!resolve_only || (!need_write && !need_exec));
	let cover = sandbox.check_covered(abspath, need_write, need_exec);
	if matches!(cover, Ok((true, _))) || !resolve_only {
		return cover;
	}
	match sandbox.has_placeholder(abspath) {
		Ok(true) => Ok((true, None)),
		Ok(false) => cover,
		Err(e) => {
			debug!(
				"error checking if {:?} is covered by placeholder: {}",
				abspath, e
			);
			cover
		}
	}
}

/// Permissive-mode "inherit access down": after granting `attrs` at a
/// path, upgrade every existing descendant mount so that it is at least
/// as permissive. For example, if a ro mount is created on a subpath
/// earlier due to read, but then a write is attempted on its parent, a
/// reasonable policy would just grant read-write on the parent.
fn inherit_attrs_to_descendants(
	sandbox: &ManagedBindMountSandbox,
	abspath: &CStr,
	attrs: MountAttributes,
) {
	if attrs.readonly && attrs.noexec {
		// Nothing more permissive than the default to propagate.
		return;
	}
	let descendants = match sandbox.mounts_under(abspath) {
		Ok(d) => d,
		Err(e) => {
			debug!("could not list mounts under {:?}: {}", abspath, e);
			return;
		}
	};
	for (sandbox_path, mut mp) in descendants {
		let mut changed = false;
		if !attrs.readonly && mp.attrs.readonly {
			mp.attrs.readonly = false;
			changed = true;
		}
		if !attrs.noexec && mp.attrs.noexec {
			mp.attrs.noexec = false;
			changed = true;
		}
		if !changed {
			continue;
		}
		if let Err(e) = sandbox.add_or_update_mount(&sandbox_path, mp) {
			error!(
				"error inheriting access to descendant mount {:?}: {}",
				sandbox_path, e
			);
		} else {
			debug!(
				"inherited access down to descendant mount {:?}",
				sandbox_path
			);
		}
	}
}

/// (Re)load the user config file referenced by `context.config_path` and
/// apply it to the sandbox, replacing the current mount/placeholder set.
/// Used both at startup and when a prompter requests a config reload.
fn load_config_into_sandbox(context: &Context) -> Result<(), Box<dyn std::error::Error>> {
	let cfg = Config::load(&context.config_path)?;
	let resolved_entries = cfg.parse_entries()?;
	if resolved_entries.is_empty() {
		info!(
			"config file {:?} has no rules; sandbox will start empty",
			context.config_path
		);
	}
	let mut entries: Vec<(&OsStr, ManagedTreeEntry)> = Vec::with_capacity(resolved_entries.len());
	for e in &resolved_entries {
		let entry = match e.mount {
			Some(ref m) => ManagedTreeEntry::BindMount(m.clone()),
			None => {
				let p = build_resolve_placeholder(
					e.placeholder_host_path
						.as_deref()
						.expect("placeholder_host_path must be non-empty when mount is None"),
				)?;
				ManagedTreeEntry::Placeholder(p)
			}
		};
		entries.push((e.sandbox_path.as_os_str(), entry));
	}
	context.sandbox.update_from_list(entries)?;
	Ok(())
}

/// Build a [`PrompterRequest`] describing the access request and run the
/// configured prompter program, returning its decision.  Returns `None`
/// if the prompter could not be launched or its response could not be
/// parsed (in which case the caller should fail the syscall safely).
fn prompt_for_request(
	context: &Context,
	program: &str,
	req_ctx: &mut RequestContext,
	access_request: &AccessRequest,
	rwx_permissions: Vec<RwxPermission>,
) -> Option<PrompterResponse> {
	let pid = req_ctx.pid();
	let request_comm = req_ctx
		.comm()
		.map(|c| c.to_string_lossy().into_owned())
		.unwrap_or_default();
	// Open an O_PATH fd to /proc/<pid> for the prompter so it can inspect
	// the requesting process.  Passed to the child by clearing CLOEXEC in
	// `run_prompter`.
	let proc_fd = unsafe {
		libc::open(
			format!("/proc/{pid}\0").as_ptr() as *const libc::c_char,
			libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
		)
	};
	let pidfd = if proc_fd >= 0 {
		Some(proc_fd as u32)
	} else {
		debug!(
			"could not open /proc/{} to pass to prompter: {}",
			pid,
			io::Error::last_os_error()
		);
		None
	};
	let request = PrompterRequest {
		sandbox_id: context.sandbox_id,
		sandbox_cmd: context.sandbox_cmd.clone(),
		request_pid: pid as u32,
		request_comm,
		access_request: access_request.clone(),
		pidfd,
		rwx_permissions,
		config_path: context.config_path.to_string_lossy().into_owned(),
	};
	let pass_fd = (proc_fd >= 0).then(|| unsafe { BorrowedFd::borrow_raw(proc_fd) });
	if req_ctx.still_valid().ok() != Some(true) {
		debug!("request is no longer valid; not prompting");
		if proc_fd >= 0 {
			unsafe {
				libc::close(proc_fd);
			}
		}
		return None;
	}
	let response = match run_prompter(program, &request, pass_fd) {
		Ok(r) => Some(r),
		Err(e) => {
			error!("error running prompter {:?}: {}", program, e);
			None
		}
	};
	if proc_fd >= 0 {
		unsafe {
			libc::close(proc_fd);
		}
	}
	response
}

/// Trim a trailing "/." from a path (the only non-canonical form a
/// realpath-derived path can take, produced when the syscall's path
/// ended in "/", "/." or "/..").  Keeps "/" if trimming would empty the
/// path.  The sandbox mount tree rejects "." path components, so any
/// prompter-supplied path is run through this first.
fn trim_trailing_dot(path: &[u8]) -> &[u8] {
	match path.strip_suffix(b"/.") {
		Some(b"") => b"/",
		Some(stripped) => stripped,
		None => path,
	}
}

/// Apply the side effects requested by a [`PrompterResponse`]: an
/// optional config reload, added mounts and placeholders, and the
/// symlink-mirroring / descendant-widening conveniences.  The
/// syscall-level decision in `response.action` is handled by the caller.
fn apply_prompter_response(context: &Context, response: &PrompterResponse, t_local: &FsTarget) {
	if response.reload_config {
		match load_config_into_sandbox(context) {
			Ok(()) => debug!("prompter: reloaded config from {:?}", context.config_path),
			Err(e) => error!("prompter: error reloading config: {}", e),
		}
	}

	for m in &response.add_mounts {
		let mount_bytes = trim_trailing_dot(m.mount_point.as_bytes());
		debug!(
			"prompter: adding mount at {:?} -> {:?} (ro={}, noexec={})",
			m.mount_point, m.mount.host_path, m.mount.attrs.readonly, m.mount.attrs.noexec
		);
		match context
			.sandbox
			.add_or_update_mount(OsStr::from_bytes(mount_bytes), m.mount.clone())
		{
			Ok(()) => {
				if response.auto_widen_descendant_permissions {
					match CString::new(mount_bytes.to_vec()) {
						Ok(c) => inherit_attrs_to_descendants(&context.sandbox, &c, m.mount.attrs),
						Err(_) => error!(
							"prompter: mount point {:?} contains a NUL byte",
							m.mount_point
						),
					}
				}
			}
			Err(e) => error!("prompter: error adding mount at {:?}: {}", m.mount_point, e),
		}
	}

	for p in &response.add_placeholders {
		let path_bytes = trim_trailing_dot(p.path.as_bytes());
		// `match_host` and an explicit placeholder are mutually
		// exclusive; exactly one must be provided.
		let placeholder = match (p.match_host, &p.placeholder) {
			(true, Some(_)) => {
				error!(
					"prompter: placeholder add for {:?} sets both match_host and an explicit \
					 placeholder; skipping",
					p.path
				);
				continue;
			}
			(false, None) => {
				error!(
					"prompter: placeholder add for {:?} sets neither match_host nor an explicit \
					 placeholder; skipping",
					p.path
				);
				continue;
			}
			(true, None) => {
				let host_path = match CString::new(path_bytes.to_vec()) {
					Ok(c) => c,
					Err(_) => {
						error!(
							"prompter: placeholder path {:?} contains a NUL byte",
							p.path
						);
						continue;
					}
				};
				match build_resolve_placeholder(&host_path) {
					Ok(ph) => ph,
					Err(e) => {
						error!(
							"prompter: error building match_host placeholder for {:?}: {}",
							p.path, e
						);
						continue;
					}
				}
			}
			(false, Some(ph)) => ph.clone(),
		};
		debug!(
			"prompter: adding placeholder at {:?}: {:?}",
			p.path, placeholder
		);
		if let Err(e) = context
			.sandbox
			.add_or_update_placeholder(OsStr::from_bytes(path_bytes), placeholder)
		{
			error!("prompter: error adding placeholder at {:?}: {}", p.path, e);
		}
	}

	if response.auto_add_symlinks {
		debug!("prompter: auto-adding symlinks for requested path");
		if let Err(e) = create_symlinks_for_user_path(
			&context.sandbox,
			t_local.dfd(),
			t_local.path(),
			!t_local.no_follow(),
		) {
			debug!("prompter: could not mirror symlinks: {}", e);
		}
	}
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
				// Set to the errno the prompter asked us to fail the
				// syscall with, if any.
				let mut send_errno: Option<i32> = None;
				// Set once we have prompted for this syscall, so we do not
				// prompt again for its remaining permissions.
				let mut prompted = false;
				// Set when we cannot evaluate the request at all (e.g.
				// request is for an anonymous pipe or socket)
				let mut force_continue = false;
				match request.operation() {
					Operation::FsOperation(fsop) => {
						let rwxps = fsop.as_rwx_permissions();
						if req_ctx.still_valid().ok() != Some(true) {
							debug!("request is no longer valid");
							continue;
						}
						for rwxp in &rwxps {
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
										match e.kind() {
											io::ErrorKind::NotFound
											| io::ErrorKind::PermissionDenied => {
												debug!(
													"error reopening target dfd in real root for {}: {}",
													rwxp, e
												);
											}
											_ => {
												error!(
													"error reopening target dfd in real root for {}: {}",
													rwxp, e
												);
											}
										}
										debug!("Will not evaluate request");
										force_continue = true;
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
							if abspath.as_bytes() == b"/" {
								debug!("skipping /");
								continue;
							}
							let mut add_symlinks = false;
							let mut add_placeholder = false;
							let mut add_mount = false;
							let resolve_only =
								!rwxp.read && !rwxp.write && !rwxp.exec && !rwxp.chdir;
							// We consider a request covered if either it is under a
							// mount with sufficient permissions, or if it is a
							// resolve-only request and the path is covered by a
							// placeholder.
							let cover = check_covered_or_placeholder(
								&context.sandbox,
								&abspath,
								rwxp.write,
								rwxp.exec,
								resolve_only,
							);
							match cover.as_ref().map(|x| x.0) {
								Ok(true) => {
									debug!(
										"{}[{}] is covered for {}{}{} on {}",
										req_ctx
											.comm()
											.unwrap_or_else(|_| OsString::from("???"))
											.to_string_lossy(),
										req_ctx.pid(),
										if rwxp.read || rwxp.chdir { "r" } else { "-" },
										if rwxp.write { "w" } else { "-" },
										if rwxp.exec { "x" } else { "-" },
										t_local,
									);
									add_symlinks = true;
								}
								Ok(false) => {
									check_req_valid!();
									info!(
										"{}[{}] need fs permission {}{}{} on {}",
										req_ctx
											.comm()
											.unwrap_or_else(|_| OsString::from("???"))
											.to_string_lossy(),
										req_ctx.pid(),
										if rwxp.read || rwxp.chdir { "r" } else { "-" },
										if rwxp.write { "w" } else { "-" },
										if rwxp.exec { "x" } else { "-" },
										t_local,
									);
									// TODO: using abspath here is technically wrong -
									// we want to emit denials in the sandbox's path,
									// so that if e.g. /tmp is mounted ro to
									// /tmp/real_tmp, a write at /tmp/aa shows up as a
									// denial at /tmp/aa, not /tmp/real_tmp/aa.
									let d = denials.get_mut_or_insert(
										OsStr::from_bytes(abspath.as_bytes()),
										DenialLogNode::default,
									);
									d.need_read |= rwxp.read || rwxp.chdir;
									d.need_write |= rwxp.write;
									d.need_exec |= rwxp.exec;
									if context.permissive {
										add_symlinks = true;
										if !resolve_only {
											add_mount = true;
										} else {
											add_placeholder = true;
										}
									} else if let Some(program) = &context.prompter {
										// Ask the prompter what to do.  We prompt at
										// most once per syscall, sending all of its
										// rwx permissions; the mounts / placeholders
										// the prompter adds may then also cover the
										// remaining permissions of this same syscall.
										if !prompted {
											prompted = true;
											match prompt_for_request(
												context,
												program,
												&mut req_ctx,
												&request,
												rwxps.to_vec(),
											) {
												Some(response) => {
													apply_prompter_response(
														context, &response, &t_local,
													);
													match response.action {
														// Allow the syscall; the
														// applied mounts /
														// placeholders provide the
														// granted access.
														Action::Continue(_) => {}
														Action::SendError(errno) => {
															send_errno = Some(errno);
															break;
														}
													}
												}
												None => {
													// Prompter failed; fail the
													// syscall safely with EPERM.
													send_eperm = true;
													break;
												}
											}
										}
									} else {
										// Not covered and neither permissive nor a
										// prompter is configured - send an EPERM so
										// the process doesn't get ENOENT or EROFS
										// instead.  (This denial is not for
										// security).  Also, don't add symlinks to
										// avoid exposing symlink data which the user
										// does not intend to expose.
										send_eperm = true;
									}
								}
								Err(e) => {
									check_req_valid!();
									error!("error checking if {} is covered: {}", rwxp, e);
								}
							}
							if add_symlinks {
								// Mirror any host symlinks in the path's
								// ancestors so the original (pre-resolution)
								// path the app used keeps working inside the
								// sandbox.
								if let Err(e) = create_symlinks_for_user_path(
									&context.sandbox,
									t_local.dfd(),
									t_local.path(),
									!t_local.no_follow(),
								) {
									debug!("could not mirror symlinks for {}: {}", rwxp, e);
								}
							}
							if add_placeholder {
								// Resolve-only access (e.g.  realpath / readlink on intermediate path
								// components, stat-only lookup).  No permission to grant, but we do need to
								// make the path resolvable inside the sandbox by mirroring the host entry's
								// type as a placeholder.
								let ph = match build_resolve_placeholder(&abspath) {
									Ok(ph) => ph,
									Err(e) => {
										debug!(
											"could not build resolve placeholder for {:?}: {}",
											abspath, e
										);
										continue;
									}
								};
								if let Err(e) = context.sandbox.add_or_update_placeholder(
									OsStr::from_bytes(abspath.as_bytes()),
									ph,
								) {
									error!(
										"error adding resolve placeholder for {:?}: {}",
										abspath, e
									);
								} else {
									debug!("added resolve placeholder for {:?}", abspath);
								}
							}
							if add_mount {
								// `cover.1` is the deepest mount that is an
								// ancestor-or-self of `abspath` (or None).  In
								// permissive mode the sandbox mirrors the host
								// 1:1, so a mount whose host_path == abspath is
								// the exact mount at this path; anything else is
								// an ancestor.
								let covering = cover.unwrap().1;
								let exact = covering
									.as_ref()
									.filter(|mp| mp.host_path == abspath)
									.cloned();
								let ancestor = covering.filter(|mp| mp.host_path != abspath);
								let mut mp = exact.unwrap_or_else(|| ManagedMountPoint {
									host_path: abspath.clone(),
									attrs: MountAttributes {
										readonly: true,
										noexec: true,
									},
								});
								// Inherit access down: a child must be at least
								// as permissive as its covering ancestor, so a
								// writable/executable parent is not shadowed by a
								// more restrictive child.
								if let Some(anc) = &ancestor {
									if !anc.attrs.readonly {
										mp.attrs.readonly = false;
									}
									if !anc.attrs.noexec {
										mp.attrs.noexec = false;
									}
								}
								if rwxp.write {
									mp.attrs.readonly = false;
								}
								if rwxp.exec {
									mp.attrs.noexec = false;
								}
								let new_attrs = mp.attrs;
								match context
									.sandbox
									.add_or_update_mount(OsStr::from_bytes(abspath.as_bytes()), mp)
								{
									Ok(()) => {
										// Propagate the (possibly newly granted)
										// access down to any existing, more
										// restrictive descendant mounts.
										inherit_attrs_to_descendants(
											&context.sandbox,
											&abspath,
											new_attrs,
										);
									}
									Err(e) => {
										error!("error updating mount for {:?}: {}", abspath, e);
									}
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
				if force_continue {
					if let Err(e) = req_ctx.send_continue() {
						debug!("error continuing request: {}", e);
					}
					continue;
				}
				// Finalize via the sandbox, which transparently upgrades
				// the traced process's fd view on allow, or fails the
				// syscall on deny.
				let handle = context.sandbox.new_request_handle(request, req_ctx);
				let res = if let Some(errno) = send_errno {
					handle.deny(errno)
				} else if send_eperm {
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
		// "Inherit access down" also when summarising denials
		let mut rules: std::collections::BTreeMap<String, String> =
			std::collections::BTreeMap::new();
		denials.fold_top_down_from(
			|path, curr, (acc_r, acc_w, acc_x)| {
				let (r, w, x) = (curr.need_read, curr.need_write, curr.need_exec);
				let is_mount = r || w || x;
				let parent_has_mount = acc_r;
				let redundant = if is_mount {
					// Read is always covered by a covering mount, so we only
					// need write/exec to also be covered for this mount to be
					// redundant.
					parent_has_mount && (!w || acc_w) && (!x || acc_x)
				} else {
					// Resolve-only placeholder: redundant once any covering
					// mount makes it resolvable.  Placeholders do not inherit
					// down (a placeholder at /home does not make a placeholder
					// at /home/user redundant).
					parent_has_mount
				};
				if !redundant {
					let mut perms = String::new();
					if is_mount {
						// A config entry must be either empty or contains
						// 'r', so always emit it for a mount.
						perms.push('r');
						if w {
							perms.push('w');
						}
						if x {
							perms.push('x');
						}
					}
					// Escape $ to $$ (our config format has special
					// handling for $)
					let path_str = String::from_utf8_lossy(path.as_bytes()).replace('$', "$$");
					rules.insert(path_str, perms);
				}
				(acc_r || is_mount, acc_w || w, acc_x || x)
			},
			(false, false, false),
			OsStr::new("/"),
		);
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

	if cli.permissive && cli.prompter.is_some() {
		return Err("--permissive and --prompter are mutually exclusive".into());
	}

	let sandbox = ManagedBindMountSandbox::new(cli.block_nested_userns)?;
	let path_res_sandbox = ManagedBindMountSandbox::new(true)?;

	let context = Box::leak(Box::new(Context {
		sandbox,
		path_res_sandbox,
		tracer: TurnstileTracer::new(TracerOptions::default())?,
		pidfd: OnceLock::new(),
		should_exit: AtomicBool::new(false),
		permissive: cli.permissive,
		prompter: cli.prompter.clone(),
		config_path: cli.config.clone(),
		sandbox_cmd: env::args().collect(),
		sandbox_id: random_sandbox_id(),
	}));

	// Load mounts from the user-provided config file, replacing the
	// previously hard-coded default initial mount list.
	load_config_into_sandbox(context)?;

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
