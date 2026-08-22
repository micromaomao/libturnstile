use std::{
	collections::VecDeque,
	ffi::{CStr, CString, OsStr, OsString},
	io::{self, Write},
	os::{
		fd::{AsRawFd, BorrowedFd},
		unix::{ffi::OsStrExt, process::CommandExt},
	},
	path::{Path, PathBuf},
	process::Command,
	sync::{Mutex, OnceLock, atomic::AtomicBool},
	thread::{self, sleep},
	time::Duration,
};

use clap::Parser;
use inotify::{EventMask, Inotify, WatchMask};
use libturnstile::{
	AccessRequestError, BindMountSandboxError, CommonPlaceholderData, ManagedBindMountSandbox,
	ManagedMountPoint, ManagedPlaceholder, ManagedTreeEntry, MountAttributes, PlaceholderDirData,
	PlaceholderFileData, PlaceholderSymlinkData, RequestContext, SandboxOptions, TracerOptions,
	TurnstileTracer,
	access::{
		AccessRequest, Operation,
		fs::{ForeignFd, FsOperation, FsTarget, RwxPermission},
	},
	fstree::FsTree,
};
use log::{debug, error, info};

use crate::common::ProcPidFd;
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

	/// Configuration for this sandbox. Changes to this file will be
	/// live-reloaded.
	#[arg(required = true)]
	config: PathBuf,

	/// If set, and if the config file provided either does not exist or is
	/// empty, a default config will be written to the file.
	#[arg(long = "default-config")]
	default_config: bool,

	/// If set, the sandbox will log denials in the form of a policy yaml,
	/// but always allow the operation to continue.  This is mutually
	/// exclusive with `--prompter` and `--qt-prompter`.
	#[arg(long = "permissive")]
	permissive: bool,

	/// If set, on access denials the sandbox will launch the given
	/// program and wait for it to make a decision.  The program is
	/// expected to accept as input a JSON object, and output a JSON
	/// object.  See src/bin/prompter.rs for the object's specification,
	/// and an example implementation at `prompter/main.py`.  This is
	/// mutually exclusive with `--permissive` and `--qt-prompter`.
	#[arg(long = "prompter")]
	prompter: Option<String>,

	/// If set, on access denials the sandbox will launch a built-in, Python and
	/// Qt-based prompter.  Mutually exclusive with `--permissive` and
	/// `--prompter`.  Requires host Python to have pyside6 and pyyaml.
	#[arg(long = "qt-prompter")]
	qt_prompter: bool,

	/// ID identifying this sandbox instance in requests sent to the prompter.
	/// Defaults to a randomly generated value.
	#[arg(long = "sandbox-id")]
	sandbox_id: Option<u64>,

	/// Program to run and its arguments
	#[arg(required = true)]
	command: Vec<OsString>,
}

const QT_PROMPTER_SCRIPT: &[u8] = include_bytes!("../../prompter/main.py");
const DEFAULT_CONFIG: &[u8] = include_bytes!("sandbox-config-default.yaml");

fn write_default_config_if_empty(path: &Path) -> io::Result<()> {
	// Don't require write permission if the config exists.  Therefore we only
	// open if len is 0 or not exist.
	let len = match std::fs::metadata(path) {
		Ok(meta) => meta.len(),
		Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
		Err(e) => return Err(e),
	};
	if len > 0 {
		return Ok(());
	}
	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.write(true)
		.truncate(false)
		.open(path)?;
	// Check again for good measure (this is still not race-free)
	if file.metadata()?.len() == 0 {
		file.write_all(DEFAULT_CONFIG)?;
	}
	Ok(())
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
	prompter: Option<String>,
	config_path: PathBuf,
	/// Expanded sandbox paths marked `ignore: true` in the config.  Any
	/// request whose resolved path equals or sits under one of these is
	/// passed through unmediated (no mount, prompt, or denial).  Replaced
	/// on every config (re)load.
	ignore_paths: Mutex<Vec<Vec<u8>>>,
	/// The command (program and arguments) being run inside the sandbox,
	/// forwarded to the prompter for display.
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

struct ConfigWatcher {
	inotify: Inotify,
	file_name: OsString,
}

fn watch_config_file(path: &Path) -> io::Result<ConfigWatcher> {
	let parent = path
		.parent()
		.filter(|parent| !parent.as_os_str().is_empty())
		.unwrap_or_else(|| Path::new("."));
	let file_name = path
		.file_name()
		.ok_or_else(|| io::Error::from_raw_os_error(libc::EISDIR))?
		.to_owned();
	let inotify = Inotify::init()?;
	inotify
		.watches()
		.add(parent, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)?;
	Ok(ConfigWatcher { inotify, file_name })
}

fn config_reload_thread(context: &'static Context, mut watcher: ConfigWatcher) {
	let mut buf = [0u8; 4096];
	while !context
		.should_exit
		.load(std::sync::atomic::Ordering::Relaxed)
	{
		let events = match watcher.inotify.read_events(&mut buf) {
			Ok(events) => events,
			Err(err) => {
				match err.kind() {
					io::ErrorKind::WouldBlock => sleep(Duration::from_millis(50)),
					io::ErrorKind::Interrupted => continue,
					_ => {
						error!(
							"error watching config file {:?}: {}",
							context.config_path, err
						);
						break;
					}
				}
				continue;
			}
		};
		let mut should_reload = false;
		for event in events {
			if event
				.mask
				.intersects(EventMask::CLOSE_WRITE | EventMask::MOVED_TO)
			{
				let name = event.name.expect(
					"CLOSE_WRITE and MOVED_TO are both only triggered for contents of the watched dir",
				);
				if name == &watcher.file_name {
					should_reload = true;
					break;
				}
			}
			if event.mask.contains(EventMask::Q_OVERFLOW) {
				should_reload = true;
				break;
			}
		}
		if should_reload {
			info!("reloading config {:?} due to changes", context.config_path);
			if let Err(e) = load_config_into_sandboxes(context) {
				error!(
					"error reloading config from {:?}: {}",
					context.config_path, e
				);
			}
		}
	}
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
/// Note that a trailing slash on `path` also forces the final component
/// to be followed regardless of `follow_final`, since the kernel must
/// resolve it to a directory.
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
	// A trailing slash forces the kernel to follow the final component
	// (it must resolve to a directory) even when AT_SYMLINK_NOFOLLOW /
	// O_NOFOLLOW was requested.  In that case the leaf behaves like an
	// intermediate component and must be mirrored too.
	let follow_final = follow_final || path.to_bytes().ends_with(b"/");
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

/// Whether `abspath` is equal to, or nested under, one of the
/// `ignore_paths` (each an absolute, expanded byte path with no trailing
/// slash).  Used to pass `ignore: true` requests through unmediated.
fn path_is_ignored(ignore_paths: &[Vec<u8>], abspath: &[u8]) -> bool {
	ignore_paths.iter().any(|prefix| {
		if prefix.as_slice() == b"/" {
			// Ignoring "/" ignores the whole tree.
			return true;
		}
		abspath == prefix.as_slice()
			|| (abspath.len() > prefix.len()
				&& abspath.starts_with(prefix)
				&& abspath[prefix.len()] == b'/')
	})
}

/// Create a redirect target on the host if it does not yet exist.
///
/// A "redirect" is a rule whose mount source (`host_path`) differs from
/// its sandbox path (e.g. mapping `/dev/shm` to `/tmp/anki-shm`).  If the
/// host source does not exist the bind mount would fail, so create it
/// here, before the mounts are built.  The new entry mirrors the sandbox
/// path's type on the host (a regular file when the sandbox path is a
/// regular file, otherwise a directory), defaulting to a directory.
fn create_missing_redirect_target(sandbox_path: &OsStr, host_path: &CStr) -> io::Result<()> {
	// Only for genuine redirects (source differs from the sandbox path);
	// real paths that happen to be missing should not be conjured up.
	if host_path.to_bytes() == sandbox_path.as_bytes() {
		return Ok(());
	}
	let host = Path::new(OsStr::from_bytes(host_path.to_bytes()));
	// If the target already exists as anything (file, directory, symlink,
	// ...), leave it untouched.
	if host.symlink_metadata().is_ok() {
		return Ok(());
	}
	let as_file = std::fs::metadata(sandbox_path)
		.map(|m| m.is_file())
		.unwrap_or(false);
	if as_file {
		if let Some(parent) = host.parent() {
			std::fs::create_dir_all(parent)?;
		}
		std::fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(host)?;
		debug!("created missing redirect target file {:?}", host);
	} else {
		std::fs::create_dir_all(host)?;
		debug!("created missing redirect target directory {:?}", host);
	}
	Ok(())
}

/// (Re)load the user config file referenced by `context.config_path` and apply it to the sandbox
/// and the path resolution sandbox, replacing the current mount/placeholder set.  Used both at
/// startup and when a prompter requests a config reload.
fn load_config_into_sandboxes(context: &Context) -> Result<(), Box<dyn std::error::Error>> {
	let cfg = Config::load(&context.config_path)?;
	let resolved_entries = cfg.parse_entries()?;
	if resolved_entries.is_empty() {
		info!(
			"config file {:?} has no rules; sandbox will start empty",
			context.config_path
		);
	}
	// Create any redirect targets that don't exist on the host yet, so the
	// bind mounts below have a source to bind from.  Done before building
	// the mount list.
	for e in &resolved_entries {
		if let Some(m) = &e.mount {
			if let Err(err) =
				create_missing_redirect_target(e.sandbox_path.as_os_str(), &m.host_path)
			{
				error!(
					"could not create redirect target {:?} for {:?}: {}",
					m.host_path, e.sandbox_path, err
				);
			}
		}
	}
	let mut entries: Vec<(&OsStr, ManagedTreeEntry)> = Vec::with_capacity(resolved_entries.len());
	let mut ignore_paths: Vec<Vec<u8>> = Vec::new();
	for e in &resolved_entries {
		// An ignore flag is independent of any mount/placeholder: a rule
		// can both grant access and pass through what it does not cover.
		if e.ignore {
			ignore_paths.push(e.sandbox_path.as_bytes().to_vec());
		}
		let entry = match (&e.mount, &e.placeholder_host_path) {
			(Some(m), _) => ManagedTreeEntry::BindMount(m.clone()),
			(None, Some(ph)) => ManagedTreeEntry::Placeholder(build_resolve_placeholder(ph)?),
			// Ignore-only rule: nothing to add to the mount tree.
			(None, None) => continue,
		};
		entries.push((e.sandbox_path.as_os_str(), entry));
	}
	let mut ignore_paths_lock = context.ignore_paths.lock().unwrap();
	let mut path_res_entries: Vec<(&OsStr, ManagedTreeEntry)> = Vec::new();
	path_res_entries.push((
		OsStr::new("/"),
		ManagedTreeEntry::BindMount(ManagedMountPoint {
			host_path: CString::new("/").unwrap(),
			attrs: MountAttributes {
				readonly: true,
				noexec: true,
			},
		}),
	));
	for (sb_path, ent) in &entries {
		match ent {
			ManagedTreeEntry::BindMount(ManagedMountPoint { host_path, .. }) => {
				if host_path.to_bytes() != sb_path.as_bytes() {
					path_res_entries.push((
						sb_path,
						ManagedTreeEntry::BindMount(ManagedMountPoint {
							host_path: host_path.clone(),
							attrs: MountAttributes::rwx(),
						}),
					));
				}
			}
			ManagedTreeEntry::Placeholder(_) => {}
		}
	}
	fn print_errs(errs: &[(OsString, BindMountSandboxError)]) {
		for (path, err) in errs {
			error!("  {:?}: {}", path, err);
		}
	}
	let mut errs = context.path_res_sandbox.update_from_list(path_res_entries);
	if !errs.is_empty() {
		error!("errors applying config to path resolution sandbox:");
		print_errs(&errs);
		return Err(Box::new(errs.swap_remove(0).1));
	}
	errs = context.sandbox.update_from_list(entries);
	if !errs.is_empty() {
		error!("errors applying config to sandbox:");
		print_errs(&errs);
		return Err(Box::new(errs.swap_remove(0).1));
	}
	*ignore_paths_lock = ignore_paths;
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
		match load_config_into_sandboxes(context) {
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

fn has_inode_permission(
	statx: &libc::statx,
	our_uid: libc::uid_t,
	our_gid: libc::gid_t,
	need_read: bool,
	need_write: bool,
	need_exec: bool,
) -> bool {
	let mode = u32::from(statx.stx_mode);
	// Linux permissions are not "cumulative".  In other words, if uid is
	// equal, the group permission is not used, etc.
	let permissions = if statx.stx_uid == our_uid {
		(mode >> 6) & 0o7
	} else if statx.stx_gid == our_gid {
		(mode >> 3) & 0o7
	} else {
		mode & 0o7
	};

	(!need_read || permissions & 0o4 != 0)
		&& (!need_write || permissions & 0o2 != 0)
		&& (!need_exec || permissions & 0o1 != 0)
}

fn tracing_thread(context: &'static Context) {
	if let Err(e) = context.tracer.receive_notify_fd() {
		error!("error receiving notify fd: {}", e);
		std::process::exit(1);
	}
	let uid = unsafe { libc::getuid() };
	let gid = unsafe { libc::getgid() };
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
							// This is the fd opened in the path resolution sandbox (which is not
							// the host).  The path resolution sandbox is allowed to access
							// everything, but still has any redirects applied.
							let t_pres = match rwxp.target.in_root(resolve_sandbox_root.as_raw_fd())
							{
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
							// For a create-like directory operation, if the
							// target entry itself already exists and is already
							// covered, the continued syscall will just open the
							// existing entry or fail with EEXIST - neither needs
							// access on the parent directory.  Short-circuit so we
							// don't spuriously prompt for (or deny on) the parent,
							// e.g. creating /dev/null when /dev/null is mounted
							// but /dev is not.  Only open(O_CREAT) / mkdir /
							// symlink / mknod qualify (a dir-op on FsOpen /
							// FsCreate); ops that genuinely mutate the parent
							// (unlink / rename / link) are excluded.
							if rwxp.is_dir_op
								&& matches!(fsop, FsOperation::FsOpen(_) | FsOperation::FsCreate(_))
								&& let Ok(leaf_fd) = t_pres.open_target()
								&& let Ok(leaf_path) = leaf_fd.readlink()
							{
								let mut bytes = leaf_path.into_encoded_bytes();
								bytes.push(b'\0');
								let leaf_abspath = CString::from_vec_with_nul(bytes).unwrap();
								if leaf_abspath.as_bytes() != b"/"
									&& matches!(
										check_covered_or_placeholder(
											&context.sandbox,
											&leaf_abspath,
											rwxp.write,
											rwxp.exec,
											false,
										),
										Ok((true, _))
									) {
									debug!(
										"{} target {:?} already exists and is covered; \
										 not requiring parent access",
										rwxp, leaf_abspath
									);
									if let Err(e) = create_symlinks_for_user_path(
										&context.sandbox,
										t_pres.dfd(),
										t_pres.path(),
										!t_pres.no_follow(),
									) {
										debug!("could not mirror symlinks for {}: {}", rwxp, e);
									}
									continue;
								}
							}
							let target_fd = if rwxp.is_dir_op {
								t_pres.open_target_dir().map(|x| x.0)
							} else {
								t_pres.open_target()
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
									io::ErrorKind::NotADirectory => {
										debug!("ENOTDIR opening target for {}: {}", rwxp, e);
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
							let target_fd = target_fd.unwrap();
							let sandbox_abspath = match target_fd.readlink() {
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
							if !sandbox_abspath.as_bytes().starts_with(b"/") {
								check_req_valid!();
								// might be sockets etc
								debug!(
									"{} resolved to non-absolute path {:?}",
									rwxp, sandbox_abspath
								);
								break;
							}
							if sandbox_abspath.as_bytes() == b"/" {
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
							//
							// TODO: this currently only cares about the absolute path of the
							// target, but really if the sandboxed program used a symlink to reach
							// the target, we should enforce that that symlink has to be covered too
							// (either with a mount or placeholder).  Currently we auto-creates it.
							//
							// Probably we should just get rid of create_symlinks_for_user_path, and
							// create a method on BindMountSandbox that's like a more complete
							// version of "check_covered" / "has_placeholder" that replicates the
							// path resolution logic to get the last "uncovered" target (either the
							// symlink, its target, or its target's target, etc until we get the
							// final one), and returns
							// enum {
							//   CoveredBy(ManagedTreeEntry),
							//   MissingSymlink(OsString),
							//   MissingTarget(OsString),
							// }
							// it then needs to be passed the original sandbox path, and no_follow: bool
							// or maybe just takes the FsTarget
							let cover = check_covered_or_placeholder(
								&context.sandbox,
								&sandbox_abspath,
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
										t_pres,
									);
									add_symlinks = true;
								}
								Ok(false) => {
									check_req_valid!();
									// If the target is, or sits under, a path configured with
									// `ignore: true`, don't do anything.  For on-directory
									// operations like create, we match on the full target path
									// including the leaf to be created, so that ignore rules can be
									// specific to target files.
									let ignore_paths = context.ignore_paths.lock().unwrap();
									let ignored =
										path_is_ignored(&ignore_paths, sandbox_abspath.as_bytes());
									drop(ignore_paths);
									if ignored {
										debug!(
											"{} not covered but under an ignored path; \
											 passing through",
											rwxp
										);
										force_continue = true;
										break;
									}
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
										t_pres,
									);
									let d = denials.get_mut_or_insert(
										OsStr::from_bytes(sandbox_abspath.as_bytes()),
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
										// First, don't prompt if we don't have the
										// requested inode access anyway on the file.
										if !matches!(fsop, FsOperation::FsChmod(_))
											&& let Ok(statx) = target_fd.statx(
												libc::STATX_UID
													| libc::STATX_GID | libc::STATX_MODE,
											) && !has_inode_permission(
											&statx, uid, gid, rwxp.read, rwxp.write, rwxp.exec,
										) {
											force_continue = true;
											debug!(
												"{}[{}] target {} does not have the requested inode permissions; \
												 not prompting",
												req_ctx
													.comm()
													.unwrap_or_else(|_| OsString::from("???"))
													.to_string_lossy(),
												req_ctx.pid(),
												t_pres,
											);
											break;
										}
										// Ask the prompter what to do.  We prompt at
										// most once per syscall, sending all of its
										// rwx permissions; the mounts / placeholders
										// the prompter adds may then also cover the
										// remaining permissions of this same syscall.
										if !prompted {
											prompted = true;
											// Resolve every target into the real
											// host root so the prompter receives
											// canonical host realpaths.  The
											// in-sandbox targets often don't
											// resolve yet (e.g. a not-yet-created
											// dir, or a path whose parent is not
											// materialised in the sandbox) and
											// would serialize as invalid,
											// unresolved paths.
											let resolved_rwxps: Vec<RwxPermission> = rwxps
												.iter()
												.map(|p| {
													let mut p = p.clone();
													match p
														.target
														.in_root(resolve_sandbox_root.as_raw_fd())
													{
														Ok(t) => p.target = t,
														Err(e) => debug!(
															"could not resolve {} in real \
															 root for prompter: {}",
															p, e
														),
													}
													p
												})
												.collect();
											match prompt_for_request(
												context,
												program,
												&mut req_ctx,
												&request,
												resolved_rwxps,
											) {
												Some(response) => {
													apply_prompter_response(
														context, &response, &t_pres,
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
									t_pres.dfd(),
									t_pres.path(),
									!t_pres.no_follow(),
								) {
									debug!("could not mirror symlinks for {}: {}", rwxp, e);
								}
							}
							if add_placeholder {
								// Resolve-only access (e.g.  realpath / readlink on intermediate path
								// components, stat-only lookup).  No permission to grant, but we do need to
								// make the path resolvable inside the sandbox by mirroring the host entry's
								// type as a placeholder.
								let ph = match build_resolve_placeholder(&sandbox_abspath) {
									Ok(ph) => ph,
									Err(e) => {
										debug!(
											"could not build resolve placeholder for {:?}: {}",
											sandbox_abspath, e
										);
										continue;
									}
								};
								if let Err(e) = context.sandbox.add_or_update_placeholder(
									OsStr::from_bytes(sandbox_abspath.as_bytes()),
									ph,
								) {
									error!(
										"error adding resolve placeholder for {:?}: {}",
										sandbox_abspath, e
									);
								} else {
									debug!("added resolve placeholder for {:?}", sandbox_abspath);
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
									.filter(|mp| mp.host_path == sandbox_abspath)
									.cloned();
								let ancestor =
									covering.filter(|mp| mp.host_path != sandbox_abspath);
								let mut mp = exact.unwrap_or_else(|| ManagedMountPoint {
									host_path: sandbox_abspath.clone(),
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
								match context.sandbox.add_or_update_mount(
									OsStr::from_bytes(sandbox_abspath.as_bytes()),
									mp,
								) {
									Ok(()) => {
										// Propagate the (possibly newly granted)
										// access down to any existing, more
										// restrictive descendant mounts.
										inherit_attrs_to_descendants(
											&context.sandbox,
											&sandbox_abspath,
											new_attrs,
										);
									}
									Err(e) => {
										error!(
											"error updating mount for {:?}: {}",
											sandbox_abspath, e
										);
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
			Ok(None) => {
				debug!("yield_request: Ok(None)");
			}
			Err(e) => {
				debug!("error yielding request: {}", e);
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

fn main() {
	common::init_logger();

	let cli = Cli::parse();

	if [cli.permissive, cli.prompter.is_some(), cli.qt_prompter]
		.into_iter()
		.filter(|&b| b)
		.count()
		> 1
	{
		eprintln!("--permissive, --prompter, and --qt-prompter are mutually exclusive");
		std::process::exit(1);
	}
	if cli.default_config {
		write_default_config_if_empty(&cli.config).unwrap_or_else(|e| {
			eprintln!("Unable to write default config: {}", e);
			std::process::exit(1);
		});
	}

	let sandbox = ManagedBindMountSandbox::new(SandboxOptions {
		disable_userns: cli.block_nested_userns,
	})
	.unwrap_or_else(|e| {
		eprintln!("Unable to create sandbox: {}", e);
		std::process::exit(1);
	});
	let path_res_sandbox = ManagedBindMountSandbox::new(SandboxOptions {
		disable_userns: true,
	})
	.unwrap_or_else(|e| {
		eprintln!("Unable to create path resolution sandbox: {}", e);
		std::process::exit(1);
	});
	let mut prompter = cli.prompter.clone();
	let mut qt_prompter_memfd = -1;
	if cli.qt_prompter {
		unsafe {
			qt_prompter_memfd = libc::memfd_create(
				c"qt_prompter/main.py".as_ptr(),
				libc::MFD_ALLOW_SEALING | libc::MFD_EXEC,
			);
			if qt_prompter_memfd < 0 && libc::__errno_location().read() == libc::EINVAL {
				// no MFD_EXEC?
				qt_prompter_memfd =
					libc::memfd_create(c"qt_prompter/main.py".as_ptr(), libc::MFD_ALLOW_SEALING);
			}
			if qt_prompter_memfd < 0 {
				eprintln!(
					"Unable to create memfd for qt prompter: {}",
					io::Error::last_os_error()
				);
				std::process::exit(1);
			}
		}
		let mut write_pos = 0;
		while write_pos < QT_PROMPTER_SCRIPT.len() {
			let written = unsafe {
				libc::write(
					qt_prompter_memfd,
					QT_PROMPTER_SCRIPT[write_pos..].as_ptr() as *const libc::c_void,
					QT_PROMPTER_SCRIPT.len() - write_pos,
				)
			};
			if written < 0 {
				eprintln!(
					"Unable to write qt prompter to memfd: {}",
					io::Error::last_os_error()
				);
				std::process::exit(1);
			}
			write_pos += written as usize;
		}
		unsafe {
			let res = libc::fcntl(
				qt_prompter_memfd,
				libc::F_ADD_SEALS,
				libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
			);
			if res < 0 {
				eprintln!(
					"Unable to seal qt prompter memfd: {}",
					io::Error::last_os_error()
				);
				std::process::exit(1);
			}
		}
		prompter = Some(format!("/proc/self/fd/{}", qt_prompter_memfd));
	}

	let context: &'static Context = Box::leak(Box::new(Context {
		sandbox,
		path_res_sandbox,
		tracer: TurnstileTracer::new(TracerOptions::default()).unwrap_or_else(|e| {
			eprintln!("Unable to create seccomp-unotify tracer: {}", e);
			std::process::exit(1);
		}),
		pidfd: OnceLock::new(),
		should_exit: AtomicBool::new(false),
		permissive: cli.permissive,
		prompter,
		config_path: cli.config.clone(),
		ignore_paths: Mutex::new(Vec::new()),
		sandbox_cmd: cli
			.command
			.iter()
			.map(|s| s.to_string_lossy().into_owned())
			.collect(),
		sandbox_id: cli.sandbox_id.unwrap_or_else(random_sandbox_id),
	}));

	let config_watcher = watch_config_file(&context.config_path).unwrap_or_else(|e| {
		eprintln!("Unable to watch config file: {}", e);
		std::process::exit(1);
	});
	load_config_into_sandboxes(context).unwrap_or_else(|e| {
		eprintln!("Unable to load config: {}", e);
		std::process::exit(1);
	});
	let config_reload_thread = thread::spawn(move || config_reload_thread(context, config_watcher));

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);
	unsafe {
		if qt_prompter_memfd >= 0 {
			cmd.pre_exec(move || {
				if libc::close(qt_prompter_memfd) < 0 {
					Err(io::Error::last_os_error())
				} else {
					Ok(())
				}
			});
		}
		cmd.pre_exec(|| {
			context
				.tracer
				.install_filters(true)
				.map_err(|_| io::ErrorKind::Other.into())
		});
	}
	let tracing_thread = thread::spawn(move || tracing_thread(context));
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
			config_reload_thread.join().unwrap();
			std::process::exit(1);
		}
	};
	let child_pid = res.id();
	info!("Spawned child process with pid {}", child_pid);
	context
		.pidfd
		.set(ProcPidFd::from_pid(child_pid).unwrap_or_else(|e| {
			eprintln!("Unable to acquire pidfd to child: {}", e);
			std::process::exit(1);
		}))
		.unwrap();
	let res = res.wait().unwrap_or_else(|e| {
		eprintln!("error calling wait() on child: {}", e);
		std::process::exit(1);
	});
	if res.success() {
		info!("Child process exited successfully");
	} else {
		error!("Child process exited with error: {:?}", res);
	}
	context
		.should_exit
		.store(true, std::sync::atomic::Ordering::Relaxed);
	tracing_thread.join().unwrap();
	config_reload_thread.join().unwrap();
}

#[cfg(test)]
mod tests {
	use super::{
		Cli, DEFAULT_CONFIG, create_missing_redirect_target, has_inode_permission, path_is_ignored,
		write_default_config_if_empty,
	};
	use clap::Parser;
	use std::ffi::CString;
	use std::os::unix::ffi::OsStrExt;

	#[test]
	fn parses_optional_sandbox_id() {
		let cli = Cli::try_parse_from([
			"turnstile-sandbox",
			"--sandbox-id",
			"12345",
			"config.yaml",
			"command",
		])
		.unwrap();
		assert_eq!(cli.sandbox_id, Some(12345));

		let cli = Cli::try_parse_from(["turnstile-sandbox", "config.yaml", "command"]).unwrap();
		assert_eq!(cli.sandbox_id, None);
	}

	#[test]
	fn writes_default_config_only_for_missing_or_empty_files() {
		let tmp = std::env::temp_dir().join(format!(
			"turnstile-default-config-test-{}",
			std::process::id()
		));
		let _ = std::fs::remove_dir_all(&tmp);
		std::fs::create_dir_all(&tmp).unwrap();

		let missing = tmp.join("missing.yaml");
		write_default_config_if_empty(&missing).unwrap();
		assert_eq!(std::fs::read(&missing).unwrap(), DEFAULT_CONFIG);

		let empty = tmp.join("empty.yaml");
		std::fs::write(&empty, "").unwrap();
		write_default_config_if_empty(&empty).unwrap();
		assert_eq!(std::fs::read(&empty).unwrap(), DEFAULT_CONFIG);

		let existing = tmp.join("existing.yaml");
		std::fs::write(&existing, "rules: {}\n").unwrap();
		write_default_config_if_empty(&existing).unwrap();
		assert_eq!(std::fs::read(&existing).unwrap(), b"rules: {}\n");

		std::fs::remove_dir_all(&tmp).unwrap();
	}

	#[test]
	fn ignore_exact_and_descendants() {
		let ignored = vec![b"/proc".to_vec(), b"/run/user/1000".to_vec()];
		assert!(path_is_ignored(&ignored, b"/proc"));
		assert!(path_is_ignored(&ignored, b"/proc/self/status"));
		assert!(path_is_ignored(&ignored, b"/run/user/1000/bus"));
		// A sibling sharing a name prefix is not under the ignored path.
		assert!(!path_is_ignored(&ignored, b"/proc2"));
		assert!(!path_is_ignored(&ignored, b"/procfoo"));
		assert!(!path_is_ignored(&ignored, b"/run/user/10001"));
		assert!(!path_is_ignored(&ignored, b"/etc"));
	}

	#[test]
	fn ignore_root_matches_everything() {
		let ignored = vec![b"/".to_vec()];
		assert!(path_is_ignored(&ignored, b"/"));
		assert!(path_is_ignored(&ignored, b"/anything/at/all"));
	}

	#[test]
	fn ignore_empty_list_matches_nothing() {
		assert!(!path_is_ignored(&[], b"/proc"));
	}

	#[test]
	fn inode_permissions_use_the_matching_mode_class() {
		let mut statx: libc::statx = unsafe { std::mem::zeroed() };
		statx.stx_uid = 1000;
		statx.stx_gid = 100;
		statx.stx_mode = 0o642;

		assert!(has_inode_permission(&statx, 1000, 999, true, true, false));
		assert!(!has_inode_permission(&statx, 1000, 100, false, false, true));
		assert!(has_inode_permission(&statx, 2000, 100, true, false, false));
		assert!(!has_inode_permission(&statx, 2000, 100, false, true, false));
		assert!(has_inode_permission(&statx, 2000, 200, false, true, false));
	}

	#[test]
	fn inode_permissions_require_every_requested_bit_from_one_class() {
		let mut statx: libc::statx = unsafe { std::mem::zeroed() };
		statx.stx_uid = 1000;
		statx.stx_gid = 100;
		statx.stx_mode = 0o421;

		assert!(has_inode_permission(&statx, 1000, 100, false, false, false));
		assert!(!has_inode_permission(&statx, 1000, 100, true, false, true));
		assert!(!has_inode_permission(&statx, 2000, 100, true, true, false));
		assert!(!has_inode_permission(&statx, 2000, 200, false, true, true));
	}

	#[test]
	fn create_redirect_target_dir_file_and_skip() {
		let tmp = std::env::temp_dir().join(format!("turnstile-rt-test-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&tmp);
		std::fs::create_dir_all(&tmp).unwrap();
		let c = |p: &std::path::Path| CString::new(p.as_os_str().as_bytes()).unwrap();

		// Sandbox path is an existing directory -> target created as a dir.
		let src_dir = tmp.join("srcdir");
		std::fs::create_dir_all(&src_dir).unwrap();
		let dst_dir = tmp.join("nested/dstdir");
		create_missing_redirect_target(src_dir.as_os_str(), &c(&dst_dir)).unwrap();
		assert!(dst_dir.is_dir());

		// Sandbox path is an existing file -> target created as a file.
		let src_file = tmp.join("srcfile");
		std::fs::write(&src_file, b"x").unwrap();
		let dst_file = tmp.join("sub/dstfile");
		create_missing_redirect_target(src_file.as_os_str(), &c(&dst_file)).unwrap();
		assert!(dst_file.is_file());

		// Not a redirect (host == sandbox) -> nothing is created.
		let none = tmp.join("nope");
		create_missing_redirect_target(none.as_os_str(), &c(&none)).unwrap();
		assert!(!none.exists());

		std::fs::remove_dir_all(&tmp).unwrap();
	}
}
