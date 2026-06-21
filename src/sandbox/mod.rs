use std::{
	borrow::Cow,
	collections::HashMap,
	ffi::{CStr, CString, OsStr, OsString},
	io::{self, Write},
	mem,
	os::{
		fd::{AsRawFd, IntoRawFd},
		unix::{ffi::OsStrExt, process::CommandExt},
	},
	sync::Mutex,
	thread,
};

use log::{debug, error, info, warn};

use crate::{
	BindMountSandboxError,
	access::fs::ForeignFd,
	fstree::FsTree,
	utils::{fork_wait, unix_recv_fd, unix_send_fd},
};

/// We technically can't safely log or format strings in fork or pre_exec
/// context, but to make our life easier we will do it anyway in debug
/// builds.
const ENABLE_LOG_IN_FORK: bool = cfg!(debug_assertions);

/// Generate a process-unique scratch directory name for parking a mount
/// into the hidden scratch tmpfs (see [`BindMountSandbox::park_to_scratch`]).
/// The name need only be unique among concurrently-parked mounts within
/// this process; a monotonic counter combined with the pid suffices.
fn next_scratch_name() -> CString {
	use std::sync::atomic::{AtomicU64, Ordering};
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	let n = COUNTER.fetch_add(1, Ordering::Relaxed);
	let pid = unsafe { libc::getpid() };
	CString::new(format!("park-{pid}-{n}")).expect("no NUL in generated name")
}

/// Call umount("/proc/self/fd/<fd>", MNT_DETACH) in a async-signal-safe
/// manner.
unsafe fn umount_detach_fd(fd: libc::c_int) {
	const PREFIX: &[u8] = b"/proc/self/fd/";
	let mut buf = [0u8; PREFIX.len() + 11];
	buf[..PREFIX.len()].copy_from_slice(PREFIX);
	if let Err(e) = write!(&mut buf[PREFIX.len()..], "{}", fd) {
		if ENABLE_LOG_IN_FORK {
			error!("Failed to format fd path for umount: {}", e);
		}
		unsafe { libc::_exit(1) };
	}
	unsafe {
		if libc::umount2(buf.as_ptr() as *const libc::c_char, libc::MNT_DETACH) != 0
			&& ENABLE_LOG_IN_FORK
		{
			error!(
				"umount2(MNT_DETACH) of unmovable child failed: errno {}",
				libc::__errno_location().read()
			);
		}
	}
}
macro_rules! perror {
	($s:literal) => {{
		let err = libc::__errno_location().read();
		if ENABLE_LOG_IN_FORK {
			let strerr = libc::strerror(err);
			error!(
				concat!($s, ": errno {} ({:#?})"),
				err,
				std::ffi::CStr::from_ptr(strerr)
			);
		}
		err
	}};
}

mod mount_obj;
mod mountinfo;
mod namespace;
mod upgrade;
mod utils;

use mount_obj::MountObj;
use namespace::ManagedNamespaces;
pub use upgrade::RequestHandle;
use utils::{split_parent_leaf, validate_sandbox_path};

fn write_to_path(path: &CStr, content: &str) -> libc::c_int {
	unsafe {
		let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
		if fd < 0 {
			let err = perror!("open");
			if ENABLE_LOG_IN_FORK {
				error!("Failed to open {:#?} for writing: errno {}", path, err);
			}
			return err;
		}
		let bytes = content.as_bytes();
		let write_res = libc::write(fd, bytes.as_ptr() as *const _, bytes.len());
		if write_res < 0 {
			let err = perror!("write");
			libc::close(fd);
			return err;
		}
		if write_res as usize != bytes.len() {
			if ENABLE_LOG_IN_FORK {
				error!(
					"Short write to {:#?}: expected {} bytes, wrote {} bytes",
					path,
					bytes.len(),
					write_res
				);
			}
			libc::close(fd);
			return libc::EAGAIN;
		}
		libc::close(fd);
		0
	}
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MountAttributes {
	pub readonly: bool,
	pub noexec: bool,
}

impl MountAttributes {
	pub fn rwx() -> Self {
		Self {
			readonly: false,
			noexec: false,
		}
	}
	pub fn rx() -> Self {
		Self {
			readonly: true,
			noexec: false,
		}
	}
	pub fn ro() -> Self {
		Self {
			readonly: true,
			noexec: true,
		}
	}
	pub fn rw() -> Self {
		Self {
			readonly: false,
			noexec: true,
		}
	}
}

impl std::fmt::Display for MountAttributes {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.readonly {
			write!(f, "ro")?;
		} else {
			write!(f, "rw")?;
		}
		if self.noexec {
			write!(f, ",noexec")?;
		}
		Ok(())
	}
}

/// Implements a basic bind-mount based sandbox.
#[derive(Debug)]
pub struct BindMountSandbox {
	namespaces: ManagedNamespaces,
	/// A fd to the placeholder tmpfs opened inside m0 (the outer mount
	/// namespace).
	root_tmpfs: MountObj,
	/// O_PATH fd to the actual, outside-sandbox "/" opened inside m0.  Used as
	/// the dirfd when resolving caller-provided host paths so that the
	/// resulting fd is associated with m0's mount namespace and is therefore
	/// acceptable to `open_tree()` once the helper process enters m0.
	host_root_fd: ForeignFd,
	/// O_PATH fd to the scratch tmpfs root inside m1.  The scratch is a
	/// separate tmpfs (distinct from `root_tmpfs`) that is first mounted
	/// into m1, and then by mounting root_tmpfs on top, it eventually is
	/// shadowed, so the sandboxed app never sees it.  It is used by
	/// [`Self::park_to_scratch`] to temporarily park a mount, in order to
	/// unmount a parent, before moving it back.
	m1_scratch_fd: ForeignFd,
}

#[derive(Debug)]
pub struct MountBuilder<'a, 'b> {
	host_path: &'a CStr,
	sandbox_path: &'a CStr,
	attrs: MountAttributes,
	follow_host_symlinks: bool,
	// follow_sandbox_symlinks: bool,
	sandbox: &'b BindMountSandbox,
}

impl<'a, 'b> MountBuilder<'a, 'b> {
	pub fn attributes(&mut self, attrs: MountAttributes) -> &mut Self {
		self.attrs = attrs;
		self
	}

	/// If host path points into a location controllable or writable by
	/// the sandboxed process, this must not be used.  This only affects
	/// the path resolution for the "source" side - symlinks are still not
	/// followed when resolving the mount destination.
	pub fn follow_host_symlinks(&mut self, follow: bool) -> &mut Self {
		self.follow_host_symlinks = follow;
		self
	}

	// pub fn follow_sandbox_symlinks(&mut self, follow: bool) -> &mut Self {
	// 	self.follow_sandbox_symlinks = follow;
	// 	self
	// }

	pub fn mount(self) -> Result<(), BindMountSandboxError> {
		self.sandbox
			.mount_host_into_sandbox_impl(
				self.host_path,
				self.sandbox_path,
				self.attrs,
				self.follow_host_symlinks,
				// self.follow_sandbox_symlinks,
				false,
				true,
			)
			.map(|_| ())
	}
}

fn restrict_self_impl<F: FnOnce() -> Result<(), std::io::Error>>(
	nsenter_fn: F,
	new_cwd_cstr: Option<&CStr>,
) -> Result<(), std::io::Error> {
	match nsenter_fn() {
		Ok(()) => (),
		Err(e) => {
			if ENABLE_LOG_IN_FORK {
				error!("Failed to enter namespaces: {}", e);
			}
			return Err(e);
		}
	}
	if let Some(new_cwd_cstr) = new_cwd_cstr {
		unsafe {
			let res = libc::chdir(new_cwd_cstr.as_ptr());
			if res != 0 {
				let err = perror!("chdir");
				if ENABLE_LOG_IN_FORK {
					error!("Failed to chdir to {:?}: errno {}", new_cwd_cstr, err);
				}
				return Err(io::Error::from_raw_os_error(err));
			}
		}
	}
	Ok(())
}

unsafe fn send_fd_from_ns<
	F1: FnOnce() -> Result<(), std::io::Error> + Send,
	F2: FnOnce() -> Result<libc::c_int, std::io::Error> + Send,
	E: FnOnce(libc::c_int) -> BindMountSandboxError,
>(
	nsenter_fn: F1,
	acquire_fd: F2,
	map_err: E,
) -> Result<libc::c_int, BindMountSandboxError> {
	unsafe {
		thread::scope(|s| {
			let mut sock = [-1i32; 2];
			let res = libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				sock.as_mut_ptr(),
			);
			if res == -1 {
				return Err(BindMountSandboxError::Socketpair(io::Error::last_os_error()));
			}
			let parent_sock = sock[0];
			let child_sock = sock[1];

			let jh = s.spawn(move || {
				let recv_res = unix_recv_fd(parent_sock);
				libc::close(parent_sock);
				recv_res
			});

			let fork_res = fork_wait(|| {
				libc::close(parent_sock);
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces for mount: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				let mut ret = 0;
				match acquire_fd() {
					Ok(fd) => {
						if let Err(e) = unix_send_fd(child_sock, fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send fd to parent: {}", e);
							}
							ret = e.raw_os_error().unwrap_or(libc::EIO)
						}
						libc::close(child_sock);
						libc::close(fd);
						ret
					}
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to acquire fd in child: {}", e);
						}
						libc::close(child_sock);
						e.raw_os_error().unwrap_or(libc::EIO)
					}
				}
			})
			.map_err(BindMountSandboxError::ForkError)?;
			libc::close(child_sock);

			if fork_res != 0 {
				let _ = jh.join().expect("Child thread panicked");
				return Err(map_err(fork_res));
			}
			jh.join()
				.expect("Child thread panicked")
				.map_err(BindMountSandboxError::ReceiveMountFd)
		})
	}
}

impl BindMountSandbox {
	pub fn new(disable_userns: bool) -> Result<Self, BindMountSandboxError> {
		let namespaces = ManagedNamespaces::new(disable_userns)?;
		let root_tmpfs = unsafe {
			let nsenter_fn = namespaces.nsenter_fn(true, true, false, false);
			MountObj::new_from_fd(send_fd_from_ns(
				nsenter_fn,
				|| MountObj::new_tmpfs().map(IntoRawFd::into_raw_fd),
				BindMountSandboxError::MakeDetachedTmpfsMountFailed,
			)?)
		};
		// Open a fd to "/" from inside m0 so that subsequent host path
		// lookups can be performed relative to it, yielding fds that are
		// already associated with m0's mount namespace.
		let host_root_fd = unsafe {
			let nsenter_fn = namespaces.nsenter_fn(true, true, false, false);
			let raw_fd = send_fd_from_ns(
				nsenter_fn,
				|| {
					let fd = libc::open(
						c"/".as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
					);
					if fd < 0 {
						Err(io::Error::last_os_error())
					} else {
						Ok(fd)
					}
				},
				BindMountSandboxError::OpenRootInSandboxFailed,
			)?;
			ForeignFd { local_fd: raw_fd }
		};
		// Create the scratch tmpfs inside m1 and make it m1's root, then
		// capture an O_PATH handle to it.  This happens before the
		// root_tmpfs bind below, so the scratch ends up shadowed beneath
		// the placeholder tmpfs and is invisible to the app.
		let m1_scratch_fd = unsafe {
			// Enter the first user namespace (where the outside uid is
			// mapped to root) and then m1.
			let nsenter_fn = namespaces.nsenter_fn(true, false, true, false);
			let raw_fd = send_fd_from_ns(
				nsenter_fn,
				|| {
					// fsmount a brand-new tmpfs (distinct from root_tmpfs),
					// move_mount it onto "/" of m1, and return its fd.
					let scratch = MountObj::new_tmpfs()?;
					scratch.mount(libc::AT_FDCWD, c"/", false)?;
					Ok(scratch.into_raw_fd())
				},
				BindMountSandboxError::SetupScratchFailed,
			)?;
			ForeignFd { local_fd: raw_fd }
		};
		let s = Self {
			namespaces,
			root_tmpfs,
			host_root_fd,
			m1_scratch_fd,
		};
		// Bind-mount root_tmpfs over m1's "/", shadowing the scratch.
		s.mount_host_into_sandbox_impl(
			CStr::from_bytes_with_nul(
				format!("/proc/self/fd/{}\0", s.root_tmpfs.0.as_raw_fd()).as_bytes(),
			)
			.unwrap(),
			c"/",
			MountAttributes::ro(),
			true,
			false,
			true,
		)?;
		Ok(s)
	}

	/// Create either a file or directory at the given absolute path
	/// within the sandbox's backing tmpfs.  This makes a new empty file
	/// or directory appear within the sandbox, unless the path or any of
	/// its parent directories is already bind-mounted to some other host
	/// path, in which case the new file or directory will not be visible.
	///
	/// If any of the path's parent doesn't exist or is not a directory, a
	/// directory is created in its place (overriding any existing files,
	/// which is sensible since this is a placeholder fs)
	pub fn create_placeholder_hierarchy(
		&self,
		path: &CStr,
		leaf_is_dir: bool,
	) -> Result<ForeignFd, BindMountSandboxError> {
		validate_sandbox_path(path)?;

		let mut fd = self.root_tmpfs.0.clone();
		let components = path
			.to_bytes()
			.split(|&b| b == b'/')
			.filter(|c| !c.is_empty())
			.collect::<Vec<_>>();
		let len = components.len();
		for (i, comp) in components.into_iter().enumerate() {
			let comp = CString::new(comp).unwrap();
			let is_leaf = i == len - 1;
			let want_dir = !is_leaf || leaf_is_dir;
			let placeholder = placeholder_default_no_metadata(want_dir);
			create_or_update_placeholder(fd.as_raw_fd(), &comp, &placeholder)?;
			let newfd = unsafe {
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS;
				if i == 0 {
					openhow.resolve |= libc::RESOLVE_IN_ROOT;
				}
				let raw = libc::syscall(
					libc::SYS_openat2,
					fd.as_raw_fd(),
					comp.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if raw < 0 {
					return Err(BindMountSandboxError::ResolveSandboxPath(
						io::Error::last_os_error(),
					));
				}
				ForeignFd { local_fd: raw }
			};
			fd = newfd;
		}
		Ok(fd)
	}

	/// Create a symlink within the sandbox's backing tmpfs, which will
	/// appear within the sandbox unless the location is already within a
	/// bind-mount.  linkpath must be absolute, but target need not be (as
	/// it usually is, relative paths are interpreted relative to the
	/// symlink's parent directory).
	pub fn create_placeholder_symlink(
		&self,
		linkpath: &CStr,
		target: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(linkpath)?;
		if linkpath.to_bytes() == b"/" {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"cannot create symlink at root",
				linkpath.to_owned(),
			));
		}
		let (parent, child) = split_parent_leaf(linkpath);
		let parent_fd = self.create_placeholder_hierarchy(&parent, true)?;
		let placeholder = placeholder_default_symlink(target.to_owned());
		create_or_update_placeholder(parent_fd.as_raw_fd(), child, &placeholder)?;
		debug!("Created symlink {:?} -> {:?} in sandbox", linkpath, target);
		Ok(())
	}

	/// Remove the given sandbox path from the backing tmpfs, removing
	/// files within the pointed to directory recursively if it's a
	/// directory.  Nothing is done if the path, or any of its parent
	/// components, doesn't exist.
	pub fn remove_placeholder(&self, path: &CStr) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(path)?;

		if path.to_bytes() == b"/" {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"cannot remove root",
				path.to_owned(),
			));
		}
		let (parent_path, leaf) = split_parent_leaf(path);

		let parent_fd = unsafe {
			let mut openhow: libc::open_how = mem::zeroed();
			openhow.flags =
				(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY) as u64;
			// RESOLVE_IN_ROOT and RESOLVE_NO_XDEV are not technically
			// necessary in our setup, but adding for safety.
			openhow.resolve =
				libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_XDEV;
			let fd = libc::syscall(
				libc::SYS_openat2,
				self.root_tmpfs.0.as_raw_fd(),
				parent_path.as_ptr(),
				&openhow as *const _,
				std::mem::size_of::<libc::open_how>(),
			) as libc::c_int;
			if fd < 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					return Ok(());
				}
				return Err(BindMountSandboxError::ResolveSandboxPath(err));
			}
			ForeignFd { local_fd: fd }
		};

		remove_entry_at(parent_fd.as_raw_fd(), leaf)?;

		debug!("Removed {:?} from sandbox tmpfs", path);
		Ok(())
	}

	/// Resolve `host_path` (interpreted relative to the m0 host root) to
	/// an `O_PATH` fd.  Leading slashes are stripped because `openat2`
	/// ignores the dirfd for absolute paths.  Symlinks in the final
	/// component are followed only when `follow_host_symlinks` is set.
	fn resolve_host_path(
		&self,
		host_path: &CStr,
		follow_host_symlinks: bool,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let mut open_how: libc::open_how = unsafe { std::mem::zeroed() };
		open_how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
		if !follow_host_symlinks {
			open_how.flags |= libc::O_NOFOLLOW as u64;
			open_how.resolve |= libc::RESOLVE_NO_SYMLINKS;
		}
		let with_nul = host_path.to_bytes_with_nul();
		let relative_host_path: &CStr = if with_nul.starts_with(b"/") {
			let mut i = 0;
			while i < with_nul.len() - 1 && with_nul[i] == b'/' {
				i += 1;
			}
			if i == with_nul.len() - 1 {
				c"."
			} else {
				CStr::from_bytes_with_nul(&with_nul[i..]).unwrap()
			}
		} else {
			host_path
		};
		let host_fd = unsafe {
			libc::syscall(
				libc::SYS_openat2,
				self.host_root_fd.as_raw_fd(),
				relative_host_path.as_ptr(),
				&open_how,
				std::mem::size_of_val(&open_how),
			) as libc::c_int
		};
		if host_fd < 0 {
			return Err(BindMountSandboxError::ResolveHostPath(
				host_path.to_owned(),
				io::Error::last_os_error(),
			));
		}
		Ok(ForeignFd { local_fd: host_fd })
	}

	// todo: the semantic of follow_ns_symlinks is ill-defined due to use
	// of create_hierarchy, which has no visibility into bind-mounted
	// symlinks
	pub(self) fn mount_host_into_sandbox_impl(
		&self,
		host_path: &CStr,
		ns_path: &CStr,
		attrs: MountAttributes,
		follow_host_symlinks: bool,
		follow_ns_symlinks: bool,
		create_placeholders: bool,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let host_fd = self.resolve_host_path(host_path, follow_host_symlinks)?;

		if create_placeholders {
			let mut stat: libc::stat = unsafe { std::mem::zeroed() };
			if unsafe { libc::fstat(host_fd.as_raw_fd(), &mut stat) } != 0 {
				return Err(BindMountSandboxError::StatHostPath(
					host_path.to_owned(),
					io::Error::last_os_error(),
				));
			}
			self.create_placeholder_hierarchy(
				ns_path,
				stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
			)?;
		}

		let nsenter_fn_m0 = unsafe { self.namespaces.nsenter_fn(true, true, false, false) };
		let nsenter_fn_m1 = unsafe { self.namespaces.nsenter_fn(false, false, true, false) };
		let host_fd_raw = host_fd.as_raw_fd();
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn_m0() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				// host_fd was opened relative to host_root_fd (which was
				// opened inside m0), so it carries m0's mount namespace
				// context and is acceptable to open_tree() here without
				// needing to be reopened.
				let source_tree =
					match MountObj::new_bind(host_fd_raw, c"", attrs, follow_host_symlinks) {
						Ok(tree) => tree,
						Err(e) => {
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					};
				match nsenter_fn_m1() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				match source_tree.mount(libc::AT_FDCWD, ns_path, follow_ns_symlinks) {
					Ok(()) => (),
					Err(e) => {
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to bind mount {:?} to {:?} with {}: errno {}",
				host_path, ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountFailed(fork_res));
		}
		info!("Mount bind {:?} {:?} {}", host_path, ns_path, attrs,);
		Ok(())
	}

	/// Bind-mount `host_path` at `ns_path` while "carrying over" any
	/// existing direct sub-mounts that the new bind would otherwise
	/// shadow.
	///
	/// `child_ns_paths` lists the immediate sub-mounts of `ns_path`.
	///
	/// Roughly, this function does:
	///
	/// - (in m0) `open_tree` the host source.
	/// - (in m1) open an `O_PATH` fd to every child.
	/// - (in m1) `move_mount` the source onto `ns_path` (the children are
	///   now shadowed).
	/// - (in m1) `move_mount` each child back onto its own path resolved
	///   inside the new bind mount.
	///
	/// A child whose mountpoint dentry is absent from the new parent's
	/// host fs cannot be moved back, and so will be unmounted.
	///
	/// With no children this is exactly a plain bind mount.
	pub(self) fn mount_covering(
		&self,
		host_path: &CStr,
		ns_path: &CStr,
		attrs: MountAttributes,
		child_ns_paths: &[CString],
	) -> Result<(), BindMountSandboxError> {
		if child_ns_paths.is_empty() {
			return self
				.mount_host_into_sandbox_impl(host_path, ns_path, attrs, false, false, false);
		}
		validate_sandbox_path(ns_path)?;

		let host_fd = self.resolve_host_path(host_path, false)?;

		// Pre-allocate the fd buffer before we fork so the forked child
		// does not allocate.
		let mut child_fds: Vec<libc::c_int> = vec![-1; child_ns_paths.len()];
		let n_children = child_ns_paths.len();

		let nsenter_fn_m0 = unsafe { self.namespaces.nsenter_fn(true, true, false, false) };
		let nsenter_fn_m1 = unsafe { self.namespaces.nsenter_fn(false, false, true, false) };
		let host_fd_raw = host_fd.as_raw_fd();
		let fork_res = unsafe {
			fork_wait(move || {
				if let Err(e) = nsenter_fn_m0() {
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				let source_tree = match MountObj::new_bind(host_fd_raw, c"", attrs, false) {
					Ok(tree) => tree,
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				};
				if let Err(e) = nsenter_fn_m1() {
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				// Open every child while still reachable.
				let mut child_openhow: libc::open_how = mem::zeroed();
				child_openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				child_openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				for i in 0..n_children {
					let fd = libc::syscall(
						libc::SYS_openat2,
						libc::AT_FDCWD,
						child_ns_paths[i].as_ptr(),
						&child_openhow as *const _,
						std::mem::size_of::<libc::open_how>(),
					) as libc::c_int;
					// A child that can't be opened (already gone) is just
					// skipped; -1 stays in the slot.
					child_fds[i] = fd;
				}
				// Bind the parent over ns_path (shadows the children).
				if let Err(e) = source_tree.mount(libc::AT_FDCWD, ns_path, false) {
					for &fd in &child_fds {
						if fd >= 0 {
							libc::close(fd);
						}
					}
					return e.raw_os_error().unwrap_or(libc::EIO);
				}
				// Move each child back onto its path inside the new bind
				// mount.  If the mountpoint dentry is missing in the new
				// parent the child can't be moved back, so lazily detach
				// it (MNT_DETACH) rather than leaving it shadowed; we
				// don't fail the whole op.
				for i in 0..n_children {
					let fd = child_fds[i];
					if fd < 0 {
						continue;
					}
					let res = libc::syscall(
						libc::SYS_move_mount,
						fd,
						c"".as_ptr(),
						libc::AT_FDCWD,
						child_ns_paths[i].as_ptr(),
						libc::MOVE_MOUNT_F_EMPTY_PATH,
					);
					if res != 0 {
						let err = libc::__errno_location().read();
						if ENABLE_LOG_IN_FORK {
							error!("move_mount(child back) failed: errno {}", err);
						}
						umount_detach_fd(fd);
					}
					libc::close(fd);
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to mount (covering) {:?} to {:?} with {}: errno {}",
				host_path, ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountFailed(fork_res));
		}
		info!(
			"Mount bind (covering {} children) {:?} {:?} {}",
			n_children, host_path, ns_path, attrs
		);
		Ok(())
	}

	/// Open the parent directory of `sandbox_path` within the backing
	/// tmpfs, without creating any intermediate components.  The parent
	/// must already exist.
	pub(self) fn open_sandbox_parent(
		&self,
		sandbox_path: &CStr,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let (parent, _) = split_parent_leaf(sandbox_path);
		if parent.as_c_str() == c"/" {
			let dup =
				unsafe { libc::fcntl(self.root_tmpfs.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
			if dup < 0 {
				return Err(BindMountSandboxError::ResolveSandboxPath(
					io::Error::last_os_error(),
				));
			}
			return Ok(ForeignFd { local_fd: dup });
		}
		unsafe {
			let mut openhow: libc::open_how = mem::zeroed();
			openhow.flags =
				(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY) as u64;
			openhow.resolve =
				libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_XDEV;
			let fd = libc::syscall(
				libc::SYS_openat2,
				self.root_tmpfs.0.as_raw_fd(),
				parent.as_ptr(),
				&openhow as *const _,
				std::mem::size_of::<libc::open_how>(),
			) as libc::c_int;
			if fd < 0 {
				return Err(BindMountSandboxError::ResolveSandboxPath(
					io::Error::last_os_error(),
				));
			}
			Ok(ForeignFd { local_fd: fd })
		}
	}

	pub fn mount_host_into_sandbox<'a, 'b>(
		&'b self,
		host_path: &'a CStr,
		sandbox_path: &'a CStr,
	) -> MountBuilder<'a, 'b> {
		MountBuilder {
			host_path,
			sandbox_path,
			attrs: MountAttributes::default(),
			follow_host_symlinks: false,
			// follow_sandbox_symlinks: false,
			sandbox: self,
		}
	}

	/// Unmount the bind mount at the given absolute path within the
	/// sandbox.  Symlinks are not followed.  The path must not be "/".
	/// The path must have been previously bind-mounted with
	/// [`Self::mount_host_into_sandbox`].
	///
	/// When `forcibly` is false (the default for steady-state
	/// reconcile), a plain `umount2` is used: it fails with `EBUSY` if
	/// the app still holds the mount (an open fd or cwd), which the
	/// caller uses as the source of truth for "still in use".  When
	/// `forcibly` is true, `MNT_DETACH` is added so the unmount always
	/// succeeds, detaching the subtree lazily (held references keep it
	/// alive until they close).
	pub fn unmount(&self, ns_path: &CStr, forcibly: bool) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		if ns_path.to_bytes() == b"/" {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"cannot unmount root",
				ns_path.to_owned(),
			));
		}
		let (parent_path, leaf) = split_parent_leaf(ns_path);

		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let parent_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					parent_path.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if parent_fd < 0 {
					return perror!("openat2(parent)");
				}
				let res = libc::fchdir(parent_fd);
				libc::close(parent_fd);
				if res != 0 {
					return perror!("fchdir");
				}
				let mut flags = libc::UMOUNT_NOFOLLOW;
				if forcibly {
					flags |= libc::MNT_DETACH;
				}
				let res = libc::umount2(leaf.as_ptr(), flags);
				if res != 0 {
					return perror!("umount2");
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			if fork_res != libc::EBUSY {
				error!("Failed to unmount {:?}: errno {}", ns_path, fork_res);
			}
			return Err(BindMountSandboxError::UnmountFailed(fork_res));
		} else {
			info!("Unmounted {:?}", ns_path);
		}
		Ok(())
	}

	/// Update the attributes of an existing mount within the sandbox.
	/// Symlinks are not followed.  Caller should store and pass in the
	/// existing attributes to avoid EPERM errors caused by trying to
	/// clear attributes that we didn't previously set (and thus have no
	/// rights to clear).
	pub fn set_mount_attr(
		&self,
		ns_path: &CStr,
		attrs: MountAttributes,
		existing_attrs: MountAttributes,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return e.raw_os_error().unwrap_or(libc::EIO);
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					ns_path.as_ptr(),
					&openhow,
					std::mem::size_of_val(&openhow),
				) as libc::c_int;
				if fd < 0 {
					return perror!("open");
				}
				let mnt = MountObj::new_from_fd(fd);
				match mnt.setattr(attrs, existing_attrs, 0) {
					Ok(()) => 0,
					Err(e) => e.raw_os_error().unwrap_or(libc::EIO),
				}
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			error!(
				"Failed to set mount attributes for {:?} to {}: errno {}",
				ns_path, attrs, fork_res
			);
			return Err(BindMountSandboxError::MountSetAttrsFailed(fork_res));
		} else {
			info!("Set mount attributes for {:?} to {}", ns_path, attrs);
		}
		Ok(())
	}

	/// Open `path` (absolute, resolved from "/") inside m1, returning an
	/// fd that resolves through m1's *current* mount layout.  `openhow`
	/// gives the open flags / resolve flags; the path is always resolved
	/// relative to m1's root.  Backs the fd-upgrade / proxy path (§11)
	/// and the reconcile process (opening child mounts and mount
	/// targets).
	///
	/// We resolve in m1 (not m0) so the sandbox's own mount layout and
	/// `mount_attr`s are authoritative and we cannot accidentally
	/// over-grant (§11.4).
	pub fn open_in_m1(
		&self,
		path: &CStr,
		openhow: &libc::open_how,
	) -> Result<ForeignFd, BindMountSandboxError> {
		let openhow_copy = *openhow;
		let raw_fd = unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, false, true, true);
			send_fd_from_ns(
				nsenter_fn,
				|| {
					let fd = libc::syscall(
						libc::SYS_openat2,
						libc::AT_FDCWD,
						path.as_ptr(),
						&openhow_copy as *const _,
						std::mem::size_of::<libc::open_how>(),
					) as libc::c_int;
					if fd < 0 {
						return Err(io::Error::last_os_error());
					}
					Ok(fd)
				},
				BindMountSandboxError::OpenInM1Failed,
			)?
		};
		Ok(ForeignFd { local_fd: raw_fd })
	}

	/// Read `/proc/self/mountinfo` as seen from inside m1, returning its
	/// raw bytes.  A short-lived helper forks, `setns`es into m1, reads
	/// its own mountinfo (now m1's view) and streams it back.  Backs the
	/// §13 mount-tree refresh.
	pub fn read_m1_mountinfo(&self) -> Result<Vec<u8>, BindMountSandboxError> {
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, false, true, false) };
		unsafe {
			thread::scope(|s| {
				let mut pipe_fds = [-1i32; 2];
				if libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
					return Err(BindMountSandboxError::ReadMountinfoFailed(
						io::Error::last_os_error(),
					));
				}
				let read_fd = pipe_fds[0];
				let write_fd = pipe_fds[1];

				// Read the whole pipe concurrently with the child writing,
				// so a mountinfo larger than the pipe buffer can't
				// deadlock.
				let reader = s.spawn(move || {
					let mut out = Vec::new();
					let mut buf = [0u8; 8192];
					loop {
						let n =
							libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
						if n < 0 {
							let err = io::Error::last_os_error();
							if err.kind() == io::ErrorKind::Interrupted {
								continue;
							}
							libc::close(read_fd);
							return Err(err);
						}
						if n == 0 {
							break;
						}
						out.extend_from_slice(&buf[..n as usize]);
					}
					libc::close(read_fd);
					Ok(out)
				});

				let fork_res = fork_wait(|| {
					libc::close(read_fd);
					// Pin a handle to the host procfs *before* entering m1,
					// because m1's mount layout has no /proc mounted.  An
					// fd to procfs stays valid across setns; reading
					// `self/mountinfo` through it still reflects the
					// reader's *current* mount namespace (m1 after setns),
					// rendered relative to m1's root (mntns_install sets
					// our fs root/pwd to m1's root).
					let proc_fd = libc::open(
						c"/proc".as_ptr(),
						libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
					);
					if proc_fd < 0 {
						return perror!("open(/proc)");
					}
					match nsenter_fn() {
						Ok(()) => (),
						Err(e) => {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to enter m1 for mountinfo: {}", e);
							}
							libc::close(proc_fd);
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					}
					let src = libc::openat(
						proc_fd,
						c"self/mountinfo".as_ptr(),
						libc::O_RDONLY | libc::O_CLOEXEC,
					);
					libc::close(proc_fd);
					if src < 0 {
						return perror!("openat(/proc/self/mountinfo)");
					}
					let mut buf = [0u8; 8192];
					loop {
						let n = libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
						if n < 0 {
							let err = libc::__errno_location().read();
							if err == libc::EINTR {
								continue;
							}
							libc::close(src);
							return err;
						}
						if n == 0 {
							break;
						}
						let mut off = 0isize;
						while off < n {
							let w = libc::write(
								write_fd,
								buf.as_ptr().offset(off) as *const libc::c_void,
								(n - off) as usize,
							);
							if w < 0 {
								let err = libc::__errno_location().read();
								if err == libc::EINTR {
									continue;
								}
								libc::close(src);
								return err;
							}
							off += w;
						}
					}
					libc::close(src);
					0
				});
				// Closing our copy of the write end lets the reader see EOF.
				libc::close(write_fd);

				let fork_res = match fork_res {
					Ok(c) => c,
					Err(e) => {
						let _ = reader.join();
						return Err(BindMountSandboxError::ForkError(e));
					}
				};
				let read_res = reader.join().expect("mountinfo reader thread panicked");
				if fork_res != 0 {
					return Err(BindMountSandboxError::ReadMountinfoFailed(
						io::Error::from_raw_os_error(fork_res),
					));
				}
				read_res.map_err(BindMountSandboxError::ReadMountinfoFailed)
			})
		}
	}

	/// Move the mount currently at `ns_path` into the hidden scratch
	/// tmpfs at `scratch/<name>`, preserving its `struct mount` identity.
	/// Used to temporarily "park" a child (or a soon-to-be-rebuilt
	/// parent's descendants) out of the way during reconcile so a
	/// non-`MNT_DETACH` umount of its old location can proceed.  The
	/// `name` must be a single path component (no slashes).
	pub fn park_to_scratch(
		&self,
		ns_path: &CStr,
		name: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let scratch_fd = self.m1_scratch_fd.as_raw_fd();
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				}
				// Create scratch/<name> to receive the parked mount.
				if libc::mkdirat(scratch_fd, name.as_ptr(), 0o700) != 0 {
					let err = libc::__errno_location().read();
					if err != libc::EEXIST {
						return perror!("mkdirat(scratch/name)");
					}
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let src_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					ns_path.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if src_fd < 0 {
					return perror!("openat2(park source)");
				}
				let res = libc::syscall(
					libc::SYS_move_mount,
					src_fd,
					c"".as_ptr(),
					scratch_fd,
					name.as_ptr(),
					libc::MOVE_MOUNT_F_EMPTY_PATH,
				);
				libc::close(src_fd);
				if res != 0 {
					return perror!("move_mount(park)");
				}
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			return Err(BindMountSandboxError::ParkToScratchFailed(fork_res));
		}
		Ok(())
	}

	/// Move a previously parked mount at `scratch/<name>` back to
	/// `dest` (an absolute m1 path whose mountpoint dentry must exist),
	/// then remove the now-empty `scratch/<name>` directory.  The inverse
	/// of [`Self::park_to_scratch`].
	pub fn restore_from_scratch(
		&self,
		name: &CStr,
		dest: &CStr,
	) -> Result<(), BindMountSandboxError> {
		validate_sandbox_path(dest)?;
		let scratch_fd = self.m1_scratch_fd.as_raw_fd();
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, false) };
		let fork_res = unsafe {
			fork_wait(|| {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => return e.raw_os_error().unwrap_or(libc::EIO),
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS;
				let src_fd = libc::syscall(
					libc::SYS_openat2,
					scratch_fd,
					name.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if src_fd < 0 {
					return perror!("openat2(scratch/name)");
				}
				let mut dest_openhow: libc::open_how = mem::zeroed();
				dest_openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				dest_openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
				let dest_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					dest.as_ptr(),
					&dest_openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if dest_fd < 0 {
					libc::close(src_fd);
					return perror!("openat2(restore dest)");
				}
				let res = libc::syscall(
					libc::SYS_move_mount,
					src_fd,
					c"".as_ptr(),
					dest_fd,
					c"".as_ptr(),
					libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH,
				);
				libc::close(src_fd);
				libc::close(dest_fd);
				if res != 0 {
					return perror!("move_mount(restore)");
				}
				// Best-effort cleanup of the now-empty scratch dir.
				libc::unlinkat(scratch_fd, name.as_ptr(), libc::AT_REMOVEDIR);
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			return Err(BindMountSandboxError::RestoreFromScratchFailed(fork_res));
		}
		Ok(())
	}

	/// Unmount `ns_path` while preserving its sub-mounts: park every
	/// direct sub-mount under `ns_path` to the hidden scratch tmpfs,
	/// attempt a non-detach
	/// `umount2(ns_path)`, then restore the parked sub-mounts onto their
	/// original paths.  Returns `Ok(true)` if the parent mount was
	/// successfully unmounted, or `Ok(false)` if it was kept because the
	/// app still holds it (the umount returned `EBUSY`).  In both cases
	/// the children keep their `struct mount` identity (and thus any app
	/// fds / cwd resolving through them remain valid).
	///
	/// `child_ns_paths` must list the *direct* (topmost) sub-mounts of
	/// `ns_path` in the live mount tree - parking all present children
	/// (not just still-desired ones) is required so that none of them
	/// pins the parent and causes a spurious `EBUSY` (see §6).  Their
	/// mountpoint dentries must exist on the layer revealed by the umount
	/// (the placeholder hierarchy), which the caller is responsible for.
	pub(self) fn unmount_covering(
		&self,
		ns_path: &CStr,
		child_ns_paths: &[CString],
	) -> Result<bool, BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		// Park each direct child out of the way so it can't pin the
		// parent; each gets a unique scratch directory.
		let mut parked: Vec<(CString, &CStr)> = Vec::with_capacity(child_ns_paths.len());
		for child in child_ns_paths {
			let name = next_scratch_name();
			if let Err(e) = self.park_to_scratch(child, &name) {
				// Best-effort: restore anything already parked before
				// propagating the failure.
				for (name, dest) in &parked {
					let _ = self.restore_from_scratch(name, dest);
				}
				return Err(e);
			}
			parked.push((name, child.as_c_str()));
		}
		// Attempt a non-detach unmount.  With every child parked, only the
		// app's own references on `ns_path` can still pin it.
		let unmounted = match self.unmount(ns_path, false) {
			Ok(()) => true,
			Err(BindMountSandboxError::UnmountFailed(e)) if e == libc::EBUSY => false,
			Err(e) => {
				for (name, dest) in &parked {
					let _ = self.restore_from_scratch(name, dest);
				}
				return Err(e);
			}
		};
		// Restore each parked child onto its original path: on the
		// revealed placeholder layer when unmounted, or under the kept
		// mount on EBUSY.
		for (name, dest) in &parked {
			self.restore_from_scratch(name, dest)?;
		}
		Ok(unmounted)
	}

	/// instead of [`Self::run_command`], most likely within a pre_exec
	/// hook or after fork()ing.  This cannot be used if the current
	/// process contains more than one threads.
	pub fn restrict_self(&self) -> Result<(), BindMountSandboxError> {
		let nsenter_fn = unsafe { self.namespaces.nsenter_fn(true, true, true, true) };
		restrict_self_impl(nsenter_fn, None).map_err(BindMountSandboxError::RestrictSelf)
	}

	/// Run a command within the sandbox.  Can be called more than once
	/// (unlike
	/// [`TurnstileTracer::run_command`](crate::tracer::TurnstileTracer::run_command))
	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, BindMountSandboxError> {
		let new_cwd = match cmd.get_current_dir() {
			Some(path) => Cow::Borrowed(path),
			None => Cow::Owned(std::env::current_dir().map_err(BindMountSandboxError::Getcwd)?),
		};
		let new_cwd_cstr = std::ffi::CString::new(new_cwd.as_os_str().as_encoded_bytes())
			.expect("current directory path contains NUL byte");
		self.create_placeholder_hierarchy(&new_cwd_cstr, true)?;
		unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, true, true, true);
			cmd.pre_exec(move || restrict_self_impl(&nsenter_fn, Some(&new_cwd_cstr)))
		};
		let child = cmd.spawn().map_err(BindMountSandboxError::Spawn)?;
		Ok(child)
	}

	pub fn root_in_sandbox(&self) -> Result<ForeignFd, BindMountSandboxError> {
		unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, true, true, true);
			Ok(ForeignFd {
				local_fd: send_fd_from_ns(
					nsenter_fn,
					|| {
						let fd = libc::open(
							c"/".as_ptr(),
							libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
						);
						if fd < 0 {
							let err = perror!("Failed to open root in sandbox namespace");
							return Err(io::Error::from_raw_os_error(err));
						}
						Ok(fd)
					},
					BindMountSandboxError::OpenRootInSandboxFailed,
				)?,
			})
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMountPoint {
	pub host_path: CString,
	pub attrs: MountAttributes,
}

/// Internal per-mount bookkeeping kept in `current_mount_tree`.  Wraps
/// the user-facing [`ManagedMountPoint`] with the kernel `mnt_id`
/// captured at mount-creation time (used as the join key for the §13
/// mountinfo refresh and, in future, the fd-staleness key for §11), and
/// an `expired` flag set by the refresh when the bind source has been
/// unlinked on the host (`//deleted`).
#[derive(Debug, Clone)]
pub(crate) struct MountInternal {
	/// host_path + currently-applied attrs (the user-visible part).
	pub user: ManagedMountPoint,
	/// Kernel `mnt_id` captured at creation via `statx(STATX_MNT_ID)`
	/// from the m1 helper; 0 if the capture failed.
	pub mnt_id: u64,
	/// Set by the refresh when mountinfo shows the bind source as
	/// `//deleted`; forces umount-and-readd on the next reconcile if
	/// still desired.
	pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedTreeEntry {
	Placeholder(ManagedPlaceholder),
	BindMount(ManagedMountPoint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedPlaceholder {
	PlaceholderDir(PlaceholderDirData),
	PlaceholderFile(PlaceholderFileData),
	PlaceholderSymlink(PlaceholderSymlinkData),
}

#[derive(Debug, Clone)]
pub struct CommonPlaceholderData {
	pub atime: libc::timespec,
	pub mtime: libc::timespec,
}

impl PartialEq for CommonPlaceholderData {
	fn eq(&self, other: &Self) -> bool {
		self.atime.tv_sec == other.atime.tv_sec
			&& self.atime.tv_nsec == other.atime.tv_nsec
			&& self.mtime.tv_sec == other.mtime.tv_sec
			&& self.mtime.tv_nsec == other.mtime.tv_nsec
	}
}

impl Eq for CommonPlaceholderData {}

impl CommonPlaceholderData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			atime: libc::timespec {
				tv_sec: stat.st_atime,
				tv_nsec: stat.st_atime_nsec as _,
			},
			mtime: libc::timespec {
				tv_sec: stat.st_mtime,
				tv_nsec: stat.st_mtime_nsec as _,
			},
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderDirData {
	pub common: CommonPlaceholderData,
	pub mode: u32,
}

/// Recursively remove a directory entry, ignoring ENOENT.  Used as the
/// underlying implementation of [`remove_entry_at`].
fn remove_dir_recursive_at(
	parent_fd: libc::c_int,
	name: &CStr,
) -> Result<(), BindMountSandboxError> {
	unsafe {
		let mut openhow: libc::open_how = mem::zeroed();
		openhow.flags =
			(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
		openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
		let dir_fd = libc::syscall(
			libc::SYS_openat2,
			parent_fd,
			name.as_ptr(),
			&openhow as *const _,
			std::mem::size_of::<libc::open_how>(),
		) as libc::c_int;
		if dir_fd < 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}
		// dup because fdopendir takes ownership
		let dir_fd_dup = libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0);
		if dir_fd_dup < 0 {
			libc::close(dir_fd);
			let err = io::Error::last_os_error();
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}

		let dir = libc::fdopendir(dir_fd);
		if dir.is_null() {
			libc::close(dir_fd);
			libc::close(dir_fd_dup);
			let err = io::Error::last_os_error();
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}
		// dir_fd is now owned by dir

		loop {
			*libc::__errno_location() = 0;
			let entry = libc::readdir(dir);
			if entry.is_null() {
				let errno = *libc::__errno_location();
				if errno != 0 {
					libc::closedir(dir);
					libc::close(dir_fd_dup);
					return Err(BindMountSandboxError::OpenSandboxDir(
						io::Error::from_raw_os_error(errno),
					));
				}
				break;
			}

			let entry_name = CStr::from_ptr((*entry).d_name.as_ptr());
			if entry_name == c"." || entry_name == c".." {
				continue;
			}

			let mut stat: libc::stat = std::mem::zeroed();
			if libc::fstatat(
				dir_fd_dup,
				entry_name.as_ptr(),
				&mut stat,
				libc::AT_SYMLINK_NOFOLLOW,
			) != 0
			{
				let err = io::Error::last_os_error();
				libc::closedir(dir);
				libc::close(dir_fd_dup);
				return Err(BindMountSandboxError::StatSandboxPath(err));
			}

			if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
				if let Err(e) = remove_dir_recursive_at(dir_fd_dup, entry_name) {
					libc::closedir(dir);
					libc::close(dir_fd_dup);
					return Err(e);
				}
			} else {
				let res = libc::unlinkat(dir_fd_dup, entry_name.as_ptr(), 0);
				if res != 0 {
					let err = io::Error::last_os_error();
					if err.kind() != io::ErrorKind::NotFound {
						libc::closedir(dir);
						libc::close(dir_fd_dup);
						return Err(BindMountSandboxError::RemoveSandboxPath(err));
					}
				}
			}
		}

		libc::closedir(dir);
		libc::close(dir_fd_dup);

		let res = libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR);
		if res != 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::RemoveSandboxPath(err));
		}
	}
	Ok(())
}

/// Remove an entry at (`parent_fd`, `name`) regardless of its type.
/// Directories are removed recursively.  Returns `Ok(())` if the entry
/// (or any intermediate child) is already gone.  Symlinks are never
/// followed.
fn remove_entry_at(parent_fd: libc::c_int, name: &CStr) -> Result<(), BindMountSandboxError> {
	unsafe {
		let mut stat: libc::stat = mem::zeroed();
		if libc::fstatat(
			parent_fd,
			name.as_ptr(),
			&mut stat,
			libc::AT_SYMLINK_NOFOLLOW,
		) != 0
		{
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::StatSandboxPath(err));
		}
		if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
			remove_dir_recursive_at(parent_fd, name)
		} else {
			let res = libc::unlinkat(parent_fd, name.as_ptr(), 0);
			if res != 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					return Ok(());
				}
				return Err(BindMountSandboxError::RemoveSandboxPath(err));
			}
			Ok(())
		}
	}
}

/// Create or update a single placeholder entry at (`dirfd`, `name`).
///
/// If nothing exists at the path, the entry is created with the
/// requested type.  If something exists with the wrong type (or, for
/// symlinks, a wrong target), it is removed (recursively for
/// directories) and recreated.
///
/// After the entry exists with the correct type, its mode is updated
/// via `fchmodat` (skipped for symlinks since Linux does not allow
/// changing symlink modes), and timestamps are updated via `utimensat`.
/// Set both `atime.tv_nsec` and `mtime.tv_nsec` to `UTIME_OMIT` to skip
/// the timestamp update entirely (useful when this function is used
/// just to ensure the entry exists with reasonable defaults).
///
/// Symlinks are never followed for any operation.
fn create_or_update_placeholder(
	dirfd: libc::c_int,
	name: &CStr,
	placeholder_data: &ManagedPlaceholder,
) -> Result<(), BindMountSandboxError> {
	const MAX_ATTEMPTS: u32 = 2;

	let (common, expected_kind, mode_perms): (
		&CommonPlaceholderData,
		libc::mode_t,
		Option<libc::mode_t>,
	) = match placeholder_data {
		ManagedPlaceholder::PlaceholderDir(d) => (
			&d.common,
			libc::S_IFDIR,
			Some((d.mode & 0o7777) as libc::mode_t),
		),
		ManagedPlaceholder::PlaceholderFile(f) => (
			&f.common,
			libc::S_IFREG,
			Some((f.mode & 0o7777) as libc::mode_t),
		),
		ManagedPlaceholder::PlaceholderSymlink(s) => (&s.common, libc::S_IFLNK, None),
	};

	let mut attempts: u32 = 0;
	loop {
		attempts += 1;
		if attempts > MAX_ATTEMPTS {
			return Err(BindMountSandboxError::SandboxPlaceholderConflict(
				name.to_owned(),
			));
		}

		let create_res: libc::c_int;
		let create_err: io::Error;
		unsafe {
			let res = match placeholder_data {
				ManagedPlaceholder::PlaceholderDir(_) => {
					libc::mkdirat(dirfd, name.as_ptr(), mode_perms.unwrap())
				}
				ManagedPlaceholder::PlaceholderFile(_) => {
					let fd = libc::openat(
						dirfd,
						name.as_ptr(),
						libc::O_CREAT
							| libc::O_EXCL | libc::O_WRONLY
							| libc::O_NOFOLLOW | libc::O_CLOEXEC,
						mode_perms.unwrap() as libc::c_uint,
					);
					if fd < 0 {
						-1
					} else {
						libc::close(fd);
						0
					}
				}
				ManagedPlaceholder::PlaceholderSymlink(s) => {
					libc::symlinkat(s.target.as_ptr(), dirfd, name.as_ptr())
				}
			};
			create_res = res;
			create_err = if res != 0 {
				io::Error::last_os_error()
			} else {
				io::Error::from_raw_os_error(0)
			};
		}

		if create_res == 0 {
			break;
		}

		if create_err.kind() != io::ErrorKind::AlreadyExists {
			return Err(match placeholder_data {
				ManagedPlaceholder::PlaceholderDir(_) => {
					BindMountSandboxError::Mkdir(name.to_owned(), create_err)
				}
				ManagedPlaceholder::PlaceholderFile(_) => {
					BindMountSandboxError::Mkfile(name.to_owned(), create_err)
				}
				ManagedPlaceholder::PlaceholderSymlink(s) => {
					BindMountSandboxError::Symlinkat(name.to_owned(), s.target.clone(), create_err)
				}
			});
		}

		// EEXIST: stat the existing entry and decide what to do.
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		let stat_res =
			unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
		if stat_res != 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				// raced; just retry
				continue;
			}
			return Err(BindMountSandboxError::StatSandboxPath(err));
		}

		let existing_kind = stat.st_mode & libc::S_IFMT;
		if existing_kind != expected_kind {
			// wrong type: remove (recursively if dir) and retry.
			remove_entry_at(dirfd, name)?;
			continue;
		}

		// Right type.  For symlinks, also verify the target.
		if let ManagedPlaceholder::PlaceholderSymlink(s) = placeholder_data {
			let mut buf = vec![0u8; libc::PATH_MAX as usize];
			let n = unsafe {
				libc::readlinkat(dirfd, name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
			};
			if n < 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					continue;
				}
				return Err(BindMountSandboxError::Readlink(name.to_owned(), err));
			}
			let existing_target = &buf[..n as usize];
			if existing_target != s.target.to_bytes() {
				// Wrong target: must unlink (symlinkat is not atomic-replace)
				// before retrying.  ENOENT is fine (race).
				let res = unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) };
				if res != 0 {
					let err = io::Error::last_os_error();
					if err.kind() != io::ErrorKind::NotFound {
						return Err(BindMountSandboxError::RemoveSandboxPath(err));
					}
				}
				continue;
			}
		}

		break;
	}

	// Update mode.  Skipped for symlinks: Linux does not support changing
	// symlink modes (fchmodat with AT_SYMLINK_NOFOLLOW returns ENOTSUP)
	// and symlink permissions are meaningless on Linux anyway.
	if let Some(mode_perms) = mode_perms {
		let res = unsafe { libc::fchmodat(dirfd, name.as_ptr(), mode_perms, 0) };
		if res != 0 {
			return Err(BindMountSandboxError::Chmod(
				name.to_owned(),
				io::Error::last_os_error(),
			));
		}
	}

	// Update timestamps unless both are UTIME_OMIT (caller's signal to
	// leave timestamps untouched).
	if common.atime.tv_nsec != libc::UTIME_OMIT || common.mtime.tv_nsec != libc::UTIME_OMIT {
		let times = [common.atime, common.mtime];
		let res = unsafe {
			libc::utimensat(
				dirfd,
				name.as_ptr(),
				times.as_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if res != 0 {
			return Err(BindMountSandboxError::Utimens(
				name.to_owned(),
				io::Error::last_os_error(),
			));
		}
	}

	Ok(())
}

/// Stat a host path from the caller's mount namespace.  Symlinks are
/// not followed.
fn stat_host(host_path: &CStr) -> Result<libc::stat, BindMountSandboxError> {
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
		return Err(BindMountSandboxError::StatHostPath(
			host_path.to_owned(),
			io::Error::last_os_error(),
		));
	}
	Ok(stat)
}

/// Convenience for callers that just need to ensure an entry exists
/// with sensible default mode and without touching timestamps.
fn placeholder_default_no_metadata(kind_is_dir: bool) -> ManagedPlaceholder {
	let common = CommonPlaceholderData {
		atime: libc::timespec {
			tv_sec: 0,
			tv_nsec: libc::UTIME_OMIT,
		},
		mtime: libc::timespec {
			tv_sec: 0,
			tv_nsec: libc::UTIME_OMIT,
		},
	};
	if kind_is_dir {
		ManagedPlaceholder::PlaceholderDir(PlaceholderDirData {
			common,
			mode: 0o755,
		})
	} else {
		ManagedPlaceholder::PlaceholderFile(PlaceholderFileData {
			common,
			mode: 0o644,
			len: 0,
		})
	}
}

fn placeholder_default_symlink(target: CString) -> ManagedPlaceholder {
	ManagedPlaceholder::PlaceholderSymlink(PlaceholderSymlinkData {
		common: CommonPlaceholderData {
			atime: libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_OMIT,
			},
			mtime: libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_OMIT,
			},
		},
		target,
	})
}

impl PlaceholderDirData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			mode: stat.st_mode,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderFileData {
	pub common: CommonPlaceholderData,
	pub mode: u32,
	pub len: u64,
}

impl PlaceholderFileData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			mode: stat.st_mode,
			len: stat.st_size as u64,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderSymlinkData {
	pub common: CommonPlaceholderData,
	pub target: CString,
}

impl PlaceholderSymlinkData {
	pub fn from_stat(stat: &libc::stat, target: CString) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			target,
		}
	}
}

/// Implements a bind-mount based sandbox that automatically mount and
/// unmounts based on a desired state.
#[derive(Debug)]
pub struct ManagedBindMountSandbox {
	sandbox: BindMountSandbox,
	current_placeholder_tree: Mutex<FsTree<ManagedPlaceholder>>,
	current_mount_tree: Mutex<FsTree<MountInternal>>,
}

impl ManagedBindMountSandbox {
	pub fn new(disable_userns: bool) -> Result<Self, BindMountSandboxError> {
		Ok(Self {
			sandbox: BindMountSandbox::new(disable_userns)?,
			current_placeholder_tree: Mutex::new(FsTree::new()),
			current_mount_tree: Mutex::new(FsTree::new()),
		})
	}

	fn check_path_no_nul(path: &OsStr) -> Result<(), BindMountSandboxError> {
		if path.as_encoded_bytes().contains(&0) {
			return Err(BindMountSandboxError::InvalidSandboxPath(
				"path contains NUL byte",
				CString::from_vec_with_nul(format!("{:?}", path).into_bytes())
					.expect("debug format should not contain NUL bytes"),
			));
		}
		Ok(())
	}

	/// Convenience: update a single entry (placeholder or mount) and
	/// reconcile.
	///
	/// Reconciliation may touch other paths (ancestors, shadowed
	/// sub-mounts, previously-tracked entries).  Only an error related to
	/// `path` itself is surfaced to the caller; failures on unrelated
	/// paths are logged by `reconcile` but do not fail this call.
	pub fn add_or_update_entry(
		&self,
		path: &OsStr,
		entry: ManagedTreeEntry,
	) -> Result<(), BindMountSandboxError> {
		Self::check_path_no_nul(path)?;
		let (mut pt, mut mt) = self.lock_trees();
		let mut desired_entries = self.entries_from_state(&pt, &mt);
		desired_entries.insert(path, entry);
		let errors = self.reconcile(&mut pt, &mut mt, &desired_entries);
		Self::error_for_path(errors, path)
	}

	/// Pick out the reconcile error (if any) that relates to `path`,
	/// discarding errors on unrelated paths.
	fn error_for_path(
		errors: Vec<(OsString, BindMountSandboxError)>,
		path: &OsStr,
	) -> Result<(), BindMountSandboxError> {
		for (p, e) in errors {
			if p.as_os_str() == path {
				return Err(e);
			}
		}
		Ok(())
	}

	pub fn add_or_update_mount(
		&self,
		path: &OsStr,
		mp: ManagedMountPoint,
	) -> Result<(), BindMountSandboxError> {
		self.add_or_update_entry(path, ManagedTreeEntry::BindMount(mp))
	}

	pub fn add_or_update_placeholder(
		&self,
		path: &OsStr,
		ph: ManagedPlaceholder,
	) -> Result<(), BindMountSandboxError> {
		self.add_or_update_entry(path, ManagedTreeEntry::Placeholder(ph))
	}

	/// Remove either the placeholder or mount entry at the given path.
	pub fn remove_entry(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		Self::check_path_no_nul(path)?;
		let (mut pt, mut mt) = self.lock_trees();
		let mut desired_entries = self.entries_from_state(&pt, &mt);
		desired_entries.remove(path);
		let errors = self.reconcile(&mut pt, &mut mt, &desired_entries);
		Self::error_for_path(errors, path)
	}

	pub fn remove_mount(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		self.remove_entry(path)
	}

	pub fn update_from_tree(
		&self,
		desired_tree: &FsTree<ManagedTreeEntry>,
	) -> Result<(), BindMountSandboxError> {
		let (mut pt, mut mt) = self.lock_trees();
		let errors = self.reconcile(&mut pt, &mut mt, desired_tree);
		// A bulk update has no single "target" path, so surface the
		// first error encountered (all are logged by `reconcile`).
		match errors.into_iter().next() {
			Some((_, e)) => Err(e),
			None => Ok(()),
		}
	}

	pub fn update_from_list<'a>(
		&self,
		desired_entries: impl IntoIterator<Item = (&'a OsStr, ManagedTreeEntry)>,
	) -> Result<(), BindMountSandboxError> {
		let mut tree = FsTree::new();
		for (path, entry) in desired_entries {
			Self::check_path_no_nul(path)?;
			tree.insert(path, entry);
		}
		self.update_from_tree(&tree)
	}

	pub fn update_mounts_from_tree(
		&self,
		desired_tree: &FsTree<ManagedMountPoint>,
	) -> Result<(), BindMountSandboxError> {
		let mut converted = FsTree::new();
		desired_tree.walk_top_down(|path, mp| {
			converted.insert(path, ManagedTreeEntry::BindMount(mp.clone()));
		});
		self.update_from_tree(&converted)
	}

	pub fn update_mounts_from_list<'a>(
		&self,
		desired_mounts: impl IntoIterator<Item = (&'a OsStr, ManagedMountPoint)>,
	) -> Result<(), BindMountSandboxError> {
		self.update_from_list(
			desired_mounts
				.into_iter()
				.map(|(p, m)| (p, ManagedTreeEntry::BindMount(m))),
		)
	}

	fn lock_trees(
		&self,
	) -> (
		std::sync::MutexGuard<'_, FsTree<ManagedPlaceholder>>,
		std::sync::MutexGuard<'_, FsTree<MountInternal>>,
	) {
		// Always acquire in the same order to avoid deadlocks.
		let pt = self
			.current_placeholder_tree
			.lock()
			.expect("current_placeholder_tree lock poisoned");
		let mt = self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned");
		(pt, mt)
	}

	/// Reconstruct an entry tree from the current internal state.  Mount
	/// entries take precedence over placeholders at the same path
	/// (they share the path when we created a placeholder under a
	/// mount).
	fn entries_from_state(
		&self,
		pt: &FsTree<ManagedPlaceholder>,
		mt: &FsTree<MountInternal>,
	) -> FsTree<ManagedTreeEntry> {
		let mut out = FsTree::new();
		pt.walk_top_down(|path, ph| {
			out.insert(path, ManagedTreeEntry::Placeholder(ph.clone()));
		});
		mt.walk_top_down(|path, mp| {
			out.insert(path, ManagedTreeEntry::BindMount(mp.user.clone()));
		});
		out
	}

	/// Reconcile current state with `desired_entries`.  Caller locks the
	/// two internal states.
	///
	/// Steps:
	///   1. Build the desired placeholder tree from `desired_entries`,
	///      including ancestor directories.  For each bind-mount entry,
	///      synthesize a default placeholder (file or dir, based on the
	///      host stat) at the mount point if one isn't already specified
	///      by the user.
	///   2. Build the desired mount tree.
	///   3. Diff current_placeholder_tree -> desired_placeholder_tree
	///      and create/update placeholders (ignoring removals).
	///   4. Diff current_mount_tree -> desired_mount_tree and
	///      apply unmount / mount / set_mount_attr accordingly.
	///   5. Diff current_placeholder_tree -> desired_placeholder_tree
	///      again and remove now-unused placeholders (ignoring adds).
	///
	/// Reconciliation is best-effort and does not stop at the first
	/// failure: an error applying one path is recorded (annotated by the
	/// sandbox path it relates to) and the remaining pending
	/// modifications are still attempted.  The accumulated errors are
	/// returned to the caller, which decides which ones are relevant.
	fn reconcile(
		&self,
		current_pt: &mut FsTree<ManagedPlaceholder>,
		current_mt: &mut FsTree<MountInternal>,
		desired_entries: &FsTree<ManagedTreeEntry>,
	) -> Vec<(OsString, BindMountSandboxError)> {
		// §13: refresh the mount tree from m1's mountinfo so the diff
		// input is kernel-truthful (drops vanished mounts, tracks renamed
		// bind sources, flags unlinked sources as expired).  Best-effort:
		// on any read/parse failure we keep the current tree as-is.
		self.refresh_mount_tree(current_mt);

		let (desired_pt, desired_mt, mut errors) = self.build_desired_trees(desired_entries);
		debug!("Current placeholder tree: {:?}", current_pt);
		debug!("Desired placeholder tree: {:?}", desired_pt);
		debug!("Current mount tree: {:?}", current_mt);
		debug!("Desired mount tree: {:?}", desired_mt);

		let mut new_pt = current_pt.clone();
		let mut new_mt = current_mt.clone();

		// Phase 1: create / update placeholders top-down.
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Added(new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						new_pt.insert(sandbox_path, new.clone());
					}
					crate::fstree::DiffTree::Updated(_, new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						*new_pt.get_mut(sandbox_path).expect("must exist") = new.clone();
					}
					crate::fstree::DiffTree::Removed(_) => {}
				}
			},
			|_, _, _| false,
			false,
		);

		// Phase 2: mounts diff.
		current_mt.diff(
			&desired_mt,
			|sandbox_path, diff| {
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Removed(old) => {
						// A `Removed` whose path still exists in the
						// desired mount tree is half of a host_path-change
						// "split" (§5): the diff emits Removed(P) then
						// Added(P).  Its identity is being discarded and
						// the following Added re-covers P, so detach the
						// old bind unconditionally (MNT_DETACH) rather than
						// running the §6 keep-on-EBUSY dance - keeping it
						// would leave the new bind shadowing the old one.
						if desired_mt.get(sandbox_path).is_some() {
							if let Err(e) = self.sandbox.unmount(&ns_path, true) {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							new_mt.remove(sandbox_path);
							return;
						}
						// discover the direct (topmost) sub-mounts
						// still present under this path in the live tree
						// and hand them to the unmount routine, which
						// parks them out of the way, does a non-detach
						// umount, then restores them - preserving each
						// child's `struct mount` identity instead of
						// detaching the whole subtree.
						let mut children: Vec<CString> = Vec::new();
						new_mt.walk_subtree_top_down(sandbox_path, true, |child_path, _| {
							if let Ok(c) = CString::new(child_path.as_encoded_bytes()) {
								children.push(c);
							}
						});
						match self.sandbox.unmount_covering(&ns_path, &children) {
							Ok(true) => {
								new_mt.remove(sandbox_path);
							}
							Ok(false) => {
								// EBUSY: the app itself still holds this
								// path.  Keep it but lock it down to the
								// covering attrs (§4 SetAttrToCovering);
								// a later reconcile retries the removal
								// once the app lets go (eventual
								// consistency).
								let covering = self.covering_attrs(&desired_mt, sandbox_path);
								if covering != old.user.attrs {
									if let Err(e) = self.sandbox.set_mount_attr(
										&ns_path,
										covering,
										old.user.attrs,
									) {
										errors.push((sandbox_path.to_owned(), e));
										return;
									}
								}
								let entry = new_mt.get_mut(sandbox_path).expect("must exist");
								entry.user.attrs = covering;
							}
							Err(e) => {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
						}
					}
					crate::fstree::DiffTree::Added(new) => {
						// §7: discover the immediate sub-mounts this new
						// bind would shadow (topmost mounts strictly under
						// the path in the live tree) and re-expose them.
						let mut children: Vec<CString> = Vec::new();
						new_mt.walk_subtree_top_down(sandbox_path, true, |child_path, _| {
							if let Ok(c) = CString::new(child_path.as_encoded_bytes()) {
								children.push(c);
							}
						});
						if let Err(e) = self.sandbox.mount_covering(
							&new.host_path,
							&ns_path,
							new.attrs,
							&children,
						) {
							errors.push((sandbox_path.to_owned(), e));
							return;
						}
						let mnt_id = self.capture_mnt_id(&ns_path);
						new_mt.insert(
							sandbox_path,
							MountInternal {
								user: (*new).clone(),
								mnt_id,
								expired: false,
							},
						);
					}
					crate::fstree::DiffTree::Updated(old, new) => {
						assert_eq!(old.user.host_path, new.host_path);
						// §13: an expired entry (host source was unlinked
						// while mounted) is rebuilt so the sandbox picks up
						// any freshly created host dentry at the same path.
						if old.expired {
							if let Err(e) = self.sandbox.unmount(&ns_path, true) {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							if let Err(e) = self.sandbox.mount_host_into_sandbox_impl(
								&new.host_path,
								&ns_path,
								new.attrs,
								false,
								false,
								false,
							) {
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							let mnt_id = self.capture_mnt_id(&ns_path);
							*new_mt.get_mut(sandbox_path).expect("must exist") = MountInternal {
								user: (*new).clone(),
								mnt_id,
								expired: false,
							};
						} else if old.user.attrs != new.attrs {
							if let Err(e) =
								self.sandbox
									.set_mount_attr(&ns_path, new.attrs, old.user.attrs)
							{
								errors.push((sandbox_path.to_owned(), e));
								return;
							}
							let entry = new_mt.get_mut(sandbox_path).expect("must exist");
							entry.user = (*new).clone();
						}
					}
				}
			},
			|_, old, new| old.user.host_path != new.host_path,
			true,
		);

		// Phase 3: remove placeholders no longer desired (bottom-up).
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				if matches!(diff, crate::fstree::DiffTree::Removed(_)) {
					let ns_path = CString::new(sandbox_path.as_encoded_bytes())
						.expect("checked for NUL byte");
					if ns_path.as_c_str() == c"/" {
						return;
					}
					if let Err(e) = self.sandbox.remove_placeholder(&ns_path) {
						errors.push((sandbox_path.to_owned(), e));
						return;
					}
					new_pt.remove(sandbox_path);
				}
			},
			|_, _, _| false,
			false,
		);

		*current_pt = new_pt;
		*current_mt = new_mt;
		for (path, err) in &errors {
			warn!("reconcile: error applying {:?}: {}", path, err);
		}
		errors
	}

	/// Apply (create or update) a placeholder at `ns_path`.  The parent
	/// directory must already exist in the backing tmpfs.
	fn apply_placeholder(
		&self,
		ns_path: &CStr,
		placeholder: &ManagedPlaceholder,
	) -> Result<(), BindMountSandboxError> {
		if ns_path == c"/" {
			// Root is the tmpfs itself; no placeholder to manage.
			return Ok(());
		}
		validate_sandbox_path(ns_path)?;
		let (_, leaf) = split_parent_leaf(ns_path);
		let parent_fd = self.sandbox.open_sandbox_parent(ns_path)?;
		create_or_update_placeholder(parent_fd.as_raw_fd(), leaf, placeholder)
	}

	/// Build (desired_placeholder_tree, desired_mount_tree) from an
	/// entry tree.  For each bind-mount entry, a default placeholder is
	/// synthesized at the mount point if the caller didn't supply one;
	/// missing ancestor directories are then filled in via
	/// `FsTree::fill_incomplete_parent` so creation order naturally
	/// flows parent-before-child.
	fn build_desired_trees(
		&self,
		desired_entries: &FsTree<ManagedTreeEntry>,
	) -> (
		FsTree<ManagedPlaceholder>,
		FsTree<ManagedMountPoint>,
		Vec<(OsString, BindMountSandboxError)>,
	) {
		let mut placeholders: FsTree<ManagedPlaceholder> = FsTree::new();
		let mut mounts: FsTree<ManagedMountPoint> = FsTree::new();
		let mut errors: Vec<(OsString, BindMountSandboxError)> = Vec::new();
		desired_entries.walk_top_down(|path, entry| {
			if path.as_encoded_bytes() == b"/" {
				// Root: never a placeholder.  May be a mount target.
				if let ManagedTreeEntry::BindMount(mp) = entry {
					mounts.insert(path, mp.clone());
				}
				return;
			}
			match entry {
				ManagedTreeEntry::Placeholder(p) => {
					placeholders.insert(path, p.clone());
				}
				ManagedTreeEntry::BindMount(mp) => {
					if placeholders.get(path).is_none() {
						// Skip (and record) this single entry on a stat
						// failure rather than aborting the whole
						// reconcile: an unrelated mount whose host source
						// has vanished must not block updates to other
						// paths.
						let stat = match stat_host(&mp.host_path) {
							Ok(s) => s,
							Err(e) => {
								errors.push((path.to_owned(), e));
								return;
							}
						};
						let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
						placeholders.insert(path, placeholder_default_no_metadata(is_dir));
					}
					mounts.insert(path, mp.clone());
				}
			}
		});
		placeholders.fill_incomplete_parent(|_| placeholder_default_no_metadata(true));
		(placeholders, mounts, errors)
	}

	/// Capture the kernel `mnt_id` of the mount currently topmost at
	/// `ns_path`, by opening an `O_PATH` handle to it in m1 and running
	/// `statx(STATX_MNT_ID)`.  Returns 0 (and logs) if the capture
	/// fails, since a missing id only degrades the §13 refresh join for
	/// that one entry rather than breaking the mount.
	fn capture_mnt_id(&self, ns_path: &CStr) -> u64 {
		let mut openhow: libc::open_how = unsafe { mem::zeroed() };
		openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
		openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
		match self.sandbox.open_in_m1(ns_path, &openhow) {
			Ok(fd) => match fd.mnt_id() {
				Ok(id) => id,
				Err(e) => {
					warn!("Failed to capture mnt_id for {:?}: {}", ns_path, e);
					0
				}
			},
			Err(e) => {
				warn!(
					"Failed to open {:?} in m1 to capture mnt_id: {}",
					ns_path, e
				);
				0
			}
		}
	}

	/// §13: refresh `current_mt` from m1's `/proc/self/mountinfo`.
	///
	/// Joins each tracked entry to its live mountinfo line by `mnt_id`:
	/// an entry whose `mnt_id` is absent from mountinfo is dropped (its
	/// mount is gone); a `//deleted` source flags the entry `expired`;
	/// a renamed source (different root path, no `//deleted`) updates the
	/// recorded `host_path` without expiring.  Entries with a 0 `mnt_id`
	/// (capture previously failed) are kept untouched.
	///
	/// Best-effort: on any error reading or parsing mountinfo, the tree
	/// is left unchanged.
	fn refresh_mount_tree(&self, current_mt: &mut FsTree<MountInternal>) {
		if current_mt.is_empty() {
			return;
		}
		let raw = match self.sandbox.read_m1_mountinfo() {
			Ok(b) => b,
			Err(e) => {
				warn!("mountinfo refresh skipped: {}", e);
				return;
			}
		};
		let entries = mountinfo::parse_mountinfo(&raw);
		// Index the parsed lines by mnt_id for the join.
		let mut by_id: HashMap<u64, &mountinfo::MountinfoEntry> = HashMap::new();
		for e in &entries {
			by_id.insert(e.mnt_id, e);
		}

		let mut updates: Vec<(OsString, bool, Option<CString>)> = Vec::new();
		let mut drops: Vec<OsString> = Vec::new();
		current_mt.walk_top_down(|path, mi| {
			if mi.mnt_id == 0 {
				// No usable join key; leave as-is.
				return;
			}
			match by_id.get(&mi.mnt_id) {
				None => drops.push(OsString::from(path)),
				Some(info) => {
					let new_host =
						if !info.deleted && info.root.as_bytes() != mi.user.host_path.to_bytes() {
							CString::new(info.root.as_bytes()).ok()
						} else {
							None
						};
					updates.push((OsString::from(path), info.deleted, new_host));
				}
			}
		});

		for (path, deleted, new_host) in updates {
			if let Some(entry) = current_mt.get_mut(&path) {
				entry.expired = deleted;
				if let Some(h) = new_host {
					entry.user.host_path = h;
				}
			}
		}
		for path in drops {
			current_mt.remove(&path);
		}
	}

	/// §4 `SetAttrToCovering`: the attributes a path should fall back to
	/// when an entry we tried to remove is kept (app still holds it).
	/// This is the attrs of the deepest desired entry that is a proper
	/// prefix of `path`, or the safe default `ro,noexec` when none
	/// covers it.
	fn covering_attrs(
		&self,
		desired_mt: &FsTree<ManagedMountPoint>,
		path: &std::ffi::OsStr,
	) -> MountAttributes {
		let mut best: Option<MountAttributes> = None;
		let mut best_len = 0usize;
		desired_mt.walk_top_down(|p, mp| {
			let pb = p.as_encoded_bytes();
			let path_b = path.as_encoded_bytes();
			// `p` must be a proper ancestor of `path`: either "/" or a
			// path that `path` continues with a '/' separator.
			let is_ancestor = if pb == b"/" {
				path_b != b"/"
			} else {
				path_b.len() > pb.len() && path_b.starts_with(pb) && path_b[pb.len()] == b'/'
			};
			if is_ancestor && pb.len() >= best_len {
				best_len = pb.len();
				best = Some(mp.attrs);
			}
		});
		best.unwrap_or_else(MountAttributes::ro)
	}

	pub fn check_covered<'a>(
		&self,
		path: &CStr,
		need_write: bool,
		need_exec: bool,
	) -> Result<(bool, Option<ManagedMountPoint>), BindMountSandboxError> {
		validate_sandbox_path(path)?;
		match self
			.current_mount_tree
			.lock()
			.expect("current_mount_tree lock poisoned")
			.find(OsStr::from_bytes(path.to_bytes()), |_, _| true)
		{
			None => return Ok((false, None)),
			Some((_, mnt)) => {
				if need_write && mnt.user.attrs.readonly {
					return Ok((false, Some(mnt.user.clone())));
				}
				if need_exec && mnt.user.attrs.noexec {
					return Ok((false, Some(mnt.user.clone())));
				}
				Ok((true, Some(mnt.user.clone())))
			}
		}
	}

	pub fn restrict_self(&self) -> Result<(), BindMountSandboxError> {
		self.sandbox.restrict_self()
	}

	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, BindMountSandboxError> {
		self.sandbox.run_command(cmd)
	}

	pub fn root_in_sandbox(&self) -> Result<ForeignFd, BindMountSandboxError> {
		self.sandbox.root_in_sandbox()
	}
}

#[cfg(test)]
mod sandbox_integration_tests {
	use super::*;

	/// Try to create a low-level sandbox.  Nested user namespaces are
	/// unavailable in many CI/build environments (and may be blocked by
	/// AppArmor); when setup fails we skip the test rather than fail, so
	/// these privileged integration tests are a no-op where they can't
	/// run but still exercise the m1 mount logic where they can.
	fn try_new_sandbox() -> Option<BindMountSandbox> {
		match BindMountSandbox::new(false) {
			Ok(sb) => Some(sb),
			Err(e) => {
				eprintln!("skipping privileged sandbox test: setup failed: {e}");
				None
			}
		}
	}

	fn mountinfo_has_mountpoint(raw: &[u8], mp: &[u8]) -> bool {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.any(|e| e.mount_point.as_encoded_bytes() == mp)
	}

	/// Return the bind source (`root` field) of the topmost mount at `mp`,
	/// if any.
	fn mountinfo_root_for(raw: &[u8], mp: &[u8]) -> Option<Vec<u8>> {
		mountinfo::parse_mountinfo(raw)
			.iter()
			.filter(|e| e.mount_point.as_encoded_bytes() == mp)
			.last()
			.map(|e| e.root.as_bytes().to_vec())
	}

	/// Exercise `read_m1_mountinfo` + `park_to_scratch` +
	/// `restore_from_scratch`: a mount parked into the hidden scratch
	/// tmpfs disappears from its original mountpoint, and restoring it
	/// brings the same mount back to that path.
	#[test]
	fn park_and_restore_roundtrip() {
		let Some(sb) = try_new_sandbox() else {
			return;
		};
		sb.mount_host_into_sandbox_impl(
			c"/etc",
			c"/etc",
			MountAttributes::ro(),
			false,
			false,
			true,
		)
		.expect("mount /etc");

		let before = sb.read_m1_mountinfo().expect("read mountinfo");
		assert!(
			mountinfo_has_mountpoint(&before, b"/etc"),
			"/etc should be mounted before parking"
		);

		sb.park_to_scratch(c"/etc", c"park-test")
			.expect("park /etc");
		let parked = sb.read_m1_mountinfo().expect("read mountinfo after park");
		assert!(
			!mountinfo_has_mountpoint(&parked, b"/etc"),
			"/etc must no longer be mounted after parking"
		);

		sb.restore_from_scratch(c"park-test", c"/etc")
			.expect("restore /etc");
		let after = sb
			.read_m1_mountinfo()
			.expect("read mountinfo after restore");
		assert!(
			mountinfo_has_mountpoint(&after, b"/etc"),
			"/etc must be mounted again after restore"
		);
	}

	/// Exercise `unmount_covering` (§6): a parent mount with a child
	/// sub-mount is unmounted while the child's `struct mount` identity is
	/// preserved.  Afterwards the parent is gone but the child
	/// is restored on the revealed placeholder layer.
	#[test]
	fn unmount_covering_preserves_child() {
		let Some(sb) = try_new_sandbox() else {
			return;
		};
		// Parent bind: /etc at /p (creates the /p placeholder).
		sb.mount_host_into_sandbox_impl(c"/etc", c"/p", MountAttributes::ro(), false, false, true)
			.expect("mount parent /p");
		// Child bind: /etc at /p/ssl (mountpoint /etc/ssl exists through the
		// /p bind; also creates a /p/ssl placeholder on the revealed layer).
		sb.mount_host_into_sandbox_impl(
			c"/etc",
			c"/p/ssl",
			MountAttributes::ro(),
			false,
			false,
			true,
		)
		.expect("mount child /p/ssl");

		let before = sb.read_m1_mountinfo().expect("read mountinfo");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p"),
			"/p should be mounted before unmount_covering"
		);
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl should be mounted before unmount_covering"
		);

		let unmounted = sb
			.unmount_covering(c"/p", &[CString::new("/p/ssl").unwrap()])
			.expect("unmount_covering /p");
		assert!(
			unmounted,
			"/p should have been unmounted (nothing holds it)"
		);

		let after = sb.read_m1_mountinfo().expect("read mountinfo after");
		assert!(
			!mountinfo_has_mountpoint(&after, b"/p"),
			"/p must be gone after unmount_covering"
		);
		assert!(
			mountinfo_has_mountpoint(&after, b"/p/ssl"),
			"/p/ssl child mount must be preserved after unmount_covering"
		);
	}

	/// End-to-end §6 check through the managed reconcile API: removing a
	/// parent mount that has a still-desired child preserves the child
	/// (the `Removed` branch routes through `unmount_covering`).
	#[test]
	fn managed_remove_preserves_child_mount() {
		let msb = match ManagedBindMountSandbox::new(false) {
			Ok(s) => s,
			Err(e) => {
				eprintln!("skipping privileged managed test: setup failed: {e}");
				return;
			}
		};
		let mp = ManagedMountPoint {
			host_path: CString::new("/etc").unwrap(),
			attrs: MountAttributes::ro(),
		};
		msb.add_or_update_mount(OsStr::new("/p"), mp.clone())
			.expect("add /p");
		msb.add_or_update_mount(OsStr::new("/p/ssl"), mp.clone())
			.expect("add /p/ssl");

		let before = msb.sandbox.read_m1_mountinfo().expect("mountinfo");
		assert!(mountinfo_has_mountpoint(&before, b"/p"), "/p mounted");
		assert!(
			mountinfo_has_mountpoint(&before, b"/p/ssl"),
			"/p/ssl mounted"
		);

		msb.remove_mount(OsStr::new("/p")).expect("remove /p");

		let after = msb.sandbox.read_m1_mountinfo().expect("mountinfo after");
		assert!(
			!mountinfo_has_mountpoint(&after, b"/p"),
			"/p must be removed"
		);
		assert!(
			mountinfo_has_mountpoint(&after, b"/p/ssl"),
			"/p/ssl child must be preserved through parent removal"
		);
	}

	/// A host_path change is handled as a §5 split (Removed then Added).
	/// The mountpoint must survive and rebind to the new host source.
	#[test]
	fn managed_host_path_change_rebinds() {
		let msb = match ManagedBindMountSandbox::new(false) {
			Ok(s) => s,
			Err(e) => {
				eprintln!("skipping privileged managed test: setup failed: {e}");
				return;
			}
		};
		msb.add_or_update_mount(
			OsStr::new("/p"),
			ManagedMountPoint {
				host_path: CString::new("/etc").unwrap(),
				attrs: MountAttributes::ro(),
			},
		)
		.expect("add /p -> /etc");
		let before = msb.sandbox.read_m1_mountinfo().expect("mountinfo");
		assert_eq!(
			mountinfo_root_for(&before, b"/p").as_deref(),
			Some(&b"/etc"[..]),
			"/p should bind /etc initially"
		);

		// Change the host source for the same sandbox path.
		msb.add_or_update_mount(
			OsStr::new("/p"),
			ManagedMountPoint {
				host_path: CString::new("/usr").unwrap(),
				attrs: MountAttributes::ro(),
			},
		)
		.expect("rebind /p -> /usr");

		let after = msb.sandbox.read_m1_mountinfo().expect("mountinfo after");
		assert!(
			mountinfo_has_mountpoint(&after, b"/p"),
			"/p must still be mounted after host_path change"
		);
		assert_eq!(
			mountinfo_root_for(&after, b"/p").as_deref(),
			Some(&b"/usr"[..]),
			"/p should bind /usr after the host_path change"
		);
	}
}
