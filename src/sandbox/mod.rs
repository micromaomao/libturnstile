use std::{
	borrow::Cow,
	ffi::{CStr, CString, OsStr},
	io, mem,
	os::{
		fd::{AsRawFd, IntoRawFd},
		unix::{ffi::OsStrExt, process::CommandExt},
	},
	sync::Mutex,
	thread,
};

use log::{debug, error, info};

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
mod utils;

use mount_obj::MountObj;
use namespace::ManagedNamespaces;
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
	root_tmpfs: MountObj,
	/// O_PATH fd to "/" opened inside the m0 (outer) mount namespace.
	/// Used as the dirfd when resolving caller-provided host paths so
	/// that the resulting fd is associated with m0's mount namespace and
	/// is therefore acceptable to `open_tree()` once the helper process
	/// enters m0.
	host_root_fd: ForeignFd,
	/// O_PATH fd to the *scratch* tmpfs root inside m1.  The scratch is
	/// a brand-new tmpfs (distinct from `root_tmpfs`) that is made m1's
	/// root and then shadowed beneath the `root_tmpfs` bind mount, so
	/// the sandboxed app never sees it.  It serves as a hidden,
	/// m1-owned parent into which mounts can be temporarily parked
	/// during reconcile (see `park_to_scratch`).  Resolving this fd from
	/// the supervisor side reaches the scratch directly.
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
		// capture an O_PATH handle to it.  This happens *before* the
		// root_tmpfs bind below, so the scratch ends up shadowed beneath
		// the placeholder root and is invisible to the app (see §1 of
		// design.fd-upgrade.md).  We enter l0_user (for privilege over
		// the nested user/mount namespaces) and l1_mnt (m1).
		let m1_scratch_fd = unsafe {
			let nsenter_fn = namespaces.nsenter_fn(true, false, true, false);
			let raw_fd = send_fd_from_ns(
				nsenter_fn,
				|| {
					// 1. fsmount a brand-new tmpfs (distinct from
					//    root_tmpfs).
					let scratch = MountObj::new_tmpfs()?;
					// 2. move_mount it onto "/" so it becomes m1's root
					//    and thus belongs to m1 (check_mnt passes),
					//    qualifying it as a move_mount target parent.
					scratch.mount(libc::AT_FDCWD, c"/", false)?;
					// 3. Open "/" (now the scratch) as an O_PATH dirfd.
					let fd = libc::open(
						c"/".as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
					);
					if fd < 0 {
						return Err(io::Error::last_os_error());
					}
					Ok(fd)
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
		// 4. Bind-mount root_tmpfs over m1's "/", shadowing the scratch.
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
	) -> Result<libc::stat, BindMountSandboxError> {
		validate_sandbox_path(ns_path)?;
		let mut open_how: libc::open_how = unsafe { std::mem::zeroed() };
		open_how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
		if !follow_host_symlinks {
			open_how.flags |= libc::O_NOFOLLOW as u64;
			open_how.resolve |= libc::RESOLVE_NO_SYMLINKS;
		}
		// openat2 ignores the dirfd when given an absolute path, so we
		// need to remove any leading '/'.
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
			let err = io::Error::last_os_error();
			return Err(BindMountSandboxError::ResolveHostPath(
				host_path.to_owned(),
				err,
			));
		}
		let host_fd = ForeignFd { local_fd: host_fd };

		let mut stat: libc::stat;
		unsafe {
			stat = std::mem::zeroed();
			if libc::fstat(host_fd.as_raw_fd(), &mut stat) != 0 {
				let err = io::Error::last_os_error();
				return Err(BindMountSandboxError::StatHostPath(
					host_path.to_owned(),
					err,
				));
			}
		}

		if create_placeholders {
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
				let res = libc::chdir(c"/".as_ptr());
				if res != 0 {
					return perror!("chdir");
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
		Ok(stat)
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
				let res = libc::chdir(c"/".as_ptr());
				if res != 0 {
					return perror!("chdir");
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
				let res = libc::chdir(c"/".as_ptr());
				if res != 0 {
					return perror!("chdir");
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
	/// and the reconcile choreography (opening child mounts and mount
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
					if libc::chdir(c"/".as_ptr()) != 0 {
						return Err(io::Error::last_os_error());
					}
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
						let n = libc::read(
							read_fd,
							buf.as_mut_ptr() as *mut libc::c_void,
							buf.len(),
						);
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
					match nsenter_fn() {
						Ok(()) => (),
						Err(e) => {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to enter m1 for mountinfo: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					}
					let src = libc::open(
						c"/proc/self/mountinfo".as_ptr(),
						libc::O_RDONLY | libc::O_CLOEXEC,
					);
					if src < 0 {
						return perror!("open(/proc/self/mountinfo)");
					}
					let mut buf = [0u8; 8192];
					loop {
						let n =
							libc::read(src, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
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
	/// tmpfs at `scratch/<uuid>`, preserving its `struct mount` identity.
	/// Used to temporarily "park" a child (or a soon-to-be-rebuilt
	/// parent's descendants) out of the way during reconcile so a
	/// non-`MNT_DETACH` umount of its old location can proceed.  The
	/// `uuid` must be a single path component (no slashes).
	pub fn park_to_scratch(
		&self,
		ns_path: &CStr,
		uuid: &CStr,
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
				if libc::chdir(c"/".as_ptr()) != 0 {
					return perror!("chdir");
				}
				// Create scratch/<uuid> to receive the parked mount.
				if libc::mkdirat(scratch_fd, uuid.as_ptr(), 0o700) != 0 {
					let err = libc::__errno_location().read();
					if err != libc::EEXIST {
						return perror!("mkdirat(scratch/uuid)");
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
					uuid.as_ptr(),
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

	/// Move a previously parked mount at `scratch/<uuid>` back to
	/// `dest` (an absolute m1 path whose mountpoint dentry must exist),
	/// then remove the now-empty `scratch/<uuid>` directory.  The inverse
	/// of [`Self::park_to_scratch`].
	pub fn restore_from_scratch(
		&self,
		uuid: &CStr,
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
				if libc::chdir(c"/".as_ptr()) != 0 {
					return perror!("chdir");
				}
				let mut openhow: libc::open_how = mem::zeroed();
				openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
				openhow.resolve = libc::RESOLVE_NO_SYMLINKS;
				let src_fd = libc::syscall(
					libc::SYS_openat2,
					scratch_fd,
					uuid.as_ptr(),
					&openhow as *const _,
					std::mem::size_of::<libc::open_how>(),
				) as libc::c_int;
				if src_fd < 0 {
					return perror!("openat2(scratch/uuid)");
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
				libc::unlinkat(scratch_fd, uuid.as_ptr(), libc::AT_REMOVEDIR);
				0
			})
		}
		.map_err(BindMountSandboxError::ForkError)?;
		if fork_res != 0 {
			return Err(BindMountSandboxError::RestoreFromScratchFailed(fork_res));
		}
		Ok(())
	}

	/// Join the current thread into the sandbox.  This can be used
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
	current_mount_tree: Mutex<FsTree<ManagedMountPoint>>,
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
	pub fn add_or_update_entry(
		&self,
		path: &OsStr,
		entry: ManagedTreeEntry,
	) -> Result<(), BindMountSandboxError> {
		Self::check_path_no_nul(path)?;
		let (mut pt, mut mt) = self.lock_trees();
		let mut desired_entries = self.entries_from_state(&pt, &mt);
		desired_entries.insert(path, entry);
		self.reconcile(&mut pt, &mut mt, &desired_entries)
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
		self.reconcile(&mut pt, &mut mt, &desired_entries)
	}

	pub fn remove_mount(&self, path: &OsStr) -> Result<(), BindMountSandboxError> {
		self.remove_entry(path)
	}

	pub fn update_from_tree(
		&self,
		desired_tree: &FsTree<ManagedTreeEntry>,
	) -> Result<(), BindMountSandboxError> {
		let (mut pt, mut mt) = self.lock_trees();
		self.reconcile(&mut pt, &mut mt, desired_tree)
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
		std::sync::MutexGuard<'_, FsTree<ManagedMountPoint>>,
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
		mt: &FsTree<ManagedMountPoint>,
	) -> FsTree<ManagedTreeEntry> {
		let mut out = FsTree::new();
		pt.walk_top_down(|path, ph| {
			out.insert(path, ManagedTreeEntry::Placeholder(ph.clone()));
		});
		mt.walk_top_down(|path, mp| {
			out.insert(path, ManagedTreeEntry::BindMount(mp.clone()));
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
	fn reconcile(
		&self,
		current_pt: &mut FsTree<ManagedPlaceholder>,
		current_mt: &mut FsTree<ManagedMountPoint>,
		desired_entries: &FsTree<ManagedTreeEntry>,
	) -> Result<(), BindMountSandboxError> {
		let (desired_pt, desired_mt) = self.build_desired_trees(desired_entries)?;
		debug!("Current placeholder tree: {:?}", current_pt);
		debug!("Desired placeholder tree: {:?}", desired_pt);
		debug!("Current mount tree: {:?}", current_mt);
		debug!("Desired mount tree: {:?}", desired_mt);

		let mut new_pt = current_pt.clone();
		let mut new_mt = current_mt.clone();

		// Phase 1: create / update placeholders top-down.
		let mut err: Option<BindMountSandboxError> = None;
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				if err.is_some() {
					return;
				}
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Added(new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							err = Some(e);
							return;
						}
						new_pt.insert(sandbox_path, new.clone());
					}
					crate::fstree::DiffTree::Updated(_, new) => {
						if let Err(e) = self.apply_placeholder(&ns_path, new) {
							err = Some(e);
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
		if let Some(e) = err {
			*current_pt = new_pt;
			return Err(e);
		}

		// Phase 2: mounts diff.
		let mut err: Option<BindMountSandboxError> = None;
		current_mt.diff(
			&desired_mt,
			|sandbox_path, diff| {
				if err.is_some() {
					return;
				}
				let ns_path =
					CString::new(sandbox_path.as_encoded_bytes()).expect("checked for NUL byte");
				match diff {
					crate::fstree::DiffTree::Removed(_) => {
						if let Err(e) = self.sandbox.unmount(&ns_path, true) {
							err = Some(e);
							return;
						}
						new_mt.remove(sandbox_path);
					}
					crate::fstree::DiffTree::Added(new) => {
						if let Err(e) = self.sandbox.mount_host_into_sandbox_impl(
							&new.host_path,
							&ns_path,
							new.attrs,
							false,
							false,
							false,
						) {
							err = Some(e);
							return;
						}
						new_mt.insert(sandbox_path, (*new).clone());
					}
					crate::fstree::DiffTree::Updated(old, new) => {
						assert_eq!(old.host_path, new.host_path);
						if old.attrs != new.attrs {
							if let Err(e) =
								self.sandbox.set_mount_attr(&ns_path, new.attrs, old.attrs)
							{
								err = Some(e);
								return;
							}
							*new_mt.get_mut(sandbox_path).expect("must exist") = (*new).clone();
						}
					}
				}
			},
			|_, old, new| old.host_path != new.host_path,
			true,
		);
		if let Some(e) = err {
			*current_pt = new_pt;
			*current_mt = new_mt;
			return Err(e);
		}

		// Phase 3: remove placeholders no longer desired (bottom-up).
		let mut err: Option<BindMountSandboxError> = None;
		current_pt.diff(
			&desired_pt,
			|sandbox_path, diff| {
				if err.is_some() {
					return;
				}
				if matches!(diff, crate::fstree::DiffTree::Removed(_)) {
					let ns_path = CString::new(sandbox_path.as_encoded_bytes())
						.expect("checked for NUL byte");
					if ns_path.as_c_str() == c"/" {
						return;
					}
					if let Err(e) = self.sandbox.remove_placeholder(&ns_path) {
						err = Some(e);
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
		match err {
			Some(e) => Err(e),
			None => Ok(()),
		}
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
	) -> Result<(FsTree<ManagedPlaceholder>, FsTree<ManagedMountPoint>), BindMountSandboxError> {
		let mut placeholders: FsTree<ManagedPlaceholder> = FsTree::new();
		let mut mounts: FsTree<ManagedMountPoint> = FsTree::new();
		let mut err: Option<BindMountSandboxError> = None;
		desired_entries.walk_top_down(|path, entry| {
			if err.is_some() {
				return;
			}
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
						let stat = match stat_host(&mp.host_path) {
							Ok(s) => s,
							Err(e) => {
								err = Some(e);
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
		if let Some(e) = err {
			return Err(e);
		}
		placeholders.fill_incomplete_parent(|_| placeholder_default_no_metadata(true));
		Ok((placeholders, mounts))
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
				if need_write && mnt.attrs.readonly {
					return Ok((false, Some(mnt.clone())));
				}
				if need_exec && mnt.attrs.noexec {
					return Ok((false, Some(mnt.clone())));
				}
				Ok((true, Some(mnt.clone())))
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
