use std::{
	borrow::Cow,
	ffi::{CStr, CString, OsStr},
	io,
	os::{fd::AsRawFd, unix::process::CommandExt},
	thread,
};

use log::{debug, error, info};
use smallvec::SmallVec;

use crate::{
	BindMountSandboxError, TurnstileTracer,
	fs::ForeignFd,
	utils::{fork_wait, unix_recv_fd, unix_send_fd},
};

#[derive(Debug)]
struct ManagedNamespaces {
	pub l0_user: ForeignFd,
	pub l0_mnt: ForeignFd,
	pub l1_user: ForeignFd,
	pub l1_mnt: ForeignFd,
}

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

impl ManagedNamespaces {
	pub fn new(disable_userns: bool) -> Result<Self, BindMountSandboxError> {
		// These functions are always successful
		let uid = unsafe { libc::getuid() };
		let gid = unsafe { libc::getgid() };

		let uid_map = format!("0 {} 1\n", uid);
		let gid_map = format!("0 {} 1\n", gid);
		let uid_map_back = format!("{} 0 1\n", uid);
		let gid_map_back = format!("{} 0 1\n", gid);

		let mut sock = [-1, -1];
		let res = unsafe {
			libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				sock.as_mut_ptr(),
			)
		};
		if res != 0 {
			error!("socketpair failed: {}", io::Error::last_os_error());
			return Err(BindMountSandboxError::Socketpair(io::Error::last_os_error()));
		}
		let parent_sock = sock[0];
		let child_sock = sock[1];

		let namespaces = thread::scope(
			|s| -> Result<
				(libc::c_int, libc::c_int, libc::c_int, libc::c_int),
				BindMountSandboxError,
			> {
				let jh = s.spawn(|| unsafe {
					let fds = unix_recv_fd(parent_sock).and_then(|fd1| {
						unix_recv_fd(parent_sock).and_then(|fd2| {
							unix_recv_fd(parent_sock).and_then(|fd3| {
								unix_recv_fd(parent_sock).map(|fd4| (fd1, fd2, fd3, fd4))
							})
						})
					});
					libc::close(parent_sock);
					match fds {
						Ok(fds) => Ok(fds),
						Err(e) => Err(BindMountSandboxError::ReceiveNamespaceFd(e)),
					}
				});
				let res = unsafe {
					let res = fork_wait(|| {
						libc::close(parent_sock);

						let res = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS);
						if res != 0 {
							return perror!("unshare(CLONE_NEWUSER|CLONE_NEWNS)");
						}
						let res = write_to_path(c"/proc/self/uid_map", &uid_map);
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/setgroups", "deny");
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/gid_map", &gid_map);
						if res != 0 {
							return res;
						}
						let ns_fd = libc::open(
							c"/proc/self/ns/user".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if ns_fd < 0 {
							return perror!("open user ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, ns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 0 userns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(ns_fd);

						if disable_userns {
							let res = write_to_path(c"/proc/sys/user/max_user_namespaces", "1");
							if res != 0 {
								return res;
							}
						}

						let mntns_fd = libc::open(
							c"/proc/self/ns/mnt".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if mntns_fd < 0 {
							return perror!("open mount ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, mntns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!(
									"Failed to send level 0 mount namespace fd to parent: {}",
									e
								);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(mntns_fd);

						let res = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS);
						if res != 0 {
							return perror!("unshare(CLONE_NEWUSER|CLONE_NEWNS)");
						}
						let res = write_to_path(c"/proc/self/uid_map", &uid_map_back);
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/setgroups", "deny");
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/gid_map", &gid_map_back);
						if res != 0 {
							return res;
						}
						let l1_ns_fd = libc::open(
							c"/proc/self/ns/user".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if l1_ns_fd < 0 {
							return perror!("open nested user ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, l1_ns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 1 user ns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(l1_ns_fd);

						let l1_mnt_fd = libc::open(
							c"/proc/self/ns/mnt".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if l1_mnt_fd < 0 {
							return perror!("open nested mount ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, l1_mnt_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 1 mount ns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(l1_mnt_fd);
						0
					})
					.map_err(BindMountSandboxError::ForkError)?;
					libc::close(child_sock);
					res
				};
				if res != 0 {
					_ = jh.join();
					return Err(match res {
						libc::EPERM | libc::ENOSPC => BindMountSandboxError::UserNsNotAllowed,
						err => BindMountSandboxError::NamespaceSetupFailed(err),
					});
				}
				let namespaces = jh.join().expect("Namespace setup thread panicked")?;
				Ok(namespaces)
			},
		)?;
		let l0u = ForeignFd {
			local_fd: namespaces.0,
		};
		let l0m = ForeignFd {
			local_fd: namespaces.1,
		};
		let l1u = ForeignFd {
			local_fd: namespaces.2,
		};
		let l1m = ForeignFd {
			local_fd: namespaces.3,
		};
		debug!(
			"Successfully set up namespaces: {:?}, {:?}, {:?}, {:?}",
			l0u.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l0m.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l1u.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l1m.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
		);
		Ok(Self {
			l0_user: l0u,
			l0_mnt: l0m,
			l1_user: l1u,
			l1_mnt: l1m,
		})
	}

	pub unsafe fn nsenter_fn(
		&self,
		usr_0: bool,
		mnt_0: bool,
		mnt_1: bool,
		usr_1: bool,
	) -> impl Fn() -> io::Result<()> + 'static {
		let mut ns_fds = SmallVec::<[libc::c_int; 4]>::new();
		if usr_0 {
			ns_fds.push(self.l0_user.as_raw_fd());
		}
		if mnt_0 {
			ns_fds.push(self.l0_mnt.as_raw_fd());
		}
		if mnt_1 {
			ns_fds.push(self.l1_mnt.as_raw_fd());
		}
		if usr_1 {
			ns_fds.push(self.l1_user.as_raw_fd());
		}
		move || unsafe {
			for (i, &fd) in ns_fds.iter().enumerate() {
				let res = libc::setns(fd, 0);
				if res != 0 {
					let err = libc::__errno_location().read();
					if ENABLE_LOG_IN_FORK {
						error!(
							"setns for fd ns_fds[{}] (= {}) failed with errno {}",
							i, fd, err
						);
					}
					return Err(io::Error::from_raw_os_error(err));
				} else if ENABLE_LOG_IN_FORK {
					debug!("Joined namespace ns_fds[{}] = {}", i, fd);
				}
			}
			Ok(())
		}
	}
}

#[derive(Debug)]
pub struct MountObj(ForeignFd);

#[derive(Debug, Default, Clone, Copy)]
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

impl MountObj {
	pub fn new_tmpfs() -> io::Result<Self> {
		unsafe {
			// libc::FSOPEN_CLOEXEC does not exist yet
			let fs = libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 0) as libc::c_int;
			if fs < 0 {
				let err = perror!("fsopen(tmpfs)");
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_SET_STRING */ 1,
				c"source".as_ptr(),
				c"tmpfs".as_ptr(),
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(source=tmpfs)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_SET_STRING */ 1,
				c"size".as_ptr(),
				c"16M".as_ptr(),
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(size=16M)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_CMD_CREATE */ 6,
				0,
				0,
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(CMD_CREATE)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			// libc::FSMOUNT_CLOEXEC does not exist yet
			let mnt = libc::syscall(libc::SYS_fsmount, fs, 0, 0) as libc::c_int;
			if mnt < 0 {
				let err = perror!("fsmount");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			libc::close(fs);
			Ok(Self(ForeignFd { local_fd: mnt }))
		}
	}

	pub unsafe fn new_from_fd(fd: libc::c_int) -> Self {
		Self(ForeignFd { local_fd: fd })
	}

	pub fn new_bind(
		source_dfd: libc::c_int,
		source_path: &CStr,
		attrs: MountAttributes,
		follow_source_symlinks: bool,
	) -> io::Result<Self> {
		let mut flags =
			libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_RECURSIVE as libc::c_uint;
		if source_path.is_empty() {
			flags |= libc::AT_EMPTY_PATH as libc::c_uint;
		}
		if !follow_source_symlinks {
			flags |= libc::AT_SYMLINK_NOFOLLOW as libc::c_uint;
		}
		unsafe {
			let mnt = libc::syscall(libc::SYS_open_tree, source_dfd, source_path.as_ptr(), flags)
				as libc::c_int;
			if mnt < 0 {
				let err = perror!("open_tree");
				return Err(io::Error::from_raw_os_error(err));
			}
			let mnt = Self(ForeignFd { local_fd: mnt });
			mnt.setattr(attrs, MountAttributes::default())?;
			Ok(mnt)
		}
	}

	/// When updating the attributes on an existing mount, pass in the
	/// existing attributes to avoid EPERM errors caused by trying to
	/// clear attributes that we didn't set ourselves (and thus have no
	/// rights to clear).
	pub fn setattr(
		&self,
		attrs: MountAttributes,
		existing_attr: MountAttributes,
	) -> io::Result<()> {
		unsafe {
			let mut mount_attr = std::mem::zeroed::<libc::mount_attr>();
			if attrs.readonly && !existing_attr.readonly {
				mount_attr.attr_set |= libc::MOUNT_ATTR_RDONLY;
			} else if !attrs.readonly && existing_attr.readonly {
				mount_attr.attr_clr |= libc::MOUNT_ATTR_RDONLY;
			}
			if attrs.noexec && !existing_attr.noexec {
				mount_attr.attr_set |= libc::MOUNT_ATTR_NOEXEC;
			} else if !attrs.noexec && existing_attr.noexec {
				mount_attr.attr_clr |= libc::MOUNT_ATTR_NOEXEC;
			}
			let res = libc::syscall(
				libc::SYS_mount_setattr,
				self.0.as_raw_fd(),
				c"".as_ptr(),
				libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
				&mount_attr as *const _,
				std::mem::size_of::<libc::mount_attr>(),
			);
			if res != 0 {
				let err = perror!("mount_setattr");
				return Err(io::Error::from_raw_os_error(err));
			}
			Ok(())
		}
	}

	pub fn mount(
		&self,
		dest_dfd: libc::c_int,
		dest_path: &CStr,
		follow_dest_symlink: bool,
	) -> io::Result<()> {
		let mut flags = libc::MOVE_MOUNT_F_EMPTY_PATH;
		if follow_dest_symlink {
			flags |= libc::MOVE_MOUNT_T_SYMLINKS;
		}
		if dest_path.is_empty() {
			flags |= libc::MOVE_MOUNT_T_EMPTY_PATH;
		}
		unsafe {
			let res = libc::syscall(
				libc::SYS_move_mount,
				self.0.as_raw_fd(),
				c"".as_ptr(),
				dest_dfd,
				dest_path.as_ptr(),
				flags,
			);
			if res != 0 {
				let err = perror!("move_mount");
				return Err(io::Error::from_raw_os_error(err));
			}
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct BindMountSandbox {
	tracer: TurnstileTracer,
	namespaces: ManagedNamespaces,
	root_tmpfs: MountObj,
}

#[derive(Debug)]
pub struct MountBuilder<'a, 'b> {
	host_path: &'a CStr,
	sandbox_path: &'a CStr,
	attrs: MountAttributes,
	follow_host_symlinks: bool,
	follow_sandbox_symlinks: bool,
	sandbox: &'b BindMountSandbox,
}

impl<'a, 'b> MountBuilder<'a, 'b> {
	pub fn attributes(&mut self, attrs: MountAttributes) -> &mut Self {
		self.attrs = attrs;
		self
	}

	/// If host path points into a location controllable or writable by
	/// the sandboxed process, this must not be used.
	pub fn follow_host_symlinks(&mut self, follow: bool) -> &mut Self {
		self.follow_host_symlinks = follow;
		self
	}

	pub fn follow_sandbox_symlinks(&mut self, follow: bool) -> &mut Self {
		self.follow_sandbox_symlinks = follow;
		self
	}

	pub fn mount(self) -> Result<(), BindMountSandboxError> {
		self.sandbox._mount_host_into_sandbox(
			self.host_path,
			self.sandbox_path,
			self.attrs,
			self.follow_host_symlinks,
			self.follow_sandbox_symlinks,
		)
	}
}

impl BindMountSandbox {
	pub fn new(disable_userns: bool) -> Result<Self, BindMountSandboxError> {
		let tracer = TurnstileTracer::new().map_err(BindMountSandboxError::TurnstileTracerError)?;
		let namespaces = ManagedNamespaces::new(disable_userns)?;
		let root_tmpfs = unsafe {
			MountObj::new_from_fd(thread::scope(
				|s| -> Result<libc::c_int, BindMountSandboxError> {
					let mut sock = [-1, -1];
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

					let jh = s.spawn(move || -> Result<libc::c_int, BindMountSandboxError> {
						let recv_res = unix_recv_fd(parent_sock);
						libc::close(parent_sock);
						recv_res.map_err(BindMountSandboxError::ReceiveMountFd)
					});

					let nsenter_fn = namespaces.nsenter_fn(true, true, false, false);
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
						let ret = match MountObj::new_tmpfs() {
							Ok(mnt) => {
								let fd = mnt.0.as_raw_fd();
								if let Err(e) = unix_send_fd(child_sock, fd) {
									if ENABLE_LOG_IN_FORK {
										error!("Failed to send mount fd to parent: {}", e);
									}
									return e.raw_os_error().unwrap_or(libc::EIO);
								}
								// fd will be closed by mnt's Drop
								0
							}
							Err(e) => {
								if ENABLE_LOG_IN_FORK {
									error!("Failed to create tmpfs mount: {}", e);
								}
								e.raw_os_error().unwrap_or(libc::EIO)
							}
						};
						libc::close(child_sock);
						ret
					})
					.map_err(BindMountSandboxError::ForkError)?;
					libc::close(child_sock);
					if fork_res != 0 {
						return Err(BindMountSandboxError::MakeDetachedTmpfsMountFailed(
							fork_res,
						));
					}
					jh.join().expect("Child thread panicked")
				},
			)?)
		};
		let s = Self {
			tracer,
			namespaces,
			root_tmpfs,
		};
		s._mount_host_into_sandbox(
			CStr::from_bytes_with_nul(
				format!("/proc/self/fd/{}\0", s.root_tmpfs.0.as_raw_fd()).as_bytes(),
			)
			.unwrap(),
			c"/",
			MountAttributes::ro(),
			true,
			false,
		)?;
		Ok(s)
	}

	pub fn create_hierarchy_within_ns(
		&self,
		path: &CStr,
		leaf_is_dir: bool,
	) -> Result<ForeignFd, BindMountSandboxError> {
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
			let newfd = loop {
				unsafe {
					let newfd = libc::openat(
						fd.as_raw_fd(),
						comp.as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC,
					);
					if newfd < 0 {
						let err = io::Error::last_os_error();
						if err.kind() == io::ErrorKind::NotFound {
							match !is_leaf || leaf_is_dir {
								true => {
									let ret = libc::mkdirat(fd.as_raw_fd(), comp.as_ptr(), 0o755);
									if ret != 0 {
										let err = io::Error::last_os_error();
										if err.kind() == io::ErrorKind::AlreadyExists {
											continue;
										}
										return Err(BindMountSandboxError::Mkdir(err));
									}
									debug!("Created directory {:?} in sandbox", comp);
								}
								false => {
									let ret = libc::openat(
										fd.as_raw_fd(),
										comp.as_ptr(),
										libc::O_CREAT | libc::O_WRONLY,
										0o644,
									);
									if ret < 0 {
										let err = io::Error::last_os_error();
										if err.kind() == io::ErrorKind::IsADirectory {
											continue;
										}
										return Err(BindMountSandboxError::Mkfile(err));
									}
									libc::close(ret);
									debug!("Created file {:?} in sandbox", comp);
								}
							};
							continue;
						} else {
							return Err(BindMountSandboxError::ResolveSandboxPath(err));
						}
					} else {
						let newfd = ForeignFd { local_fd: newfd };
						let mut stat: libc::stat = std::mem::zeroed();
						if libc::fstat(newfd.as_raw_fd(), &mut stat) != 0 {
							let err = io::Error::last_os_error();
							return Err(BindMountSandboxError::StatSandboxPath(err));
						}
						let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
						let expect_is_dir = !is_leaf || leaf_is_dir;
						if is_dir == expect_is_dir {
							break newfd;
						}
						let ret = libc::unlinkat(
							fd.as_raw_fd(),
							comp.as_ptr(),
							if is_dir { libc::AT_REMOVEDIR } else { 0 },
						);
						if ret != 0 {
							let err = io::Error::last_os_error();
							return Err(BindMountSandboxError::RemoveSandboxPath(err));
						}
						continue;
					}
				}
			};
			fd = newfd;
		}
		Ok(fd)
	}

	/// If host_path points into a place controllable by the sandboxed
	/// process, follow_host_symlinks must be false.
	pub(self) fn _mount_host_into_sandbox(
		&self,
		host_path: &CStr,
		ns_path: &CStr,
		attrs: MountAttributes,
		follow_host_symlinks: bool,
		follow_ns_symlinks: bool,
	) -> Result<(), BindMountSandboxError> {
		if !ns_path.to_bytes().starts_with(b"/") {
			panic!("ns_path must be an absolute path");
		}
		let mut open_how: libc::open_how = unsafe { std::mem::zeroed() };
		open_how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
		if !follow_host_symlinks {
			open_how.flags |= libc::O_NOFOLLOW as u64;
			open_how.resolve |= libc::RESOLVE_NO_SYMLINKS;
		}
		let host_fd = unsafe {
			libc::syscall(
				libc::SYS_openat2,
				libc::AT_FDCWD,
				host_path.as_ptr(),
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

		self.create_hierarchy_within_ns(ns_path, stat.st_mode & libc::S_IFMT == libc::S_IFDIR)?;

		let nsenter_fn_m0 = unsafe { self.namespaces.nsenter_fn(true, true, false, false) };
		let nsenter_fn_m1 = unsafe { self.namespaces.nsenter_fn(false, false, true, false) };
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
				// We can't use host_fd here because it belongs to the
				// host namespace, and will be rejected by open_tree().
				// Let's open again.
				// TODO: ideally BindMountSandbox will save a fd to the
				// m9's root so we can just do this outside.
				let host_fd = libc::syscall(
					libc::SYS_openat2,
					libc::AT_FDCWD,
					host_path.as_ptr(),
					&open_how,
					std::mem::size_of_val(&open_how),
				) as libc::c_int;
				if host_fd < 0 {
					let err = libc::__errno_location().read();
					if ENABLE_LOG_IN_FORK {
						error!(
							"Failed to open host path {:?} in mount helper process: errno {}",
							host_path, err
						);
					}
					return err;
				}
				let host_fd = ForeignFd { local_fd: host_fd };
				let source_tree =
					match MountObj::new_bind(host_fd.as_raw_fd(), c"", attrs, follow_host_symlinks)
					{
						Ok(tree) => tree,
						Err(e) => {
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
					};
				drop(host_fd);
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
		Ok(())
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
			follow_sandbox_symlinks: false,
			sandbox: self,
		}
	}

	pub fn set_mount_attr_within_ns(
		&self,
		ns_path: &CStr,
		attrs: MountAttributes,
		existing_attrs: MountAttributes,
	) -> Result<(), BindMountSandboxError> {
		if !ns_path.to_bytes().starts_with(b"/") {
			panic!("ns_path must be an absolute path");
		}
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
				let fd = libc::open(ns_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
				if fd < 0 {
					return perror!("open");
				}
				let mnt = MountObj::new_from_fd(fd);
				match mnt.setattr(attrs, existing_attrs) {
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
		unsafe {
			let nsenter_fn = self.namespaces.nsenter_fn(true, true, true, true);
			cmd.pre_exec(move || {
				match nsenter_fn() {
					Ok(()) => (),
					Err(e) => {
						if ENABLE_LOG_IN_FORK {
							error!("Failed to enter namespaces: {}", e);
						}
						return Err(e);
					}
				}
				let chdir = libc::chdir(new_cwd_cstr.as_ptr());
				if chdir != 0 {
					let err = perror!("chdir");
					if ENABLE_LOG_IN_FORK {
						error!("Failed to chdir to {:?}: errno {}", new_cwd_cstr, err);
					}
					return Err(io::Error::from_raw_os_error(err));
				}
				Ok(())
			})
		};
		let child = cmd.spawn().map_err(BindMountSandboxError::Spawn)?;
		Ok(child)
	}
}
