use std::{ffi::CString, io, os::unix::io::AsRawFd};

use libseccomp::{ScmpFilterContext, ScmpSyscall};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError, syscalls::RequestContext,
};

use super::lazy_syscall_table_name_to_number;

use log::warn;

#[derive(Debug)]
pub(crate) struct ForeignFd {
	local_fd: libc::c_int,
}

impl ForeignFd {
	pub(crate) fn from_path(path: &str) -> Result<Self, io::Error> {
		let local_fd = unsafe {
			libc::open(
				path.as_ptr() as *const libc::c_char,
				libc::O_PATH | libc::O_CLOEXEC,
				0,
			)
		};
		if local_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { local_fd })
	}
}

impl AsRawFd for ForeignFd {
	fn as_raw_fd(&self) -> libc::c_int {
		self.local_fd
	}
}

impl Drop for ForeignFd {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.local_fd);
		}
	}
}

impl Clone for ForeignFd {
	fn clone(&self) -> Self {
		let duped_fd = unsafe { libc::dup(self.local_fd) };
		if duped_fd < 0 {
			panic!("Failed to dup fd: {}", io::Error::last_os_error());
		}
		Self { local_fd: duped_fd }
	}
}

/// Most filesystem syscalls on Linux accept target paths in the form of a
/// "base" fd (which may implicitly be the current working directory), and
/// a path either relative to that fd, or absolute (in which case the base
/// fd is ignored).
///
/// Since the base fd is provided by the traced process, unless it
/// provides an invalid fd, it is always guaranteed to exist.  The path,
/// however, may either point to an non-existent entry in an existing
/// directory, or a completely non-existent place even ignoring the last
/// component.
///
/// Some syscalls also accepts an empty path, in which case the target is
/// the base fd itself.
///
/// This struct preserves what was passed by the traced process, except
/// that the base fd is opened by us from /proc, and so we have a local
/// reference to the base location that will still be valid even if the
/// traced process terminates.
#[derive(Debug, Clone)]
pub struct FsTarget {
	/// None if path is absolute.
	pub(crate) dfd: Option<ForeignFd>,

	pub(crate) path: CString,

	/// Whether to avoid following the final symlink component when resolving
	/// this target (corresponds to AT_SYMLINK_NOFOLLOW).
	pub(crate) no_follow: bool,
}

impl FsTarget {
	pub(crate) fn from_path(
		req: &mut RequestContext,
		path_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let pathb = path.as_bytes();
		if pathb.len() > 0 && pathb[0] == b'/' {
			Ok(Self {
				dfd: None,
				path,
				no_follow: false,
			})
		} else {
			let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
			Ok(Self {
				dfd: Some(
					ForeignFd::from_path(&cwdstr)
						.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
				),
				path,
				no_follow: false,
			})
		}
	}

	pub(crate) fn from_at_path(
		req: &mut RequestContext,
		dfd_arg_index: u8,
		path_arg_index: u8,
		at_flags: Option<u64>,
	) -> Result<Self, AccessRequestError> {
		let at_empty_path = at_flags.map_or(false, |f| f & libc::AT_EMPTY_PATH as u64 != 0);
		let no_follow = at_flags.map_or(false, |f| f & libc::AT_SYMLINK_NOFOLLOW as u64 != 0);

		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let dfd = libc::c_int::try_from(req.arg(dfd_arg_index as usize) as i64)
			.map_err(|_| AccessRequestError::InvalidSyscallData("dfd arg not a valid c_int"))?;
		let pathb = path.as_bytes();

		// AT_EMPTY_PATH: if path is empty, the target is the dfd itself.
		if at_empty_path && pathb.is_empty() {
			if dfd == libc::AT_FDCWD {
				let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
				return Ok(Self {
					dfd: Some(
						ForeignFd::from_path(&cwdstr)
							.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
					),
					path,
					no_follow,
				});
			} else if dfd < 0 {
				return Err(AccessRequestError::InvalidSyscallData("dfd invalid"));
			} else {
				let proc_fd_path = format!("/proc/{}/fd/{}", req.sreq.pid, dfd);
				return Ok(Self {
					dfd: Some(
						ForeignFd::from_path(&proc_fd_path)
							.map_err(|e| AccessRequestError::OpenFd(proc_fd_path, e))?,
					),
					path,
					no_follow,
				});
			}
		}

		if pathb.len() > 0 && pathb[0] == b'/' {
			return Ok(Self {
				dfd: None,
				path,
				no_follow,
			});
		}
		if dfd == libc::AT_FDCWD {
			let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
			Ok(Self {
				dfd: Some(
					ForeignFd::from_path(&cwdstr)
						.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
				),
				path,
				no_follow,
			})
		} else {
			if dfd < 0 {
				Err(AccessRequestError::InvalidSyscallData("dfd invalid"))
			} else {
				let proc_fd_path = format!("/proc/{}/fd/{}", req.sreq.pid, dfd);
				Ok(Self {
					dfd: Some(
						ForeignFd::from_path(&proc_fd_path)
							.map_err(|e| AccessRequestError::OpenFd(proc_fd_path, e))?,
					),
					path,
					no_follow,
				})
			}
		}
	}

	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<libc::c_int, io::Error> {
		let path_bytes = self.path.to_bytes();

		// AT_EMPTY_PATH: the target is the dfd itself — dup it.
		if path_bytes.is_empty() {
			if let Some(dfd) = &self.dfd {
				let fd = unsafe { libc::fcntl(dfd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
				if fd < 0 {
					return Err(io::Error::last_os_error());
				}
				return Ok(fd);
			}
			return Err(io::Error::from_raw_os_error(libc::ENOENT));
		}

		let mut flags = libc::O_PATH | libc::O_CLOEXEC;
		if self.no_follow {
			flags |= libc::O_NOFOLLOW;
		}
		let fd = match &self.dfd {
			None => unsafe { libc::open(self.path.as_ptr(), flags, 0) },
			Some(dfd) => unsafe { libc::openat(dfd.as_raw_fd(), self.path.as_ptr(), flags, 0) },
		};
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(fd)
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	pub fn open_target_dir(&self) -> Result<(libc::c_int, &str), io::Error> {
		let path_bytes = self.path.to_bytes();

		let (dir_cstr, file_part) = if let Some(last_slash) =
			path_bytes.iter().rposition(|&b| b == b'/')
		{
			let dir_bytes = &path_bytes[..last_slash];
			let dir_cstr = if dir_bytes.is_empty() {
				CString::new("/").unwrap()
			} else {
				CString::new(dir_bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
			};
			let file_part = std::str::from_utf8(&path_bytes[last_slash + 1..])
				.map_err(|_| io::Error::from_raw_os_error(libc::EILSEQ))?;
			(dir_cstr, file_part)
		} else {
			// No slash — the directory is the base (dfd or cwd).
			let file_part = std::str::from_utf8(path_bytes)
				.map_err(|_| io::Error::from_raw_os_error(libc::EILSEQ))?;
			(CString::new(".").unwrap(), file_part)
		};

		let dir_fd = match &self.dfd {
			None => unsafe {
				libc::open(
					dir_cstr.as_ptr(),
					libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
					0,
				)
			},
			Some(dfd) => unsafe {
				libc::openat(
					dfd.as_raw_fd(),
					dir_cstr.as_ptr(),
					libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
					0,
				)
			},
		};
		if dir_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok((dir_fd, file_part))
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<String, io::Error> {
		let path_bytes = self.path.to_bytes();

		// AT_EMPTY_PATH: the target is the dfd itself — read its proc symlink.
		if path_bytes.is_empty() {
			if let Some(dfd) = &self.dfd {
				return readlink_fd(dfd.as_raw_fd());
			}
			return Err(io::Error::from_raw_os_error(libc::ENOENT));
		}

		let (dir_fd, file_name) = self.open_target_dir()?;
		let _guard = ForeignFd { local_fd: dir_fd };
		let mut result = readlink_fd(dir_fd)?;
		if !file_name.is_empty() {
			result.push('/');
			result.push_str(file_name);
		}
		Ok(result)
	}
}

/// Read the real path of an open O_PATH file descriptor via /proc/self/fd.
fn readlink_fd(fd: libc::c_int) -> Result<String, io::Error> {
	let proc_path = format!("/proc/self/fd/{}\0", fd);
	let mut buf = vec![0u8; libc::PATH_MAX as usize];
	let ret = unsafe {
		libc::readlink(
			proc_path.as_ptr() as *const libc::c_char,
			buf.as_mut_ptr() as *mut libc::c_char,
			buf.len(),
		)
	};
	if ret < 0 {
		return Err(io::Error::last_os_error());
	}
	buf.truncate(ret as usize);
	String::from_utf8(buf).map_err(|_| io::Error::from_raw_os_error(libc::EILSEQ))
}

#[derive(Debug)]
pub struct OpenOperation {
	pub target: FsTarget,
	pub need_read: bool,
	pub need_write: bool,
}

#[derive(Debug)]
pub struct CreateOperation {
	pub target: FsTarget,
	pub mode: libc::mode_t,
	pub kind: CreateKind,
}

#[derive(Debug)]
pub enum CreateKind {
	File,
	Directory,
	Symlink { target: String },
	Device { dev: libc::dev_t },
}

#[derive(Debug)]
pub struct RenameOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub exchange: bool,
}

#[derive(Debug)]
pub struct UnlinkOperation {
	pub target: FsTarget,
	pub dir: bool,
}

#[derive(Debug)]
pub struct LinkOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub follow_src_symlink: bool,
}

#[derive(Debug)]
pub struct ExecOperation {
	pub target: FsTarget,
}

type SyscallHandler1 = fn(
	req: &mut RequestContext,
	target: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

type SyscallHandler2 = fn(
	req: &mut RequestContext,
	target1: &FsTarget,
	target2: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

// See https://syscalls.mebeim.net

fn handle_access_like(
	_req: &mut RequestContext,
	target: &FsTarget,
	access_mode: u64,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	use crate::syscalls::fs::{ExecOperation, OpenOperation};

	if access_mode == libc::X_OK as u64 {
		return Ok((
			Operation::FsExec(ExecOperation {
				target: target.clone(),
			}),
			None,
		));
	}
	Ok((
		Operation::FsOpen(OpenOperation {
			target: target.clone(),
			need_read: access_mode & libc::R_OK as u64 != 0,
			need_write: access_mode & libc::W_OK as u64 != 0,
		}),
		None,
	))
}

fn handle_open_like(
	_req: &mut RequestContext,
	target: &FsTarget,
	create_mode: Option<libc::mode_t>,
	openat_flags: Option<u64>,
	_openat2_resolve: Option<u64>,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	use crate::syscalls::fs::{CreateKind, CreateOperation, OpenOperation};

	// creat(2) has no explicit flags arg; default to O_CREAT|O_WRONLY|O_TRUNC.
	let flags = openat_flags.unwrap_or((libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64)
		as libc::c_int;

	let need_read =
		flags & libc::O_PATH == 0 && (flags & libc::O_RDWR != 0 || flags & libc::O_WRONLY == 0);
	let need_write =
		flags & libc::O_PATH == 0 && (flags & libc::O_RDWR != 0 || flags & libc::O_WRONLY != 0);

	// Create if O_CREAT is set, or if there are no openat_flags (creat syscall).
	let creates = create_mode.is_some() && (flags & libc::O_CREAT != 0 || openat_flags.is_none());

	if creates {
		let create_op = Operation::FsCreate(CreateOperation {
			target: target.clone(),
			mode: create_mode.unwrap(),
			kind: CreateKind::File,
		});
		let open_op = Operation::FsOpen(OpenOperation {
			target: target.clone(),
			need_read,
			need_write,
		});
		Ok((create_op, Some(open_op)))
	} else {
		Ok((
			Operation::FsOpen(OpenOperation {
				target: target.clone(),
				need_read,
				need_write,
			}),
			None,
		))
	}
}

fn handle_openat2(
	req: &mut RequestContext,
	target: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	let open_how_ptr = req.arg(2) as *const libc::open_how;
	let open_how = req.value_from_target_memory(open_how_ptr)?;
	handle_open_like(
		req,
		target,
		Some(open_how.mode as libc::mode_t),
		Some(open_how.flags),
		Some(open_how.resolve),
	)
}

fn handle_mknod_like(
	target: &FsTarget,
	mode: libc::mode_t,
	kind: CreateKind,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	Ok((
		Operation::FsCreate(crate::syscalls::fs::CreateOperation {
			target: target.clone(),
			mode,
			kind,
		}),
		None,
	))
}

fn handle_symlink_like(
	req: &mut RequestContext,
	target: &FsTarget,
	src_arg_index: u8,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	let src_ptr = req.arg(src_arg_index as usize) as *const libc::c_char;
	let src = req.cstr_from_target_memory(src_ptr)?;
	let src_str = src
		.into_string()
		.map_err(|_| AccessRequestError::InvalidSyscallData("invalid UTF-8 in symlink target"))?;
	Ok((
		Operation::FsCreate(crate::syscalls::fs::CreateOperation {
			target: target.clone(),
			mode: 0o777,
			kind: CreateKind::Symlink { target: src_str },
		}),
		None,
	))
}

// (name, handler, arg index of the path)
const FS_SYSCALLS_PATH: &'static [(&'static str, SyscallHandler1, u8)] = &[
	(
		"open",
		|req, target| {
			handle_open_like(
				req,
				target,
				Some(req.arg(2) as libc::mode_t),
				Some(req.arg(1)),
				None,
			)
		},
		0,
	),
	(
		"access",
		|req, target| handle_access_like(req, target, req.arg(1)),
		0,
	),
	(
		"mkdir",
		|req, target| handle_mknod_like(target, req.arg(1) as libc::mode_t, CreateKind::Directory),
		0,
	),
	(
		"rmdir",
		|_req, target| {
			Ok((
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation {
					target: target.clone(),
					dir: true,
				}),
				None,
			))
		},
		0,
	),
	(
		"creat",
		|req, target| handle_open_like(req, target, Some(req.arg(1) as libc::mode_t), None, None),
		0,
	),
	(
		"mknod",
		|req, target| {
			let mode = req.arg(1) as libc::mode_t;
			let dev = req.arg(2) as libc::dev_t;
			let kind =
				if mode & libc::S_IFMT == libc::S_IFBLK || mode & libc::S_IFMT == libc::S_IFCHR {
					CreateKind::Device { dev }
				} else {
					CreateKind::File
				};
			handle_mknod_like(target, mode, kind)
		},
		0,
	),
	(
		"unlink",
		|_req, target| {
			Ok((
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation {
					target: target.clone(),
					dir: false,
				}),
				None,
			))
		},
		0,
	),
	(
		"execve",
		|req, target| handle_access_like(req, target, libc::X_OK as u64),
		0,
	),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	(
		"symlink",
		|req, target| handle_symlink_like(req, target, 0),
		1,
	),
];

// (name, handler, arg index of the dfd, arg index of the path, arg index of AT_* flags or None)
//
// The flags field records where to find AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW
// in the syscall arguments (a non-None value means that arg index holds
// the AT_* flags bitmask; None means no such flags are present).
const FS_SYSCALLS_DFD_PATH: &'static [(&'static str, SyscallHandler1, u8, u8, Option<u8>)] = &[
	(
		"openat",
		|req, target| {
			handle_open_like(
				req,
				target,
				Some(req.arg(3) as libc::mode_t),
				Some(req.arg(2)),
				None,
			)
		},
		0,
		1,
		None,
	),
	("openat2", handle_openat2, 0, 1, None),
	(
		"faccessat",
		|req, target| handle_access_like(req, target, req.arg(2)),
		0,
		1,
		Some(3),
	),
	(
		"faccessat2",
		|req, target| handle_access_like(req, target, req.arg(2)),
		0,
		1,
		Some(3),
	),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	(
		"symlinkat",
		|req, target| handle_symlink_like(req, target, 0),
		1,
		2,
		None,
	),
	(
		"unlinkat",
		|req, target| {
			let flags = req.arg(2);
			let dir = flags & libc::AT_REMOVEDIR as u64 != 0;
			Ok((
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation {
					target: target.clone(),
					dir,
				}),
				None,
			))
		},
		0,
		1,
		None,
	),
	(
		"mkdirat",
		|req, target| handle_mknod_like(target, req.arg(2) as libc::mode_t, CreateKind::Directory),
		0,
		1,
		None,
	),
	(
		"mknodat",
		|req, target| {
			let mode = req.arg(2) as libc::mode_t;
			let dev = req.arg(3) as libc::dev_t;
			let kind =
				if mode & libc::S_IFMT == libc::S_IFBLK || mode & libc::S_IFMT == libc::S_IFCHR {
					CreateKind::Device { dev }
				} else {
					CreateKind::File
				};
			handle_mknod_like(target, mode, kind)
		},
		0,
		1,
		None,
	),
	(
		"execveat",
		|req, target| handle_access_like(req, target, libc::X_OK as u64),
		0,
		1,
		Some(4),
	),
];
// (name, handler, arg index of the first path, arg index of the second path)
const FS_SYSCALLS_PATH_PATH: &'static [(&'static str, SyscallHandler2, u8, u8)] = &[
	(
		"rename",
		|_req, target1, target2| {
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1.clone(),
					to: target2.clone(),
					exchange: false,
				}),
				None,
			))
		},
		0,
		1,
	),
	(
		"link",
		|_req, target1, target2| {
			Ok((
				Operation::FsLink(crate::syscalls::fs::LinkOperation {
					from: target1.clone(),
					to: target2.clone(),
					follow_src_symlink: false,
				}),
				None,
			))
		},
		0,
		1,
	),
];
// (name, handler, dfd1, path1, dfd2, path2, arg index of AT_* flags or None)
//
// The flags field records where to find AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW
// flags that apply to the first (source) path.
const FS_SYSCALLS_DFD_PATH_DFD_PATH: &'static [(
	&'static str,
	SyscallHandler2,
	u8,
	u8,
	u8,
	u8,
	Option<u8>,
)] = &[
	(
		"renameat",
		|_req, target1, target2| {
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1.clone(),
					to: target2.clone(),
					exchange: false,
				}),
				None,
			))
		},
		0,
		1,
		2,
		3,
		None,
	),
	(
		"renameat2",
		|req, target1, target2| {
			// RENAME_EXCHANGE = 1 << 1
			let exchange = req.arg(4) & (1u64 << 1) != 0;
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1.clone(),
					to: target2.clone(),
					exchange,
				}),
				None,
			))
		},
		0,
		1,
		2,
		3,
		None,
	),
	(
		"linkat",
		|req, target1, target2| {
			let flags = req.arg(4);
			let follow_src_symlink = flags & libc::AT_SYMLINK_FOLLOW as u64 != 0;
			Ok((
				Operation::FsLink(crate::syscalls::fs::LinkOperation {
					from: target1.clone(),
					to: target2.clone(),
					follow_src_symlink,
				}),
				None,
			))
		},
		0,
		1,
		2,
		3,
		Some(4),
	),
];

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for list in &[
		FS_SYSCALLS_PATH
			.into_iter()
			.map(|(name, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_DFD_PATH
			.into_iter()
			.map(|(name, _, _, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_PATH_PATH
			.into_iter()
			.map(|(name, _, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_DFD_PATH_DFD_PATH
			.into_iter()
			.map(|(name, _, _, _, _, _, _)| *name)
			.collect::<Vec<_>>(),
	] {
		for name in list {
			let scmpc = ScmpSyscall::from_name(name)
				.map_err(|e| TurnstileTracerError::ResolveSyscall(name, e))?;
			filter_ctx
				.add_rule(libseccomp::ScmpAction::Notify, scmpc)
				.map_err(|e| TurnstileTracerError::AddRule(name, e))?;
		}
	}
	Ok(())
}

pub(crate) fn handler_return_to_access_req(ret: (Operation, Option<Operation>)) -> AccessRequest {
	let mut ar = AccessRequest {
		operations: vec![ret.0],
	};
	if let Some(extra_op) = ret.1 {
		ar.operations.push(extra_op);
	}
	ar
}

// Resolved syscall-number tables, built once (lazily) from the name tables
// above.  Comparisons against ScmpSyscall (a plain i32 wrapper) are far
// cheaper than allocating a string via get_name() and doing a string compare.

lazy_syscall_table_name_to_number!(FS_SYSCALLS_PATH, resolved_path, SyscallHandler1, u8);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_DFD_PATH,
	resolved_dfd_path,
	SyscallHandler1,
	u8,
	u8,
	Option<u8>
);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_PATH_PATH,
	resolved_path_path,
	SyscallHandler2,
	u8,
	u8
);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_DFD_PATH_DFD_PATH,
	resolved_dfd_path_dfd_path,
	SyscallHandler2,
	u8,
	u8,
	u8,
	u8,
	Option<u8>
);

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = request_ctx.sreq.data.syscall;

	for &(scmp, handler, path_arg_index) in resolved_path() {
		if syscall == scmp {
			let target = FsTarget::from_path(request_ctx, path_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(scmp, handler, dfd_arg_index, path_arg_index, flags_arg_index) in resolved_dfd_path() {
		if syscall == scmp {
			let at_flags = flags_arg_index.map(|i| request_ctx.arg(i as usize));
			let target =
				FsTarget::from_at_path(request_ctx, dfd_arg_index, path_arg_index, at_flags)?;
			let (op, extra_op) = handler(request_ctx, &target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(scmp, handler, path1_arg_index, path2_arg_index) in resolved_path_path() {
		if syscall == scmp {
			let target1 = FsTarget::from_path(request_ctx, path1_arg_index)?;
			let target2 = FsTarget::from_path(request_ctx, path2_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target1, &target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(
		scmp,
		handler,
		dfd1_arg_index,
		path1_arg_index,
		dfd2_arg_index,
		path2_arg_index,
		flags_arg_index,
	) in resolved_dfd_path_dfd_path()
	{
		if syscall == scmp {
			let at_flags = flags_arg_index.map(|i| request_ctx.arg(i as usize));
			let target1 =
				FsTarget::from_at_path(request_ctx, dfd1_arg_index, path1_arg_index, at_flags)?;
			let target2 =
				FsTarget::from_at_path(request_ctx, dfd2_arg_index, path2_arg_index, None)?;
			let (op, extra_op) = handler(request_ctx, &target1, &target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	warn!("Unhandled syscall: {:?}", syscall);
	Ok(None)
}
