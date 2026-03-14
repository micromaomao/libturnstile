use std::{
	ffi::{CStr, CString, OsStr, OsString},
	io,
	os::unix::{
		ffi::{OsStrExt, OsStringExt},
		io::AsRawFd,
	},
};

use libseccomp::ScmpFilterContext;

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError, syscalls::RequestContext,
};

use super::lazy_syscall_table_name_to_number;

use log::debug;

/// An O_PATH / O_CLOEXEC file descriptor opened in the tracer process that
/// refers to a path in the traced process's filesystem namespace.
///
/// The fd is closed automatically on drop.  Cloning uses `F_DUPFD_CLOEXEC`
/// so the duplicate always has the close-on-exec flag set.
#[derive(Debug)]
pub struct ForeignFd {
	local_fd: libc::c_int,
}

impl ForeignFd {
	pub(crate) fn from_path_with_flags<P: AsRef<CStr>>(
		path: P,
		oflags: libc::c_int,
	) -> Result<Self, io::Error> {
		let c_path = path.as_ref();
		let local_fd = unsafe { libc::open(c_path.as_ptr(), oflags, 0) };
		if local_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { local_fd })
	}

	pub(crate) fn from_path<P: AsRef<CStr>>(path: P) -> Result<Self, io::Error> {
		Self::from_path_with_flags(path, libc::O_PATH | libc::O_CLOEXEC)
	}

	/// Read the path of an open file descriptor via /proc/self/fd.
	pub fn readlink(&self) -> Result<OsString, io::Error> {
		// /proc/self/fd/{fd} is always valid ASCII, so a format! string with a
		// manual NUL terminator is safe to pass to readlink.
		let proc_path = format!("/proc/self/fd/{}\0", self.local_fd);
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
		// readlink does not include a NUL terminator
		if buf.len() > 1 && buf.last().copied() == Some(b'/') {
			buf.pop();
		}
		Ok(OsString::from_vec(buf))
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
		let duped_fd = unsafe { libc::fcntl(self.local_fd, libc::F_DUPFD_CLOEXEC, 0) };
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
	/// None iff path is absolute, in which case path must start with '/'.
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
		let absolute = pathb.len() > 0 && pathb[0] == b'/';
		let mut ret = Self {
			dfd: None,
			path,
			no_follow: false,
		};
		if !absolute {
			let cwdstr = format!("/proc/{}/cwd\0", req.sreq.pid);
			ret.dfd = Some(
				ForeignFd::from_path(CStr::from_bytes_with_nul(cwdstr.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
			);
		}
		Ok(ret)
	}

	pub(crate) fn from_at_path(
		req: &mut RequestContext,
		dfd_arg_index: u8,
		path_arg_index: u8,
		at_flags: Option<u64>,
	) -> Result<Self, AccessRequestError> {
		let _at_empty_path = at_flags.map_or(false, |f| f & libc::AT_EMPTY_PATH as u64 != 0);
		let no_follow = at_flags.map_or(false, |f| f & libc::AT_SYMLINK_NOFOLLOW as u64 != 0);

		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let pathb = path.as_bytes();

		if pathb.len() > 0 && pathb[0] == b'/' {
			return Ok(Self {
				dfd: None,
				path,
				no_follow,
			});
		}

		// ??? what happens if AT_EMPTY_PATH is not set but path is empty

		Ok(Self {
			dfd: Some(req.arg_to_fd(dfd_arg_index as usize)?),
			path,
			no_follow,
		})
	}

	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<ForeignFd, io::Error> {
		let path_bytes = self.path.to_bytes();

		if path_bytes.is_empty() {
			let dfd = self
				.dfd
				.as_ref()
				.expect("Expected dfd to exist for non-absolute path");
			return Ok(dfd.clone());
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
		Ok(ForeignFd { local_fd: fd })
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	pub fn open_target_dir(&self) -> Result<(ForeignFd, &CStr), io::Error> {
		let path_bytes_nul = self.path.to_bytes_with_nul();

		if let Some(last_slash) = path_bytes_nul.iter().rposition(|&b| b == b'/')
			&& last_slash != 0
		{
			let dir_bytes = &path_bytes_nul[..last_slash];
			let file_bytes_nul = &path_bytes_nul[last_slash + 1..];
			let actual_parent_fd_raw = match &self.dfd {
				Some(dfd) => unsafe {
					// We have to allocate a new CString to have NUL at the end
					libc::openat(
						dfd.as_raw_fd(),
						CString::new(dir_bytes)
							.expect("self.path should not have NUL in the middle")
							.as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
						0,
					)
				},
				None => unsafe {
					// We have to allocate a new CString to have NUL at the end
					libc::open(
						CString::new(dir_bytes)
							.expect("self.path should not have NUL in the middle")
							.as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
						0,
					)
				},
			};
			if actual_parent_fd_raw < 0 {
				return Err(io::Error::last_os_error());
			}
			let file_name = CStr::from_bytes_with_nul(file_bytes_nul).unwrap();
			Ok((
				ForeignFd {
					local_fd: actual_parent_fd_raw,
				},
				file_name,
			))
		} else {
			let file_name = match path_bytes_nul {
				// In the AT_EMPTY_PATH case, we can't recover the
				// filename, so just represent it as "." to the
				// caller.  Should it need the full path it can always
				// realpath().
				b"\0" => CStr::from_bytes_with_nul(b".\0").unwrap(),
				other if other.first().copied() == Some(b'/') => {
					// Absolute path with a single filename, remove leading /
					CStr::from_bytes_with_nul(&other[1..]).unwrap()
				}
				other => CStr::from_bytes_with_nul(other).unwrap(),
			};
			let actual_parent_fd = match &self.dfd {
				Some(dfd) => dfd.clone(),
				None => {
					// Absolute path, open root.
					ForeignFd::from_path(CStr::from_bytes_with_nul(b"/\0").unwrap())?
				}
			};
			Ok((actual_parent_fd, file_name))
		}
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<OsString, io::Error> {
		let path_bytes = self.path.to_bytes();

		// AT_EMPTY_PATH: the target is the dfd itself — read its proc symlink.
		if path_bytes.is_empty() {
			let dfd = self
				.dfd
				.as_ref()
				.expect("Expected dfd to exist for non-absolute path");
			return dfd.readlink();
		}

		let (dir_fd, file_name) = self.open_target_dir()?;
		let dir_path = dir_fd.readlink()?;
		let file_name_bytes = file_name.to_bytes();
		if file_name_bytes.is_empty() {
			return Ok(dir_path);
		}
		let mut result = dir_path.into_encoded_bytes();
		if result.last().copied() != Some(b'/') {
			result.push(b'/');
		}
		result.extend_from_slice(file_name_bytes);
		Ok(OsString::from_vec(result))
	}

	pub fn dfd(&self) -> Option<&ForeignFd> {
		self.dfd.as_ref()
	}

	pub fn path(&self) -> &CStr {
		&self.path
	}
}

impl std::fmt::Display for FsTarget {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let rp = self.realpath();
		match rp {
			Ok(rp) => {
				write!(f, "{:?}", rp)
			}
			Err(rp_err) => {
				debug!("realpath() on FsTarget failed: {}", rp_err);
				match &self.dfd {
					Some(dfd) => {
						let mut dfd_path_bytes = dfd
							.readlink()
							.unwrap_or_else(|e| {
								debug!("unable to readlink() on FsTarget's dfd: {}", e);
								OsString::from("???")
							})
							.into_encoded_bytes();
						if dfd_path_bytes.last().copied() != Some(b'/') {
							dfd_path_bytes.push(b'/');
						}
						dfd_path_bytes.extend_from_slice(self.path.to_bytes());
						write!(f, "{:?} (invalid)", OsString::from_vec(dfd_path_bytes))
					}
					None => {
						// self.path is absolute, so already have leading '/'
						write!(f, "{:?} (invalid)", OsStr::from_bytes(self.path.as_bytes()))
					}
				}
			}
		}
	}
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
	Symlink { target: CString },
	Device { dev: libc::dev_t },
}

impl CreateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			CreateKind::File => "file",
			CreateKind::Directory => "directory",
			CreateKind::Symlink { .. } => "symlink",
			CreateKind::Device { .. } => "device",
		}
	}
}

impl std::fmt::Display for CreateKind {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.as_str())
	}
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
	target: FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

type SyscallHandler2 = fn(
	req: &mut RequestContext,
	target1: FsTarget,
	target2: FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

// See https://syscalls.mebeim.net

fn handle_access_like(
	_req: &mut RequestContext,
	target: FsTarget,
	access_mode: u64,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	if access_mode == libc::X_OK as u64 {
		return Ok((Operation::FsExec(ExecOperation { target }), None));
	}
	Ok((
		Operation::FsOpen(OpenOperation {
			target,
			need_read: access_mode & libc::R_OK as u64 != 0,
			need_write: access_mode & libc::W_OK as u64 != 0,
		}),
		None,
	))
}

fn handle_open_like(
	_req: &mut RequestContext,
	target: FsTarget,
	create_mode: Option<libc::mode_t>,
	openat_flags: Option<u64>,
	_openat2_resolve: Option<u64>,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	// creat(2) has no explicit flags arg; default to O_CREAT|O_WRONLY|O_TRUNC.
	let flags = openat_flags.unwrap_or((libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64)
		as libc::c_int;

	// When O_PATH is specified in flags, flag bits other than O_CLOEXEC,
	// O_DIRECTORY, and O_NOFOLLOW are ignored.
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
			target,
			need_read,
			need_write,
		});
		Ok((create_op, Some(open_op)))
	} else {
		Ok((
			Operation::FsOpen(OpenOperation {
				target,
				need_read,
				need_write,
			}),
			None,
		))
	}
}

fn handle_openat2(
	req: &mut RequestContext,
	target: FsTarget,
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
	target: FsTarget,
	mode: libc::mode_t,
	kind: CreateKind,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	Ok((
		Operation::FsCreate(crate::syscalls::fs::CreateOperation { target, mode, kind }),
		None,
	))
}

fn handle_symlink_like(
	req: &mut RequestContext,
	target: FsTarget,
	src_arg_index: u8,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	let src_ptr = req.arg(src_arg_index as usize) as *const libc::c_char;
	let src = req.cstr_from_target_memory(src_ptr)?;
	Ok((
		Operation::FsCreate(crate::syscalls::fs::CreateOperation {
			target,
			mode: 0o777,
			kind: CreateKind::Symlink { target: src },
		}),
		None,
	))
}

// (name, handler, arg index of the path)
const FS_SYSCALLS_PATH: &[(&str, SyscallHandler1, u8)] = &[
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
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation { target, dir: true }),
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
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation { target, dir: false }),
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

// (name, handler, arg index of the dfd, arg index of the path, arg index of AT_* flags or None if no such flag)
const FS_SYSCALLS_DFD_PATH: &[(&str, SyscallHandler1, u8, u8, Option<u8>)] = &[
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
		None,
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
				Operation::FsUnlink(crate::syscalls::fs::UnlinkOperation { target, dir }),
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
const FS_SYSCALLS_PATH_PATH: &[(&str, SyscallHandler2, u8, u8)] = &[
	(
		"rename",
		|_req, target1, target2| {
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1,
					to: target2,
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
					from: target1,
					to: target2,
					follow_src_symlink: false,
				}),
				None,
			))
		},
		0,
		1,
	),
];
// (name, handler, dfd1, path1, dfd2, path2, arg index of AT_* flags affecting path1, or None if no such flag)
const FS_SYSCALLS_DFD_PATH_DFD_PATH: &[(&str, SyscallHandler2, u8, u8, u8, u8, Option<u8>)] = &[
	(
		"renameat",
		|_req, target1, target2| {
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1,
					to: target2,
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
			let exchange = req.arg(4) & libc::RENAME_EXCHANGE as u64 != 0;
			Ok((
				Operation::FsRename(crate::syscalls::fs::RenameOperation {
					from: target1,
					to: target2,
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
					from: target1,
					to: target2,
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
	for &(sys, ..) in fs_syscalls_path_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	for &(sys, ..) in fs_syscalls_dfd_path_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	for &(sys, ..) in fs_syscalls_path_path_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	for &(sys, ..) in fs_syscall_dfd_path_dfd_path_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
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

lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_PATH,
	fs_syscalls_path_table,
	SyscallHandler1,
	u8
);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_DFD_PATH,
	fs_syscalls_dfd_path_table,
	SyscallHandler1,
	u8,
	u8,
	Option<u8>
);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_PATH_PATH,
	fs_syscalls_path_path_table,
	SyscallHandler2,
	u8,
	u8
);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_DFD_PATH_DFD_PATH,
	fs_syscall_dfd_path_dfd_path_table,
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

	for &(sys, handler, path_arg_index) in fs_syscalls_path_table() {
		if syscall == sys {
			let target = FsTarget::from_path(request_ctx, path_arg_index)?;
			let (op, extra_op) = handler(request_ctx, target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(sys, handler, dfd_arg_index, path_arg_index, flags_arg_index) in
		fs_syscalls_dfd_path_table()
	{
		if syscall == sys {
			let at_flags = flags_arg_index.map(|i| request_ctx.arg(i as usize));
			let target =
				FsTarget::from_at_path(request_ctx, dfd_arg_index, path_arg_index, at_flags)?;
			let (op, extra_op) = handler(request_ctx, target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(sys, handler, path1_arg_index, path2_arg_index) in fs_syscalls_path_path_table() {
		if syscall == sys {
			let target1 = FsTarget::from_path(request_ctx, path1_arg_index)?;
			let target2 = FsTarget::from_path(request_ctx, path2_arg_index)?;
			let (op, extra_op) = handler(request_ctx, target1, target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(
		sys,
		handler,
		dfd1_arg_index,
		path1_arg_index,
		dfd2_arg_index,
		path2_arg_index,
		flags_arg_index,
	) in fs_syscall_dfd_path_dfd_path_table()
	{
		if syscall == sys {
			let at_flags = flags_arg_index.map(|i| request_ctx.arg(i as usize));
			let target1 =
				FsTarget::from_at_path(request_ctx, dfd1_arg_index, path1_arg_index, at_flags)?;
			let target2 =
				FsTarget::from_at_path(request_ctx, dfd2_arg_index, path2_arg_index, None)?;
			let (op, extra_op) = handler(request_ctx, target1, target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	Ok(None)
}
