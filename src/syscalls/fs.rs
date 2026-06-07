use libseccomp::{ScmpFilterContext, ScmpSyscall};
use smallvec::{SmallVec, smallvec};

use std::sync::OnceLock;

use crate::{
	AccessRequestError, TurnstileTracerError,
	access::fs::{
		CreateKind, CreateOperation, ExecOperation, FsTarget, LinkOperation, ModifyFdKind,
		ModifyFdOperation, OpenOperation, RenameOperation, UnlinkOperation,
	},
	access::{
		AccessRequest, Operation,
		fs::{AccessOperation, StatOperation},
	},
	syscalls::RequestContext,
};

use super::lazy_syscall_table_name_to_number;

type SyscallHandler1 =
	fn(req: &mut RequestContext, target: FsTarget) -> Result<Operation, AccessRequestError>;

type SyscallHandler2 = fn(
	req: &mut RequestContext,
	target1: FsTarget,
	target2: FsTarget,
) -> Result<Operation, AccessRequestError>;

use crate::access::Operation::FsOperation as fsop;
use crate::access::fs::FsOperation::*;

fn handle_access_like(
	_req: &mut RequestContext,
	target: FsTarget,
	access_mode: u64,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsAccess(AccessOperation {
		target,
		need_read: access_mode & libc::R_OK as u64 != 0,
		need_write: access_mode & libc::W_OK as u64 != 0,
		need_exec: access_mode & libc::X_OK as u64 != 0,
	})))
}

fn handle_open_like(
	_req: &mut RequestContext,
	target: FsTarget,
	create_mode: Option<libc::mode_t>,
	openat_flags: Option<u64>,
	_openat2_resolve: Option<u64>,
) -> Result<Operation, AccessRequestError> {
	// creat(2) has no explicit flags arg; default to O_CREAT|O_WRONLY|O_TRUNC.
	let flags = openat_flags.unwrap_or((libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64)
		as libc::c_int;

	// When O_PATH is specified in flags, flag bits other than O_CLOEXEC,
	// O_DIRECTORY, and O_NOFOLLOW are ignored.
	let need_read =
		flags & libc::O_PATH == 0 && (flags & libc::O_RDWR != 0 || flags & libc::O_WRONLY == 0);
	let need_write =
		flags & libc::O_PATH == 0 && (flags & libc::O_RDWR != 0 || flags & libc::O_WRONLY != 0);

	// Create if O_CREAT is set, or if there are no openat_flags (for creat()).
	let create_mode = if flags & libc::O_CREAT != 0 || openat_flags.is_none() {
		create_mode
	} else {
		None
	};

	Ok(fsop(FsOpen(OpenOperation {
		target,
		need_read,
		need_write,
		create_mode,
	})))
}

fn handle_openat2(
	req: &mut RequestContext,
	target: FsTarget,
) -> Result<Operation, AccessRequestError> {
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

fn handle_exec_like(
	_req: &mut RequestContext,
	target: FsTarget,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsExec(ExecOperation { target })))
}

fn handle_mknod_like(
	target: FsTarget,
	mode: libc::mode_t,
	kind: CreateKind,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsCreate(CreateOperation { target, mode, kind })))
}

fn handle_symlink_like(
	req: &mut RequestContext,
	target: FsTarget,
	src_arg_index: u8,
) -> Result<Operation, AccessRequestError> {
	let src_ptr = req.arg(src_arg_index as usize) as *const libc::c_char;
	let src = req.cstr_from_target_memory(src_ptr)?;
	Ok(fsop(FsCreate(CreateOperation {
		target,
		mode: 0o777,
		kind: CreateKind::Symlink { target: src },
	})))
}

fn handle_readlink_like(
	_req: &mut RequestContext,
	target: FsTarget,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsReadlink(target)))
}

fn handle_chdir_like(
	_req: &mut RequestContext,
	target: FsTarget,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsChdir(target)))
}

fn handle_stat_like(
	_req: &mut RequestContext,
	target: FsTarget,
	lstat: bool,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsStat(StatOperation { target, lstat })))
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
		|_req, target| Ok(fsop(FsUnlink(UnlinkOperation { target, dir: true }))),
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
		|_req, target| Ok(fsop(FsUnlink(UnlinkOperation { target, dir: false }))),
		0,
	),
	("execve", handle_exec_like, 0),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	(
		"symlink",
		|req, target| handle_symlink_like(req, target, 0),
		1,
	),
	("readlink", handle_readlink_like, 0),
	("chdir", handle_chdir_like, 0),
	(
		"newstat",
		|req, target| handle_stat_like(req, target, false),
		0,
	),
	(
		"newlstat",
		|req, target| handle_stat_like(req, target, true),
		0,
	),
	(
		"stat",
		|req, target| handle_stat_like(req, target, false),
		0,
	),
	(
		"lstat",
		|req, target| handle_stat_like(req, target, true),
		0,
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
			Ok(fsop(FsUnlink(UnlinkOperation { target, dir })))
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
	("execveat", handle_exec_like, 0, 1, Some(4)),
	("readlinkat", handle_readlink_like, 0, 1, None),
	(
		"newfstatat",
		|req, target| {
			handle_stat_like(
				req,
				target,
				req.arg(3) & libc::AT_SYMLINK_NOFOLLOW as u64 != 0,
			)
		},
		0,
		1,
		Some(3),
	),
	(
		"statx",
		|req, target| {
			let lstat = req.arg(2) & libc::AT_SYMLINK_NOFOLLOW as u64 != 0;
			handle_stat_like(req, target, lstat)
		},
		0,
		1,
		Some(2),
	),
	// open_tree() without OPEN_TREE_CLONE behaves like openat() with
	// O_PATH.  We don't handle privileged operations, so we pretend that
	// it's just openat().
	(
		"open_tree",
		|_req, target| {
			Ok(fsop(FsOpen(OpenOperation {
				target,
				need_read: false,
				need_write: false,
				create_mode: None,
			})))
		},
		0,
		1,
		Some(2),
	),
	(
		"open_tree_attr",
		|_req, target| {
			Ok(fsop(FsOpen(OpenOperation {
				target,
				need_read: false,
				need_write: false,
				create_mode: None,
			})))
		},
		0,
		1,
		Some(2),
	),
];
// (name, handler, arg index of the first path, arg index of the second path)
const FS_SYSCALLS_PATH_PATH: &[(&str, SyscallHandler2, u8, u8)] = &[
	(
		"rename",
		|_req, target1, target2| {
			Ok(fsop(FsRename(RenameOperation {
				from: target1,
				to: target2,
				exchange: false,
			})))
		},
		0,
		1,
	),
	(
		"link",
		|_req, target1, target2| {
			Ok(fsop(FsLink(LinkOperation {
				from: target1,
				to: target2,
				follow_src_symlink: false,
			})))
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
			Ok(fsop(FsRename(RenameOperation {
				from: target1,
				to: target2,
				exchange: false,
			})))
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
			Ok(fsop(FsRename(RenameOperation {
				from: target1,
				to: target2,
				exchange,
			})))
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
			Ok(fsop(FsLink(LinkOperation {
				from: target1,
				to: target2,
				follow_src_symlink,
			})))
		},
		0,
		1,
		2,
		3,
		Some(4),
	),
];

// (name, handler, fd)
const FS_SYSCALLS_FD: &[(&str, SyscallHandler1, u8)] = &[
	("fchdir", handle_chdir_like, 0),
	(
		"newfstat",
		|req, target| handle_stat_like(req, target, false),
		0,
	),
	(
		"fstat",
		|req, target| handle_stat_like(req, target, false),
		0,
	),
];

/// Maximum xattr value size we are willing to copy out of the traced
/// process (matches the kernel's `XATTR_SIZE_MAX`).
const XATTR_SIZE_MAX: usize = 65536;

/// Read exactly `len` bytes from the traced process's memory at `ptr`.
///
/// Safety: the `MaybeUninit` slice aliases `buf`'s spare capacity (`len`
/// bytes were just reserved).  `read_target_memory` fully initialises it
/// (or returns `Err`, in which case we never call `set_len`), so the
/// subsequent `set_len(len)` only exposes initialised bytes.
fn read_target_bytes(
	req: &mut RequestContext,
	ptr: *const u8,
	len: usize,
) -> Result<Vec<u8>, AccessRequestError> {
	let mut buf: Vec<u8> = Vec::with_capacity(len);
	{
		let uninit = unsafe {
			std::slice::from_raw_parts_mut(
				buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
				len,
			)
		};
		req.read_target_memory(ptr, uninit)?;
	}
	unsafe { buf.set_len(len) };
	Ok(buf)
}

fn handle_modify_fd(
	target: FsTarget,
	kind: ModifyFdKind,
) -> Result<Operation, AccessRequestError> {
	Ok(fsop(FsModifyFd(ModifyFdOperation { target, kind })))
}

// File-descriptor metadata/content modifying syscalls.  The descriptor
// is always argument 0; remaining arguments carry the operation
// payload.  (name, handler, fd arg index)
const FS_SYSCALLS_FD_MODIFY: &[(&str, SyscallHandler1, u8)] = &[
	(
		"fchmod",
		|req, target| {
			handle_modify_fd(
				target,
				ModifyFdKind::Chmod {
					mode: req.arg(1) as u32,
				},
			)
		},
		0,
	),
	(
		"fchown",
		|req, target| {
			handle_modify_fd(
				target,
				ModifyFdKind::Chown {
					uid: req.arg(1) as u32,
					gid: req.arg(2) as u32,
				},
			)
		},
		0,
	),
	(
		"ftruncate",
		|req, target| {
			handle_modify_fd(
				target,
				ModifyFdKind::Truncate {
					length: req.arg(1) as i64,
				},
			)
		},
		0,
	),
	(
		"fsetxattr",
		|req, target| {
			let name_ptr = req.arg(1) as *const libc::c_char;
			let name = req.cstr_from_target_memory(name_ptr)?;
			let size = req.arg(3) as usize;
			if size > XATTR_SIZE_MAX {
				return Err(AccessRequestError::InvalidSyscallData(
					"fsetxattr value exceeds XATTR_SIZE_MAX",
				));
			}
			let value_ptr = req.arg(2) as *const u8;
			let value = read_target_bytes(req, value_ptr, size)?;
			handle_modify_fd(
				target,
				ModifyFdKind::SetXattr {
					name,
					value,
					flags: req.arg(4) as i32,
				},
			)
		},
		0,
	),
	(
		"fremovexattr",
		|req, target| {
			let name_ptr = req.arg(1) as *const libc::c_char;
			let name = req.cstr_from_target_memory(name_ptr)?;
			handle_modify_fd(target, ModifyFdKind::RemoveXattr { name })
		},
		0,
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
	for &(sys, ..) in fs_syscalls_fd_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	for &(sys, ..) in fs_syscalls_fd_modify_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	Ok(())
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
lazy_syscall_table_name_to_number!(FS_SYSCALLS_FD, fs_syscalls_fd_table, SyscallHandler1, u8);
lazy_syscall_table_name_to_number!(
	FS_SYSCALLS_FD_MODIFY,
	fs_syscalls_fd_modify_table,
	SyscallHandler1,
	u8
);

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = request_ctx.sreq.data.syscall;

	for &(sys, handler, path_arg_index) in fs_syscalls_path_table() {
		if syscall == sys {
			let target = FsTarget::from_path(request_ctx, path_arg_index)?;
			let op = handler(request_ctx, target)?;
			return Ok(Some(AccessRequest { operation: op }));
		}
	}

	for &(sys, handler, dfd_arg_index, path_arg_index, flags_arg_index) in
		fs_syscalls_dfd_path_table()
	{
		if syscall == sys {
			let at_flags = flags_arg_index.map(|i| request_ctx.arg(i as usize));
			let target =
				FsTarget::from_at_path(request_ctx, dfd_arg_index, path_arg_index, at_flags)?;
			let op = handler(request_ctx, target)?;
			return Ok(Some(AccessRequest { operation: op }));
		}
	}

	for &(sys, handler, path1_arg_index, path2_arg_index) in fs_syscalls_path_path_table() {
		if syscall == sys {
			let target1 = FsTarget::from_path(request_ctx, path1_arg_index)?;
			let target2 = FsTarget::from_path(request_ctx, path2_arg_index)?;
			let op = handler(request_ctx, target1, target2)?;
			return Ok(Some(AccessRequest { operation: op }));
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
			let op = handler(request_ctx, target1, target2)?;
			return Ok(Some(AccessRequest { operation: op }));
		}
	}

	for &(sys, handler, fd_arg_index) in fs_syscalls_fd_table() {
		if syscall == sys {
			let target = FsTarget::from_fd(request_ctx, fd_arg_index)?;
			let op = handler(request_ctx, target)?;
			return Ok(Some(AccessRequest { operation: op }));
		}
	}

	for &(sys, handler, fd_arg_index) in fs_syscalls_fd_modify_table() {
		if syscall == sys {
			let target = FsTarget::from_fd(request_ctx, fd_arg_index)?;
			let op = handler(request_ctx, target)?;
			return Ok(Some(AccessRequest { operation: op }));
		}
	}

	Ok(None)
}

/// Cache of the syscall numbers the §11 fd-upgrade dispatch needs to
/// special-case, resolved once for the native architecture.
struct UpgradeSyscalls {
	open: Option<ScmpSyscall>,
	openat: Option<ScmpSyscall>,
	openat2: Option<ScmpSyscall>,
	creat: Option<ScmpSyscall>,
	chdir: Option<ScmpSyscall>,
	fchdir: Option<ScmpSyscall>,
}

fn upgrade_syscalls() -> &'static UpgradeSyscalls {
	static ONCE: OnceLock<UpgradeSyscalls> = OnceLock::new();
	ONCE.get_or_init(|| {
		let n = |name: &str| ScmpSyscall::from_name(name).ok();
		UpgradeSyscalls {
			open: n("open"),
			openat: n("openat"),
			openat2: n("openat2"),
			creat: n("creat"),
			chdir: n("chdir"),
			fchdir: n("fchdir"),
		}
	})
}

/// How a freshly-resolved `openat`-family syscall should be re-opened in
/// m1: the open flags, creation mode, and `openat2` resolve flags (0 for
/// the non-`openat2` variants).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReopenParams {
	pub flags: u64,
	pub mode: u64,
	pub resolve: u64,
}

/// If `syscall` is an `open`-family syscall, return the parameters needed
/// to faithfully re-open the target in m1.  Reuses the same argument
/// layout the request-parsing handlers use, rather than re-parsing.
pub(crate) fn open_reopen_params(
	req: &mut RequestContext,
) -> Result<Option<ReopenParams>, AccessRequestError> {
	let s = upgrade_syscalls();
	let syscall = req.syscall();
	if Some(syscall) == s.open {
		Ok(Some(ReopenParams {
			flags: req.arg(1),
			mode: req.arg(2),
			resolve: 0,
		}))
	} else if Some(syscall) == s.openat {
		Ok(Some(ReopenParams {
			flags: req.arg(2),
			mode: req.arg(3),
			resolve: 0,
		}))
	} else if Some(syscall) == s.openat2 {
		let open_how_ptr = req.arg(2) as *const libc::open_how;
		let how = req.value_from_target_memory(open_how_ptr)?;
		Ok(Some(ReopenParams {
			flags: how.flags,
			mode: how.mode,
			resolve: how.resolve,
		}))
	} else if Some(syscall) == s.creat {
		Ok(Some(ReopenParams {
			flags: (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64,
			mode: req.arg(1),
			resolve: 0,
		}))
	} else {
		Ok(None)
	}
}

/// Whether `syscall` is `chdir` or `fchdir`.
pub(crate) fn is_chdir(syscall: ScmpSyscall) -> bool {
	let s = upgrade_syscalls();
	Some(syscall) == s.chdir || Some(syscall) == s.fchdir
}

/// Argument indices of any real `dirfd`s this syscall accepts, derived
/// from the existing request-parsing tables so the fd-upgrade path does
/// not re-implement syscall parsing.  `openat`-family syscalls are
/// excluded (they are handled by re-opening the result instead).
pub(crate) fn dfd_arg_indices(syscall: ScmpSyscall) -> SmallVec<[u8; 2]> {
	let s = upgrade_syscalls();
	if Some(syscall) == s.openat || Some(syscall) == s.openat2 {
		return smallvec![];
	}
	for &(sys, _h, dfd, _path, _flags) in fs_syscalls_dfd_path_table() {
		if sys == syscall {
			return smallvec![dfd];
		}
	}
	for &(sys, _h, dfd1, _p1, dfd2, _p2, _flags) in fs_syscall_dfd_path_dfd_path_table() {
		if sys == syscall {
			return smallvec![dfd1, dfd2];
		}
	}
	smallvec![]
}
