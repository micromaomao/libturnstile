use libseccomp::ScmpFilterContext;

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError,
	access::fs::{
		CreateKind, CreateOperation, ExecOperation, FsTarget, LinkOperation, OpenOperation,
		RenameOperation, UnlinkOperation,
	},
	fs::AccessOperation,
	syscalls::RequestContext,
};

use super::lazy_syscall_table_name_to_number;

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
	Ok((
		Operation::FsAccess(AccessOperation {
			target,
			need_read: access_mode & libc::R_OK as u64 != 0,
			need_write: access_mode & libc::W_OK as u64 != 0,
			need_exec: access_mode & libc::X_OK as u64 != 0,
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

fn handle_exec_like(
	_req: &mut RequestContext,
	target: FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	Ok((Operation::FsExec(ExecOperation { target }), None))
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
	("execve", |req, target| handle_exec_like(req, target), 0),
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
		|req, target| handle_exec_like(req, target),
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
