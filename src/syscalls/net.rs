use std::mem::offset_of;

use libseccomp::ScmpFilterContext;

use crate::{
	AccessRequestError, TurnstileTracerError,
	access::{
		AccessRequest, Operation,
		fs::{FsOperation, FsTarget, UnixBindOperation},
	},
	syscalls::{RequestContext, lazy_syscall_table_name_to_number},
};

/// (name, handler, addr arg index, addrlen arg index).
const UNIX_SOCK_SYSCALLS: &[(&str, fn(FsTarget) -> FsOperation, u8, u8)] = &[
	("connect", FsOperation::UnixConnect, 1, 2),
	(
		"bind",
		|t| FsOperation::UnixBind(UnixBindOperation { target: t }),
		1,
		2,
	),
	("sendto", FsOperation::UnixSendto, 4, 5),
];

lazy_syscall_table_name_to_number!(
	UNIX_SOCK_SYSCALLS,
	unix_sock_syscalls_table,
	fn(FsTarget) -> FsOperation,
	u8,
	u8
);

/// Try to read a Unix socket path from a sockaddr pointer in the target
/// process.
fn read_sockaddr_un(
	req: &mut RequestContext,
	addr_arg: usize,
	addrlen_arg: usize,
) -> Result<Option<FsTarget>, AccessRequestError> {
	let addr_ptr = req.arg(addr_arg) as usize;
	if addr_ptr == 0 {
		return Ok(None);
	}
	let addrlen = req.arg(addrlen_arg) as usize;
	const OFFSET_FAMILY: usize = offset_of!(libc::sockaddr_un, sun_family);
	const OFFSET_PATH: usize = offset_of!(libc::sockaddr_un, sun_path);
	// We need at least sa_family (2 bytes) + 1 path byte.
	if addrlen < OFFSET_PATH + 1 {
		return Ok(None);
	}

	let mut buf: Vec<u8> = Vec::with_capacity(addrlen + 1);
	req.read_target_memory(
		addr_ptr as *const u8,
		&mut buf.spare_capacity_mut()[..addrlen],
	)?;
	unsafe { buf.set_len(addrlen) };

	let family = libc::sa_family_t::from_ne_bytes(
		buf[OFFSET_FAMILY..OFFSET_FAMILY + std::mem::size_of::<libc::sa_family_t>()]
			.try_into()
			.unwrap(),
	);
	if family != libc::AF_UNIX as libc::sa_family_t {
		return Ok(None);
	}

	// Abstract-namespace sockets have sun_path[0] == 0 and do not
	// represent filesystem paths, so skip them.
	let path_bytes = &buf[OFFSET_PATH..];
	if path_bytes.first() == Some(&0) {
		return Ok(None);
	}

	let path = match path_bytes.iter().position(|&b| b == 0) {
		Some(nul_pos) => std::ffi::CStr::from_bytes_with_nul(&path_bytes[..nul_pos + 1])
			.expect(".position should have ensured no NUL bytes in the middle"),
		None => {
			buf.push(0);
			std::ffi::CStr::from_bytes_with_nul(&buf[OFFSET_PATH..])
				.expect("we just pushed a NUL byte at the end")
		}
	};

	let target = FsTarget::from_path_str(req, path)?;
	Ok(Some(target))
}

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for &(sys, ..) in unix_sock_syscalls_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}
	Ok(())
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = request_ctx.sreq.data.syscall;

	for &(sys, handler, addr_arg, addrlen_arg) in unix_sock_syscalls_table() {
		if syscall != sys {
			continue;
		}
		if let Some(target) =
			read_sockaddr_un(request_ctx, addr_arg as usize, addrlen_arg as usize)?
		{
			let op = handler(target);
			return Ok(Some(AccessRequest {
				operation: Operation::FsOperation(op),
			}));
		}
		// Not a Unix socket or no address — let the kernel handle it.
		return Ok(None);
	}

	Ok(None)
}
