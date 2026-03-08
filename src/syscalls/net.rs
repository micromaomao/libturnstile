use std::{ffi::CStr, mem::offset_of};

use libseccomp::{ScmpFilterContext, ScmpSyscall};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError,
	syscalls::{RequestContext, fs::ForeignFd, fs::FsTarget, lazy_syscall_table_name_to_number},
};

/// (name, handler, addr arg index, addrlen arg index).
const UNIX_SOCK_SYSCALLS: &[(&str, fn(FsTarget) -> Operation, u8, u8)] = &[
	("connect", Operation::UnixConnect, 1, 2),
	("bind", Operation::UnixListen, 1, 2),
	("sendto", Operation::UnixSendto, 4, 5),
	("recvfrom", Operation::UnixRecvfrom, 4, 5),
];

lazy_syscall_table_name_to_number!(
	UNIX_SOCK_SYSCALLS,
	unix_sock_syscalls_table,
	fn(FsTarget) -> Operation,
	u8,
	u8
);

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for &(name, _, _, _) in UNIX_SOCK_SYSCALLS {
		let scmpc = ScmpSyscall::from_name(name)
			.map_err(|e| TurnstileTracerError::ResolveSyscall(name, e))?;
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, scmpc)
			.map_err(|e| TurnstileTracerError::AddRule(name, e))?;
	}
	Ok(())
}

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
	// We need at least sa_family (2 bytes) + 1 path byte.
	if addrlen < 3 {
		return Ok(None);
	}

	// Read the address family (first 2 bytes of sockaddr).  We have to do
	// this separately from reading the path because the target sockaddr
	// might not in fact be a sockaddr_un, and it might be smaller.  If
	// the allocated sockaddr is small and crosses a page boundary, we
	// don't want to read out-of-bound.
	let family = req.value_from_target_memory(
		(addr_ptr + offset_of!(libc::sockaddr_un, sun_family)) as *const libc::sa_family_t,
	)?;
	if family != libc::AF_UNIX as libc::sa_family_t {
		return Ok(None);
	}

	let sun_path_ptr = (addr_ptr + offset_of!(libc::sockaddr_un, sun_path)) as *const libc::c_char;
	let path = req.cstr_from_target_memory(sun_path_ptr)?;

	// Abstract-namespace sockets have a sun_path with the first byte
	// being NUL, which we will end up reading as an empty string.
	if path.as_bytes().is_empty() {
		return Ok(None);
	}

	let target = if path.as_bytes().first() == Some(&b'/') {
		FsTarget {
			dfd: None,
			path,
			no_follow: false,
		}
	} else {
		let cwdstr = format!("/proc/{}/cwd\0", req.sreq.pid);
		FsTarget {
			dfd: Some(
				ForeignFd::from_path(CStr::from_bytes_with_nul(cwdstr.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
			),
			path,
			no_follow: false,
		}
	};
	Ok(Some(target))
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = request_ctx.sreq.data.syscall;

	for &(sys, builder, addr_arg, addrlen_arg) in unix_sock_syscalls_table() {
		if syscall != sys {
			continue;
		}
		if let Some(target) =
			read_sockaddr_un(request_ctx, addr_arg as usize, addrlen_arg as usize)?
		{
			let op = builder(target);
			return Ok(Some(AccessRequest {
				operations: vec![op],
			}));
		}
		// Not a Unix socket or no address — let the kernel handle it.
		return Ok(None);
	}

	Ok(None)
}
