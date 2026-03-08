use std::{ffi::CStr, mem::offset_of};

use libseccomp::ScmpFilterContext;

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
	for &(sys, ..) in unix_sock_syscalls_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
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
	const OFFSET_FAMILY: usize = offset_of!(libc::sockaddr_un, sun_family);
	const OFFSET_PATH: usize = offset_of!(libc::sockaddr_un, sun_path);
	// We need at least sa_family (2 bytes) + 1 path byte.
	if addrlen < OFFSET_PATH + 1 {
		return Ok(None);
	}

	let mut buf: Vec<u8> = Vec::with_capacity(addrlen);
	req.read_target_memory(addr_ptr as *const u8, buf.spare_capacity_mut())?;
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
			return Err(AccessRequestError::InvalidSyscallData(
				"sun_path in sockaddr_un not NUL-terminated",
			));
		}
	};

	let target = if path.to_bytes().first() == Some(&b'/') {
		FsTarget {
			dfd: None,
			path: path.to_owned(),
			no_follow: false,
		}
	} else {
		let cwdstr = format!("/proc/{}/cwd\0", req.sreq.pid);
		FsTarget {
			dfd: Some(
				ForeignFd::from_path(CStr::from_bytes_with_nul(cwdstr.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
			),
			path: path.to_owned(),
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
