use std::mem::{MaybeUninit, offset_of};

use libseccomp::{ScmpArgCompare, ScmpFilterContext};

use crate::{
	AccessRequestError, TurnstileTracerError,
	access::{
		AccessRequest, Operation,
		fs::{FsOperation, FsTarget, UnixBindOperation},
	},
	syscalls::{RequestContext, lazy_syscall_table_name_to_number},
	utils::initialize_unix_send_fd_msghdr,
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
	("sendto", |x| FsOperation::UnixSendto(vec![x]), 4, 5),
];

lazy_syscall_table_name_to_number!(
	UNIX_SOCK_SYSCALLS,
	unix_sock_syscalls_table,
	fn(FsTarget) -> FsOperation,
	u8,
	u8
);

/// (name, handler, msghdr arg index for sendmsg)
const SENDMSG_LIKE_HANDLERS: &[(
	&str,
	fn(&mut RequestContext) -> Result<Vec<FsTarget>, AccessRequestError>,
	Option<u8>,
)] = &[
	("sendmsg", handle_sendmsg, Some(1)),
	("sendmmsg", handle_sendmmsg, None),
];

lazy_syscall_table_name_to_number!(
	SENDMSG_LIKE_HANDLERS,
	sendmsg_like_syscalls_table,
	fn(&mut RequestContext) -> Result<Vec<FsTarget>, AccessRequestError>,
	Option<u8>
);

/// Try to read a Unix socket path from a sockaddr pointer in the target
/// process.
fn read_sockaddr_un(
	req: &mut RequestContext,
	addr_ptr: *const u8,
	addrlen: usize,
) -> Result<Option<FsTarget>, AccessRequestError> {
	if addr_ptr.is_null() {
		return Ok(None);
	}
	const OFFSET_FAMILY: usize = offset_of!(libc::sockaddr_un, sun_family);
	const OFFSET_PATH: usize = offset_of!(libc::sockaddr_un, sun_path);
	// We need at least sa_family (2 bytes) + 1 path byte.
	if addrlen < OFFSET_PATH + 1 {
		return Ok(None);
	}
	if addrlen > 0x1000 {
		return Err(AccessRequestError::InvalidSyscallData("addrlen too large"));
	}

	let mut buf: Vec<u8> = Vec::with_capacity(addrlen + 1);
	req.read_target_memory(addr_ptr, &mut buf.spare_capacity_mut()[..addrlen])?;
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

fn read_msghdr_un(
	req: &mut RequestContext,
	msg_hdr: *const libc::msghdr,
) -> Result<Option<FsTarget>, AccessRequestError> {
	if msg_hdr.is_null() {
		return Ok(None);
	}
	let msg_hdr = req.value_from_target_memory(msg_hdr)?;
	read_sockaddr_un(
		req,
		msg_hdr.msg_name as *const u8,
		msg_hdr.msg_namelen as usize,
	)
}

fn handle_sendmsg(req: &mut RequestContext) -> Result<Vec<FsTarget>, AccessRequestError> {
	let msg_hdr = req.arg(1) as *const libc::msghdr;
	if let Some(target) = read_msghdr_un(req, msg_hdr)? {
		Ok(vec![target])
	} else {
		Ok(Vec::new())
	}
}

fn handle_sendmmsg(req: &mut RequestContext) -> Result<Vec<FsTarget>, AccessRequestError> {
	let mmsghdrs_ptr = req.arg(1) as *const libc::mmsghdr;
	let mut vlen = req.arg(2) as usize;
	if mmsghdrs_ptr.is_null() || vlen == 0 {
		return Ok(Vec::new());
	}
	if vlen >= usize::MAX / std::mem::size_of::<libc::mmsghdr>() {
		return Err(AccessRequestError::InvalidSyscallData("vlen too large"));
	}

	// net/socket.c:__sys_sendmmsg
	if vlen > libc::UIO_MAXIOV as usize {
		vlen = libc::UIO_MAXIOV as usize;
	}

	let mut mmsghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(vlen);
	{
		let vec_byte_slice = unsafe {
			std::slice::from_raw_parts_mut(
				mmsghdrs.as_mut_ptr() as *mut MaybeUninit<u8>,
				vlen * std::mem::size_of::<libc::mmsghdr>(),
			)
		};
		req.read_target_memory(mmsghdrs_ptr as *const u8, vec_byte_slice)?;
	}
	unsafe { mmsghdrs.set_len(vlen) };
	let mut targets = Vec::with_capacity(vlen);
	for i in 0..vlen {
		let msghdr = &mmsghdrs[i].msg_hdr;
		if let Some(target) = read_sockaddr_un(
			req,
			msghdr.msg_name as *const u8,
			msghdr.msg_namelen as usize,
		)? {
			targets.push(target);
		}
	}
	Ok(targets)
}

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for &(sys, ..) in unix_sock_syscalls_table() {
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, sys)
			.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
	}

	// Hacky way to avoid notify on the sendmsg performed by our
	// unix_send_fd.
	let special_msghdr_ptr = initialize_unix_send_fd_msghdr();
	for &(sys, _, msghdr_arg) in sendmsg_like_syscalls_table() {
		if let Some(arg_idx) = msghdr_arg {
			filter_ctx
				.add_rule_conditional(
					libseccomp::ScmpAction::Notify,
					sys,
					&[ScmpArgCompare::new(
						arg_idx.into(),
						libseccomp::ScmpCompareOp::NotEqual,
						special_msghdr_ptr as u64,
					)],
				)
				.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
		} else {
			filter_ctx
				.add_rule(libseccomp::ScmpAction::Notify, sys)
				.map_err(|e| TurnstileTracerError::AddRule(sys, e))?;
		}
	}
	Ok(())
}

pub(crate) fn handle_notification<'a>(
	req: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = req.sreq.data.syscall;

	for &(sys, handler, addr_arg, addrlen_arg) in unix_sock_syscalls_table() {
		if syscall != sys {
			continue;
		}
		if let Some(target) = read_sockaddr_un(
			req,
			req.arg(addr_arg.into()) as *const u8,
			req.arg(addrlen_arg.into()) as usize as usize,
		)? {
			let op = handler(target);
			return Ok(Some(AccessRequest {
				operation: Operation::FsOperation(op),
			}));
		}
		// Not a Unix socket or no address
		return Ok(None);
	}

	for &(sys, handler, _) in sendmsg_like_syscalls_table() {
		if syscall != sys {
			continue;
		}
		let targets = handler(req)?;
		if !targets.is_empty() {
			return Ok(Some(AccessRequest {
				operation: Operation::FsOperation(FsOperation::UnixSendto(targets)),
			}));
		}
		return Ok(None);
	}

	Ok(None)
}
