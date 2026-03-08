use libseccomp::{ScmpFilterContext, ScmpSyscall};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError,
	syscalls::{RequestContext, fs::ForeignFd, fs::FsTarget},
};

/// Unix socket syscalls to intercept:
/// (name, operation builder, addr arg index, addrlen arg index).
const UNIX_SOCK_SYSCALLS: &[(&str, fn(&FsTarget) -> Operation, u8, u8)] = &[
	("connect", |t| Operation::UnixConnect(t.clone()), 1, 2),
	("bind", |t| Operation::UnixListen(t.clone()), 1, 2),
	("sendto", |t| Operation::UnixSendto(t.clone()), 4, 5),
];

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

/// Try to read a Unix socket target from the traced process's memory.
/// Returns `None` if the address is null, too short, or is an abstract-
/// namespace socket (no filesystem path).
fn read_unix_target(
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

	// Read the address family (first 2 bytes of sockaddr).
	let family = req.value_from_target_memory(addr_ptr as *const libc::sa_family_t)?;
	if family != libc::AF_UNIX as libc::sa_family_t {
		return Ok(None);
	}

	// sun_path starts at offset 2 (right after sa_family_t).
	let sun_path_ptr = (addr_ptr + 2) as *const libc::c_char;

	// Abstract-namespace sockets have sun_path[0] == '\0'.
	let first_byte = req.value_from_target_memory(sun_path_ptr as *const u8)?;
	if first_byte == 0 {
		return Ok(None);
	}

	let path = req.cstr_from_target_memory(sun_path_ptr)?;
	let path_bytes = path.as_bytes();

	let target = if path_bytes.first() == Some(&b'/') {
		FsTarget {
			dfd: None,
			path,
			no_follow: false,
		}
	} else {
		let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
		FsTarget {
			dfd: Some(
				ForeignFd::from_path(&cwdstr).map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
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
	use std::sync::OnceLock;

	type Resolved = Vec<(ScmpSyscall, fn(&FsTarget) -> Operation, u8, u8)>;
	static RESOLVED: OnceLock<Resolved> = OnceLock::new();
	let resolved = RESOLVED.get_or_init(|| {
		UNIX_SOCK_SYSCALLS
			.iter()
			.filter_map(|&(name, builder, addr_arg, addrlen_arg)| {
				ScmpSyscall::from_name(name)
					.ok()
					.map(|sc| (sc, builder, addr_arg, addrlen_arg))
			})
			.collect()
	});

	let syscall = request_ctx.sreq.data.syscall;

	for &(scmp, builder, addr_arg, addrlen_arg) in resolved {
		if syscall != scmp {
			continue;
		}
		if let Some(target) =
			read_unix_target(request_ctx, addr_arg as usize, addrlen_arg as usize)?
		{
			let op = builder(&target);
			return Ok(Some(AccessRequest {
				operations: vec![op],
			}));
		}
		// Not a Unix socket or no address — let the kernel handle it.
		return Ok(None);
	}

	Ok(None)
}
