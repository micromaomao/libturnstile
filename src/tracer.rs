use core::panic;
use std::{ffi::CStr, os::unix::process::CommandExt};

use libseccomp::{ScmpArch, ScmpFd, ScmpFilterContext, ScmpNotifReq};
use libseccomp_sys::scmp_filter_ctx;

use crate::{
	AccessRequest, AccessRequestError, TurnstileTracerError,
	syscalls::{RequestContext, fs, net},
};

use log::error;

fn dump_seccomp_request(req: &ScmpNotifReq) -> String {
	let comm = std::fs::read_to_string(format!("/proc/{}/comm", req.pid))
		.ok()
		.map(|s| s.trim().to_string())
		.unwrap_or_else(|| "???".to_string());
	format!(
		"process: {}[{}]\nsyscall: {} ({})\nargs: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
		comm,
		req.pid,
		req.data.syscall.get_name().unwrap_or("???".to_string()),
		req.data.syscall.as_raw_syscall(),
		req.data.args[0],
		req.data.args[1],
		req.data.args[2],
		req.data.args[3],
		req.data.args[4],
		req.data.args[5],
	)
}

#[derive(Debug)]
pub struct TurnstileTracer {
	/// Stores the seccomp filter context.
	pub filter_ctx: ScmpFilterContext,

	/// Stores the notify fd.
	///
	/// Seccomp only gives us the notification fd at filter load time.
	/// Therefore this is None until a forked child process calls
	/// [`Self::load_filters`].
	pub notify_fd: Option<ScmpFd>,
}

impl TurnstileTracer {
	pub fn new() -> Result<Self, TurnstileTracerError> {
		let mut filter_ctx = ScmpFilterContext::new(libseccomp::ScmpAction::Allow)
			.map_err(TurnstileTracerError::Init)?;
		let native_arch = ScmpArch::native();
		filter_ctx
			.add_arch(native_arch)
			.map_err(TurnstileTracerError::AddArch)?;

		fs::add_filter_rules(&mut filter_ctx)?;
		net::add_filter_rules(&mut filter_ctx)?;

		Ok(Self {
			filter_ctx,
			notify_fd: None,
		})
	}

	/// Process Seccomp notifications and possibly return an access
	/// request (or None if, for example, the syscall accesses an ignored
	/// file).
	///
	/// If an [`AccessRequest`] is returned, the traced process is paused,
	/// and the caller should respond to the request by calling either
	/// [`AccessRequest::send_continue`] or [`AccessRequest::send_error`].
	/// If None is returned, the tracer is set to continue automatically.
	/// The traced process is also resumed if the returned
	/// [`AccessRequest`] is dropped.
	///
	/// If the caller leaks the returned [`AccessRequest`] without
	/// responding to it, the traced process will be paused indefinitely
	/// until it is killed.
	pub fn yield_request<'a>(
		&'a self,
	) -> Result<Option<(AccessRequest, RequestContext<'a>)>, AccessRequestError> {
		let notify_fd = self.notify_fd.expect("notify fd not initialized");
		let req = ScmpNotifReq::receive(notify_fd).map_err(AccessRequestError::NotifyReceive)?;
		let procmem = format!("/proc/{}/mem\0", req.pid);
		let mut ctx = RequestContext {
			_tracer: self,
			sreq: req,
			notify_fd,
			valid: true,
			mem_fd: fs::ForeignFd::from_path(
				CStr::from_bytes_with_nul(procmem.as_bytes()).unwrap(),
			)
			.map_err(|e| AccessRequestError::ReadProcessMemory(req.pid, e))?,
		};
		let result = self.handle_notification(&mut ctx);
		match result {
			Ok(Some(access_req)) => {
				if ctx.still_valid()? == false {
					// If the notification is no longer valid, then we
					// don't want to emit the access request (which might
					// have been constructed out of invalid data)
					return Ok(None);
				}
				Ok(Some((access_req, ctx)))
			}
			Ok(None) => {
				ctx.send_continue()?;
				Ok(None)
			}
			Err(e) => {
				// If the notification is no longer valid, then we ignore
				// any errors encountered while processing it.
				if ctx.still_valid().is_ok_and(|v| v == false) {
					Ok(None)
				} else {
					_ = ctx.send_continue();
					error!(
						"Error while handling seccomp notification:\nRequest: \n{}\nError: {:#?}",
						dump_seccomp_request(&ctx.sreq),
						e
					);
					Err(e)
				}
			}
		}
	}

	fn handle_notification<'a>(
		&'a self,
		req_ctx: &mut RequestContext<'a>,
	) -> Result<Option<AccessRequest>, AccessRequestError> {
		if let Some(req) = crate::syscalls::fs::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		if let Some(req) = crate::syscalls::net::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		return Ok(None);
	}

	/// Load the seccomp filter into the current thread.  Use
	/// [`Self::run_command`] instead for loading the filter into a child
	/// process.
	pub fn install_filters(&mut self) -> Result<(), TurnstileTracerError> {
		if self.notify_fd.is_some() {
			panic!("Seccomp filters already loaded");
		}

		self.filter_ctx.load().map_err(TurnstileTracerError::Load)?;
		let notify_fd = self
			.filter_ctx
			.get_notify_fd()
			.map_err(TurnstileTracerError::NotifyFd)?;
		self.notify_fd = Some(notify_fd);
		Ok(())
	}

	/// Spawn a child process with the seccomp filters installed.
	pub fn run_command(
		&mut self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, TurnstileTracerError> {
		if self.notify_fd.is_some() {
			panic!("Seccomp filters already loaded");
		}

		let mut notify_fd_sock = [-1, -1];
		unsafe {
			if libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				notify_fd_sock.as_mut_ptr(),
			) != 0
			{
				return Err(TurnstileTracerError::Socketpair(
					std::io::Error::last_os_error(),
				));
			}
		}
		let child_sock = notify_fd_sock[1];
		let parent_sock = notify_fd_sock[0];
		let scmpctx_ptr = SendableContextPtr(self.filter_ctx.as_ptr());
		unsafe {
			cmd.pre_exec(move || {
				libc::close(parent_sock);

				let scmpctx_ptr = scmpctx_ptr.into_ptr();
				let rc = libseccomp_sys::seccomp_load(scmpctx_ptr);
				if rc != 0 {
					panic!("seccomp_load failed with error code {}", rc);
				}
				let notify_fd = libseccomp_sys::seccomp_notify_fd(scmpctx_ptr);
				if notify_fd < 0 {
					panic!(
						"seccomp_notify_fd failed with error code {}",
						-1 * notify_fd
					);
				}

				// Send notify_fd to the parent via SCM_RIGHTS.
				unix_send_fd(child_sock, notify_fd)?;

				libc::close(child_sock);
				libc::close(notify_fd);
				Ok(())
			});
		}
		unsafe {
			libc::close(child_sock);
		}

		let child = cmd.spawn().map_err(TurnstileTracerError::Spawn)?;
		let received_fd =
			unix_recv_fd(parent_sock).map_err(TurnstileTracerError::TransferNotifyFd)?;
		unsafe {
			libc::close(parent_sock);
		}
		self.notify_fd = Some(received_fd);

		Ok(child)
	}
}

#[derive(Copy, Clone)]
struct SendableContextPtr(scmp_filter_ctx);
unsafe impl Send for SendableContextPtr {}
unsafe impl Sync for SendableContextPtr {}
impl SendableContextPtr {
	fn into_ptr(self) -> scmp_filter_ctx {
		self.0
	}
}

/// Send a file descriptor to another process via a Unix socket using SCM_RIGHTS.
unsafe fn unix_send_fd(sock: libc::c_int, fd: libc::c_int) -> std::io::Result<()> {
	// Use a [u64] buffer to ensure 8-byte alignment required by cmsghdr.
	let cmsg_space =
		unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize };
	let num_u64s = (cmsg_space + 7) / 8;
	let mut cmsg_buf: Vec<u64> = vec![0u64; num_u64s];

	let mut dummy: u8 = 0;
	let mut iov = libc::iovec {
		iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
		iov_len: 1,
	};

	let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
	msg.msg_controllen = (num_u64s * 8) as libc::size_t;

	unsafe {
		let cmsg = libc::CMSG_FIRSTHDR(&msg);
		if cmsg.is_null() {
			// io::Error::new() allocates and is not safe in a pre_exec context;
			// this branch is unreachable since we sized the buffer correctly above.
			panic!("CMSG_FIRSTHDR returned null");
		}
		(*cmsg).cmsg_level = libc::SOL_SOCKET;
		(*cmsg).cmsg_type = libc::SCM_RIGHTS;
		(*cmsg).cmsg_len =
			libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as libc::size_t;
		let fd_data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
		std::ptr::write_unaligned(fd_data, fd);
	}

	let ret = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
	if ret < 0 {
		return Err(std::io::Error::last_os_error());
	}
	Ok(())
}

/// Receive a file descriptor sent via SCM_RIGHTS over a Unix socket.
fn unix_recv_fd(sock: libc::c_int) -> std::io::Result<libc::c_int> {
	let cmsg_space =
		unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize };
	let num_u64s = (cmsg_space + 7) / 8;
	let mut cmsg_buf: Vec<u64> = vec![0u64; num_u64s];

	let mut dummy: u8 = 0;
	let mut iov = libc::iovec {
		iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
		iov_len: 1,
	};

	let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
	msg.msg_controllen = (num_u64s * 8) as libc::size_t;

	let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
	if ret < 0 {
		return Err(std::io::Error::last_os_error());
	}
	if ret == 0 {
		return Err(std::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			"child closed socket without sending notify fd",
		));
	}

	let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
	if cmsg.is_null() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"no control message received",
		));
	}
	let received_fd =
		unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int) };
	Ok(received_fd)
}
