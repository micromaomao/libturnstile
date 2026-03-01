use core::panic;
use std::os::unix::process::CommandExt;

use libseccomp::{
	ScmpArch, ScmpFd, ScmpFilterContext, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags,
};
use libseccomp_sys::scmp_filter_ctx;

use crate::{
	AccessRequest, AccessRequestError, TurnstileTracerError,
	syscalls::{RequestContext, fs},
};

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
		let mut ctx = RequestContext {
			tracer: self,
			sreq: req,
			notify_fd,
			valid: true,
		};
		let result = self.handle_notification(&mut ctx);
		match result {
			Ok(Some(access_req)) => Ok(Some((access_req, ctx))),
			Ok(None) => {
				ctx.send_continue()?;
				Ok(None)
			}
			Err(e) => {
				// If the notification is no longer valid, then we ignore
				// any errors encountered while processing it.
				if ctx.still_valid() == Ok(false) {
					Ok(None)
				} else {
					_ = ctx.send_continue();
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

	/// Load the seccomp filter into the current thread.
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
					panic!("seccomp_load failed with error code: {}", rc);
				}
				let notify_fd = libseccomp_sys::seccomp_notify_fd(scmpctx_ptr);
				todo!("Send notify_fd via scm_rights on child_sock");
				libc::close(child_sock);
				libc::close(notify_fd);
				Ok(())
			});
		}
		unsafe {
			libc::close(child_sock);
		}

		let child = cmd.spawn().map_err(TurnstileTracerError::Spawn)?;
		todo!("Receive notify fd from parent_sock via scm_rights and store it in self.notify_fd");
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
