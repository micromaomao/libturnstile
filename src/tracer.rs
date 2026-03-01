use core::panic;

use libseccomp::{
	ScmpArch, ScmpFd, ScmpFilterContext, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags,
};

use crate::{AccessRequest, TurnstileTracerError};

pub struct TurnstileTracer {
	/// Stores the seccomp filter context.
	pub filter_ctx: ScmpFilterContext,

	/// Socket pair used for sending the notification fd to the parent.
	notify_fd_sock: [libc::c_int; 2],

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

		Ok(Self {
			filter_ctx,
			notify_fd_sock,
			notify_fd: None,
		})
	}

	pub fn receive_notify_fd(&mut self) -> Result<(), TurnstileTracerError> {
		todo!("Receive notify fd via scm_rights and store it in self.notify_fd");
	}

	/// Process Seccomp notifications and possibly return an access
	/// request (or None if, for example, the syscall accesses an ignored
	/// file).
	pub fn yield_request<'a>(&'a self) -> Result<Option<AccessRequest<'a>>, TurnstileTracerError> {
		let notify_fd = self.notify_fd.expect("notify fd not initialized");
		let req = ScmpNotifReq::receive(notify_fd).map_err(TurnstileTracerError::NotifyReceive)?;
		let (resp, maybe_arq) = self.handle_notification(req)?;
		resp.respond(notify_fd)
			.map_err(TurnstileTracerError::NotifyRespond)?;
		Ok(maybe_arq)
	}

	fn handle_notification<'a>(
		&'a self,
		req: ScmpNotifReq,
	) -> Result<(ScmpNotifResp, Option<AccessRequest<'a>>), TurnstileTracerError> {
		if let Some((resp, maybe_arq)) = crate::syscalls::fs::handle_notification(self, &req)? {
			Ok((resp, maybe_arq))
		} else {
			// TODO: log an unhandled request warning (our filter should
			// not produce any requests that we don't handle).
			Ok((
				ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty()),
				None,
			))
		}
	}

	/// Load the seccomp filter into the current thread.  This should
	/// usually be used with
	/// [`std::os::unix::process::CommandExt::pre_exec`] but can also be
	/// used directly.  This can only be called once, since we only handle
	/// one notification fd.  Any calls after the first one will panic.
	///
	/// This function is safe to call in pre_exec context, and will pass
	/// the notify fd acquired to the parent via a Unix socket.  The
	/// parent should then call [`Self::receive_notify_fd`] before calling
	/// [`Self::yield_request`].
	pub fn load_filters(&mut self) -> Result<(), &'static str> {
		if self.notify_fd.is_some() {
			panic!("load_filters() already called before.");
		}
		if let Err(es) = self.filter_ctx.load() {
			if let Some(_) = es.errno() {
				// Unfortunately, even though eno.strerror() returns a
				// &'static str, that function is not public, and the only
				// public interface is via Display.  Since we cannot
				// allocate in this context, we will just have to do this
				// for now.
				return Err("seccomp_load failed");
			} else {
				return Err("seccomp_load failed with unknown error");
			}
		}
		let notify_fd = self
			.filter_ctx
			.get_notify_fd()
			.map_err(|_| "failed to get notify fd")?;
		self.notify_fd = Some(notify_fd);
		todo!("Send notify_fd via scm_rights");
	}
}
