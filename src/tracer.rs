use std::{
	cell::Cell,
	ffi::CStr,
	io::Write,
	os::unix::process::CommandExt,
	sync::{
		OnceLock,
		atomic::{AtomicBool, Ordering},
	},
	thread,
};

use libseccomp::{ScmpArch, ScmpFd, ScmpFilterContext, ScmpNotifReq};
use libseccomp_sys::scmp_filter_ctx;

use crate::{
	AccessRequest, AccessRequestError, TurnstileTracerError,
	fs::ForeignFd,
	syscalls::{self, RequestContext},
	utils::{unix_recv_fd, unix_send_fd},
};

use log::{error, warn};

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

/// loads seccomp filters and, if `send_to_parent` is true, sends the
/// notify fd via `child_sock` and closes the acquired notify fd.
/// parent_sock and child_sock are always closed, and if `send_to_parent`
/// is true, notify_fd is always closed even if we fail to send it.
unsafe fn install_filters_impl(
	ctx_ptr: scmp_filter_ctx,
	parent_sock: libc::c_int,
	child_sock: libc::c_int,
	send_to_parent: bool,
) -> Result<Option<ScmpFd>, TurnstileTracerError> {
	unsafe {
		let rc = libseccomp_sys::seccomp_load(ctx_ptr);
		if rc != 0 {
			return Err(TurnstileTracerError::Load(rc));
		}
		let notify_fd = libseccomp_sys::seccomp_notify_fd(ctx_ptr);
		if notify_fd < 0 {
			return Err(TurnstileTracerError::NotifyFd(notify_fd));
		}

		let send_result = if send_to_parent {
			unix_send_fd(child_sock, notify_fd)
		} else {
			Ok(())
		};

		if send_to_parent {
			libc::close(notify_fd);
		}
		libc::close(parent_sock);
		libc::close(child_sock);

		send_result.map_err(TurnstileTracerError::SendNotifyFd)?;
		if send_to_parent {
			Ok(None)
		} else {
			Ok(Some(notify_fd))
		}
	}
}

/// Allow passing a scmp_filter_ctx into a pre_exec hook
#[derive(Copy, Clone)]
struct SendableContextPtr(scmp_filter_ctx);
unsafe impl Send for SendableContextPtr {}
unsafe impl Sync for SendableContextPtr {}
impl SendableContextPtr {
	unsafe fn into_ptr(self) -> scmp_filter_ctx {
		self.0
	}
}

macro_rules! notify_fd_state_panic {
	() => {
		panic!("install_filters, receive_notify_fd or run_command called multiple times.")
	};
}

#[derive(Debug)]
struct TracerNotifyFdState {
	notify_fd: OnceLock<ScmpFd>,
	sock_pair: Cell<[libc::c_int; 2]>,
	sock_pair_taken: AtomicBool,
}

// Safety: The sock_pair Cell is guarded by the sock_pair_taken AtomicBool
unsafe impl Sync for TracerNotifyFdState {}

impl TracerNotifyFdState {
	fn new(sock_pair: [libc::c_int; 2]) -> Self {
		Self {
			notify_fd: OnceLock::new(),
			sock_pair: Cell::new(sock_pair),
			sock_pair_taken: AtomicBool::new(false),
		}
	}

	fn wait_notify_fd(&self) -> ScmpFd {
		*self.notify_fd.wait()
	}

	fn take_sock_pair(&self) -> [libc::c_int; 2] {
		if self.notify_fd.get().is_some() || self.sock_pair_taken.swap(true, Ordering::SeqCst) {
			notify_fd_state_panic!();
		}
		self.sock_pair.replace([-1, -1])
	}

	fn store_notify_fd(&self, notify_fd: ScmpFd) {
		self.notify_fd
			.set(notify_fd)
			.unwrap_or_else(|_| notify_fd_state_panic!());
	}
}

impl Drop for TracerNotifyFdState {
	fn drop(&mut self) {
		let pair = self.sock_pair.get();
		unsafe {
			if pair[0] != -1 {
				libc::close(pair[0]);
			}
			if pair[1] != -1 {
				libc::close(pair[1]);
			}
		}
	}
}

/// Implements a seccomp-unotify-based access tracer.
///
/// <div class="warning">
/// Seccomp-unotify is not a sandboxing solution on its own due to the
/// limitations of syscall-based filtering (such as TOCTOU problems with
/// memory references).  This struct does not provide any security when
/// used alone.
/// </div>
#[derive(Debug)]
pub struct TurnstileTracer {
	/// Stores the seccomp filter context.
	filter_ctx: ScmpFilterContext,

	/// Manages the notify fd and socket pair for communicating it
	/// between parent and child processes.
	notify_fd_state: TracerNotifyFdState,
}

unsafe impl Sync for TurnstileTracer {}
unsafe impl Send for TurnstileTracer {}

impl TurnstileTracer {
	pub fn new() -> Result<Self, TurnstileTracerError> {
		let mut filter_ctx = ScmpFilterContext::new(libseccomp::ScmpAction::Allow)
			.map_err(TurnstileTracerError::Init)?;
		let native_arch = ScmpArch::native();
		filter_ctx
			.add_arch(native_arch)
			.map_err(TurnstileTracerError::AddArch)?;

		syscalls::fs::add_filter_rules(&mut filter_ctx)?;
		syscalls::net::add_filter_rules(&mut filter_ctx)?;

		let mut notify_fd_sock_pair = [-1i32; 2];
		unsafe {
			if libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				notify_fd_sock_pair.as_mut_ptr(),
			) != 0
			{
				return Err(TurnstileTracerError::Socketpair(
					std::io::Error::last_os_error(),
				));
			}
		}
		assert_ne!(notify_fd_sock_pair[0], -1);
		assert_ne!(notify_fd_sock_pair[1], -1);

		Ok(Self {
			filter_ctx,
			notify_fd_state: TracerNotifyFdState::new(notify_fd_sock_pair),
		})
	}

	/// Process Seccomp notifications and possibly return an access
	/// request (or None if, for example, the syscall accesses an ignored
	/// file).
	///
	/// If an [`AccessRequest`](crate::AccessRequest) along with its
	/// [`RequestContext`](crate::RequestContext) is returned, the traced
	/// process is paused, and the caller should respond to the request by
	/// calling either
	/// [`RequestContext::send_continue`](crate::RequestContext::send_continue)
	/// or
	/// [`RequestContext::send_error`](crate::RequestContext::send_error).
	/// If None is returned, the tracer is set to continue automatically.
	/// The traced process is also resumed if the returned
	/// [`RequestContext`](crate::RequestContext) is dropped.
	///
	/// If the caller leaks the returned
	/// [`RequestContext`](crate::RequestContext) without responding to
	/// it, the traced process will be paused indefinitely until it
	/// receives a signal.
	///
	/// Blocks until the notify_fd is ready if it is not.
	pub fn yield_request<'a>(
		&'a self,
	) -> Result<Option<(AccessRequest, RequestContext<'a>)>, AccessRequestError> {
		let notify_fd = self.notify_fd_state.wait_notify_fd();
		let req = ScmpNotifReq::receive(notify_fd).map_err(AccessRequestError::NotifyReceive)?;
		let procmem = format!("/proc/{}/mem\0", req.pid);
		let mut ctx = RequestContext {
			_tracer: self,
			sreq: req,
			notify_fd,
			valid: true,
			mem_fd: ForeignFd::from_path_with_flags(
				CStr::from_bytes_with_nul(procmem.as_bytes()).unwrap(),
				libc::O_RDONLY | libc::O_CLOEXEC,
			)
			.map_err(|e| AccessRequestError::ReadProcessMemoryOpen(req.pid, e))?,
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
					let cont_err = ctx.send_continue();
					if let AccessRequestError::InvalidSyscallData(s) = e {
						warn!(
							"Got invalid syscall for request:\n{}\nError: {}",
							dump_seccomp_request(&ctx.sreq),
							s
						);
					} else {
						error!(
							"Error while handling seccomp notification:\nRequest: \n{}\nError: {:#?}",
							dump_seccomp_request(&ctx.sreq),
							e
						);
					}
					if let Err(e) = cont_err {
						error!("failed to send continue response: {:#?}", e);
					}
					Err(e)
				}
			}
		}
	}

	fn handle_notification<'a>(
		&'a self,
		req_ctx: &mut RequestContext<'a>,
	) -> Result<Option<AccessRequest>, AccessRequestError> {
		if let Some(req) = syscalls::fs::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		if let Some(req) = syscalls::net::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		return Ok(None);
	}

	/// Set the tsync flag on the seccomp filter.  This means that if
	/// [`Self::install_filters`] is called from the current thread
	/// instead of a fork, the filters will be applied to all threads in
	/// this process.
	pub fn set_tsync(&mut self, value: bool) -> Result<(), TurnstileTracerError> {
		self.filter_ctx
			.set_ctl_tsync(value)
			.map_err(TurnstileTracerError::SetCtlTsync)
			.map(|_| {})
	}

	/// Set the no_new_privs flag on the seccomp filter.  Setting this to
	/// false will require CAP_SYS_ADMIN to load the filters.
	pub fn set_no_new_privs(&mut self, value: bool) -> Result<(), TurnstileTracerError> {
		self.filter_ctx
			.set_ctl_nnp(value)
			.map_err(TurnstileTracerError::SetCtlNoNewPrivs)
			.map(|_| {})
	}

	/// Load the seccomp filter into the current thread, or process if
	/// tsync is set.
	///
	/// This function is safe to call from a pre_exec hook, but in such
	/// cases one may wish to use [`Self::run_command`] instead.
	///
	/// If `send_to_parent` is true, sends the seccomp notify fd to a
	/// parent process via the internal socket pair, then closes the
	/// notify fd in this process.  The parent should call
	/// [`Self::receive_notify_fd`] after forking to receive the notify
	/// fd.
	///
	/// If `send_to_parent` is false, stores the notify fd internally,
	/// such that [`Self::yield_request`] can be used to handle access
	/// requests made by this process itself.
	///
	/// This function can only be called once, and is also mutually
	/// exclusive with [`Self::run_command`].
	pub fn install_filters(&self, send_to_parent: bool) -> Result<(), TurnstileTracerError> {
		let [parent_sock, child_sock] = self.notify_fd_state.take_sock_pair();
		let ctx_ptr = self.filter_ctx.as_ptr();
		unsafe {
			let notify_fd = install_filters_impl(ctx_ptr, parent_sock, child_sock, send_to_parent)?;
			if !send_to_parent {
				self.notify_fd_state.store_notify_fd(notify_fd.unwrap());
			}
		}
		Ok(())
	}

	/// Receive the notify fd from a child process via the internal socket
	/// pair.  This should be called in the parent process *after* forking
	/// a child that will call [`Self::install_filters`] with
	/// `send_to_parent` set to `true`.
	///
	/// This function can only be called once, and is also mutually
	/// exclusive with [`Self::run_command`].
	pub fn receive_notify_fd(&self) -> Result<(), TurnstileTracerError> {
		let [parent_sock, child_sock] = self.notify_fd_state.take_sock_pair();
		unsafe {
			libc::close(child_sock);
		}
		let received_fd = unix_recv_fd(parent_sock);
		unsafe {
			libc::close(parent_sock);
		}
		let received_fd = received_fd.map_err(TurnstileTracerError::ReceiveNotifyFd)?;
		self.notify_fd_state.store_notify_fd(received_fd);
		Ok(())
	}

	/// Spawn a child process with the seccomp filters installed.
	///
	/// The caller should arrange to process notifications via
	/// [`Self::yield_request`] on another thread before calling this, as
	/// this function will block until the execve() is done, which will
	/// require the caller to allow the file access to continue.
	///
	/// Should the caller wish to do more complex setup in the pre_exec
	/// stage, [`Command::pre_exec`](std::process::Command::pre_exec) can
	/// be used to install more pre_exec hooks that will be called before
	/// the seccomp filters are loaded.  Alternatively, the caller can
	/// call [`Self::install_filters`] directly from a forked process.
	///
	/// This function can only be called once, and is also mutually
	/// exclusive with [`Self::install_filters`].
	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, TurnstileTracerError> {
		let [parent_sock, child_sock] = self.notify_fd_state.take_sock_pair();
		let ctx_ptr = SendableContextPtr(self.filter_ctx.as_ptr());
		unsafe {
			cmd.pre_exec(move || {
				// both sock fds in child closed in this function
				match install_filters_impl(ctx_ptr.into_ptr(), parent_sock, child_sock, true) {
					Ok(_) => return Ok(()),
					Err(e) => {
						let mut buf = [0; 512];
						let buflen = buf.len();
						let mut bufwrite = &mut buf[..];
						let _ = write!(
							bufwrite,
							"Failed to install filters in child process: {}",
							e
						);
						let count = buflen - bufwrite.len();
						libc::write(
							libc::STDERR_FILENO,
							buf.as_ptr() as *const libc::c_void,
							count,
						);
						return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
					}
				}
			});
		}

		thread::scope(|s| {
			let jh = s.spawn(|| -> Result<(), TurnstileTracerError> {
				let received_fd = unix_recv_fd(parent_sock);
				// parent sock fd in parent closed here
				unsafe {
					libc::close(parent_sock);
				}
				let received_fd = received_fd.map_err(TurnstileTracerError::ReceiveNotifyFd)?;
				self.notify_fd_state.store_notify_fd(received_fd);
				Ok(())
			});

			match cmd.spawn() {
				// child sock fd in parent closed here.  Closing the
				// child_sock here will also means that if the child died
				// without sending a notify fd, we don't wait forever.
				Ok(child) => {
					unsafe { libc::close(child_sock) };
					jh.join().expect("receiver thread panicked")?;
					Ok(child)
				}
				Err(e) => {
					unsafe { libc::close(child_sock) };
					let _ = jh.join();
					Err(TurnstileTracerError::Spawn(e))
				}
			}
		})
	}
}
