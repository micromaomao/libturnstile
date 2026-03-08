use std::io;

use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use log::warn;

use crate::{AccessRequestError, TurnstileTracer, syscalls::fs::ForeignFd};
use std::os::unix::io::AsRawFd;

pub mod fs;
pub mod net;

#[derive(Debug)]
pub struct RequestContext<'a> {
	pub(crate) tracer: &'a TurnstileTracer,
	pub(crate) sreq: ScmpNotifReq,
	pub(crate) notify_fd: ScmpFd,
	pub(crate) valid: bool,
	pub(crate) mem_fd: ForeignFd,
}

impl<'a> RequestContext<'a> {
	pub fn sreq(&self) -> &ScmpNotifReq {
		&self.sreq
	}

	pub fn arg(&self, index: usize) -> u64 {
		self.sreq.data.args[index]
	}

	pub(crate) fn still_valid(&mut self) -> Result<bool, AccessRequestError> {
		if !self.valid {
			return Ok(false);
		}
		match libseccomp::notify_id_valid(self.notify_fd, self.sreq.id) {
			Ok(()) => Ok(true),
			Err(e) => {
				if e.errno() == Some(libseccomp::error::SeccompErrno::ENOENT) {
					self.valid = false;
					Ok(false)
				} else {
					Err(AccessRequestError::NotifyIdValid(e))
				}
			}
		}
	}

	pub(crate) fn send_response(
		&mut self,
		resp: libseccomp::ScmpNotifResp,
	) -> Result<(), AccessRequestError> {
		if self.valid {
			resp.respond(self.notify_fd)
				.map_err(AccessRequestError::NotifyRespond)?;
			self.valid = false;
		}
		Ok(())
	}

	pub fn send_continue(&mut self) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_continue(
			self.sreq.id,
			ScmpNotifRespFlags::empty(),
		))
	}

	/// Users are reminded that this should not be used to deny access
	/// unless there is a separate sandboxing mechanism making sure that
	/// the access would be denied should the traced process attempt to
	/// modify any path buffers from another thread.
	pub fn send_error(&mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_error(
			self.sreq.id,
			errno,
			ScmpNotifRespFlags::empty(),
		))
	}

	pub(crate) fn cstr_from_target_memory(
		&mut self,
		src: *const libc::c_char,
	) -> Result<std::ffi::CString, AccessRequestError> {
		const PAGE_SIZE: usize = 4096;
		let addr = src as usize;

		// First read: from addr to the end of the current page.
		let first_end = (addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
		let first_len = first_end - addr;
		let mut buf = vec![0u8; first_len];

		let ret = unsafe {
			libc::pread(
				self.mem_fd.as_raw_fd(),
				buf.as_mut_ptr() as *mut libc::c_void,
				first_len,
				addr as libc::off_t,
			)
		};
		if ret < 0 {
			return Err(AccessRequestError::ReadProcessMemory(
				self.sreq.pid,
				io::Error::last_os_error(),
			));
		}
		buf.truncate(ret as usize);

		if let Some(nul) = buf.iter().position(|&b| b == 0) {
			buf.truncate(nul);
			return std::ffi::CString::new(buf)
				.map_err(|_| AccessRequestError::InvalidSyscallData("interior NUL byte in path"));
		}

		// Second read: one more full page.
		let second_addr = first_end;
		let mut buf2 = vec![0u8; PAGE_SIZE];
		let ret = unsafe {
			libc::pread(
				self.mem_fd.as_raw_fd(),
				buf2.as_mut_ptr() as *mut libc::c_void,
				PAGE_SIZE,
				second_addr as libc::off_t,
			)
		};
		if ret < 0 {
			return Err(AccessRequestError::ReadProcessMemory(
				self.sreq.pid,
				io::Error::last_os_error(),
			));
		}
		buf2.truncate(ret as usize);

		if let Some(nul) = buf2.iter().position(|&b| b == 0) {
			buf.extend_from_slice(&buf2[..nul]);
			return std::ffi::CString::new(buf)
				.map_err(|_| AccessRequestError::InvalidSyscallData("interior NUL byte in path"));
		}

		Err(AccessRequestError::InvalidSyscallData(
			"provided path string exceeds PATH_MAX",
		))
	}

	pub(crate) fn value_from_target_memory<T: Copy>(
		&mut self,
		src: *const T,
	) -> Result<T, AccessRequestError> {
		let size = std::mem::size_of::<T>();
		let mut val = std::mem::MaybeUninit::<T>::uninit();
		let ret = unsafe {
			libc::pread(
				self.mem_fd.as_raw_fd(),
				val.as_mut_ptr() as *mut libc::c_void,
				size,
				src as libc::off_t,
			)
		};
		if ret < 0 {
			return Err(AccessRequestError::ReadProcessMemory(
				self.sreq.pid,
				io::Error::last_os_error(),
			));
		}
		if ret as usize != size {
			return Err(AccessRequestError::InvalidSyscallData(
				"short read from process memory",
			));
		}
		Ok(unsafe { val.assume_init() })
	}
}

impl Drop for RequestContext<'_> {
	fn drop(&mut self) {
		if self.still_valid().is_ok_and(|v| v) {
			warn!("RequestContext dropped without sending a response — auto-continuing");
			_ = self.send_continue();
		}
	}
}
