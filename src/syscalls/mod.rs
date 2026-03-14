use std::{ffi::CStr, io, mem::MaybeUninit, slice};

use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use log::warn;

use crate::{AccessRequestError, TurnstileTracer, syscalls::fs::ForeignFd};
use std::os::unix::io::AsRawFd;

pub mod fs;
pub mod net;

macro_rules! syscall_transform_tuple {
	($sys:expr, $t:expr, $ty1:ty) => {
		($sys, $t.1)
	};
	($sys:expr, $t:expr, $ty1:ty, $ty2:ty) => {
		($sys, $t.1, $t.2)
	};
	($sys:expr, $t:expr, $ty1:ty, $ty2:ty, $ty3:ty) => {
		($sys, $t.1, $t.2, $t.3)
	};
	($sys:expr, $t:expr, $ty1:ty, $ty2:ty, $ty3:ty, $ty4:ty) => {
		($sys, $t.1, $t.2, $t.3, $t.4)
	};
	($sys:expr, $t:expr, $ty1:ty, $ty2:ty, $ty3:ty, $ty4:ty, $ty5:ty) => {
		($sys, $t.1, $t.2, $t.3, $t.4, $t.5)
	};
	($sys:expr, $t:expr, $ty1:ty, $ty2:ty, $ty3:ty, $ty4:ty, $ty5:ty, $ty6:ty) => {
		($sys, $t.1, $t.2, $t.3, $t.4, $t.5, $t.6)
	};
}

pub(crate) use syscall_transform_tuple;

/// Resolve all syscall names in a table into their `ScmpSyscall` value
/// for the native architecture.  Entries whose name cannot be resolved
/// are dropped.
macro_rules! lazy_syscall_table_name_to_number {
	($table:expr, $fn_name:ident, $($t:ty),*) => {
		fn $fn_name() -> &'static Vec<(libseccomp::ScmpSyscall, $($t),*)> {
			static ONCE: std::sync::OnceLock<Vec<(libseccomp::ScmpSyscall, $($t),*)>> =
				std::sync::OnceLock::new();
			ONCE.get_or_init(|| {
				$table
					.iter()
					.filter_map(|tuple| {
						let name = tuple.0;
						libseccomp::ScmpSyscall::from_name(name)
							.ok()
							.map(|resolved_syscall| {
								crate::syscalls::syscall_transform_tuple!(resolved_syscall, tuple, $($t),*)
							})
					})
					.collect()
			})
		}
	};
}
pub(crate) use lazy_syscall_table_name_to_number;

#[derive(Debug)]
pub struct RequestContext<'a> {
	pub(crate) _tracer: &'a TurnstileTracer,
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
		let page_sz = page_size::get();
		let addr = src as usize;

		// First read: from addr to the end of the current page.
		let first_end = (addr + page_sz) & !(page_sz - 1);
		let first_len = first_end - addr;
		let mut buf: Vec<u8> = Vec::with_capacity(first_len);
		let uninit_buf = unsafe {
			slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, first_len)
		};
		self.read_target_memory(addr as *const u8, uninit_buf)?;
		unsafe { buf.set_len(first_len) };

		if let Some(nul) = buf.iter().position(|&b| b == 0) {
			buf.truncate(nul + 1);
			// buf has been truncated to include the first NUL byte; no interior NUL is possible.
			return Ok(std::ffi::CString::from_vec_with_nul(buf)
				.expect("buf should not have NUL bytes in the middle"));
		}

		// Second read: one more full page appended to buf
		let old_len = buf.len();
		buf.reserve_exact(page_sz);

		let uninit_buf_2 = unsafe {
			slice::from_raw_parts_mut(
				buf.as_mut_ptr().add(old_len) as *mut MaybeUninit<u8>,
				page_sz,
			)
		};
		self.read_target_memory(first_end as *const u8, uninit_buf_2)?;
		unsafe { buf.set_len(old_len + page_sz) };

		if let Some(nul) = buf[old_len..].iter().position(|&b| b == 0) {
			buf.truncate(old_len + nul + 1);
			return Ok(std::ffi::CString::from_vec_with_nul(buf)
				.expect("buf should not have NUL bytes in the middle"));
		}

		Err(AccessRequestError::InvalidSyscallData(
			"provided path string exceeds PATH_MAX",
		))
	}

	/// Reads the syscall argument at `fd_arg_index` and opens it as a
	/// `ForeignFd` via `/proc/{pid}/...`.  Does error checking and
	/// handles AT_FDCWD.
	pub(crate) fn arg_to_fd(
		&mut self,
		fd_arg_index: usize,
	) -> Result<ForeignFd, AccessRequestError> {
		let fd = self.arg(fd_arg_index) as libc::c_int;
		if fd == libc::AT_FDCWD {
			let path = format!("/proc/{}/cwd\0", self.sreq.pid);
			ForeignFd::from_path(CStr::from_bytes_with_nul(path.as_bytes()).unwrap())
				.map_err(|e| AccessRequestError::OpenFd(path, e))
		} else if fd >= 0 {
			let path = format!("/proc/{}/fd/{}\0", self.sreq.pid, fd);
			ForeignFd::from_path(CStr::from_bytes_with_nul(path.as_bytes()).unwrap())
				.map_err(|e| AccessRequestError::OpenFd(path, e))
		} else {
			Err(AccessRequestError::InvalidSyscallData("fd invalid"))
		}
	}

	fn read_target_memory_partial(
		&mut self,
		src: *const u8,
		buf: &mut [MaybeUninit<u8>],
	) -> Result<usize, AccessRequestError> {
		let ret = unsafe {
			libc::pread(
				self.mem_fd.as_raw_fd(),
				buf.as_mut_ptr() as *mut libc::c_void,
				buf.len(),
				src as libc::off_t,
			)
		};
		if ret < 0 {
			return Err(AccessRequestError::ReadProcessMemoryPread(
				self.sreq.pid,
				io::Error::last_os_error(),
			));
		}
		Ok(ret as usize)
	}

	pub(crate) fn read_target_memory(
		&mut self,
		src: *const u8,
		buf: &mut [MaybeUninit<u8>],
	) -> Result<(), AccessRequestError> {
		let ret = self.read_target_memory_partial(src, buf)?;
		if ret != buf.len() {
			warn!(
				"Short read from /proc/{}/mem: expected {} bytes, got {}",
				self.sreq.pid,
				buf.len(),
				ret
			);
			return Err(AccessRequestError::ShortReadProcessMemory(
				self.sreq.pid,
				buf.len(),
				ret,
			));
		}
		Ok(())
	}

	pub(crate) fn value_from_target_memory<T: Copy>(
		&mut self,
		src: *const T,
	) -> Result<T, AccessRequestError> {
		let size = std::mem::size_of::<T>();
		let mut val = std::mem::MaybeUninit::<T>::uninit();
		{
			let buf = unsafe {
				slice::from_raw_parts_mut(val.as_mut_ptr() as *mut MaybeUninit<u8>, size)
			};
			self.read_target_memory(src as *const u8, buf)?;
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
