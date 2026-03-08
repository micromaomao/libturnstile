use std::{ffi::CStr, io};

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

/// Lazily resolves a syscall-name table into a `ScmpSyscall`-keyed `Vec`,
/// built once via `OnceLock`.
///
/// Usage:
/// ```ignore
/// lazy_syscall_table_name_to_number!(TABLE, fn_name, Type1, Type2, ...);
/// ```
/// Generates `fn fn_name() -> &'static Vec<(ScmpSyscall, Type1, Type2, ...)>`.
/// The source table must be `&[(&str, Type1, Type2, ...)]` where the leading
/// `&str` is the syscall name; it is resolved to a `ScmpSyscall` number and
/// entries whose name cannot be resolved are silently dropped (e.g. on
/// architectures that don't have that syscall).
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
		// Avoid zero-initializing: pread will fill the bytes and we'll truncate
		// to the actual number read before inspecting the buffer.
		let mut buf: Vec<u8> = Vec::new();
		buf.reserve_exact(first_len);
		// Safety: the bytes are written by pread before we inspect them, and we
		// truncate to the number of bytes actually written immediately after.
		unsafe { buf.set_len(first_len) };

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
			// buf has been truncated at the NUL position; no interior NUL is possible.
			return Ok(
				std::ffi::CString::new(buf).expect("buf should not have NUL bytes in the middle")
			);
		}

		if (ret as usize) < first_len {
			warn!(
				"Short read from /proc/{}/mem: expected {} bytes, got {}",
				self.sreq.pid, first_len, ret
			);
			return Err(AccessRequestError::ShortReadProcessMemory(
				self.sreq.pid,
				first_len,
				ret as usize,
			));
		}

		// Second read: one more full page.
		let second_addr = first_end;
		let mut buf2: Vec<u8> = Vec::new();
		buf2.reserve_exact(PAGE_SIZE);
		// Safety: same as above — pread fills these bytes before we read them.
		unsafe { buf2.set_len(PAGE_SIZE) };

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
			// Neither buf (no NUL found in first page) nor buf2[..nul] contains
			// a NUL byte, so CString::new cannot fail here.
			return Ok(
				std::ffi::CString::new(buf).expect("buf should not have NUL bytes in the middle")
			);
		}

		if (ret as usize) < PAGE_SIZE {
			warn!(
				"Short read from /proc/{}/mem: expected {} bytes, got {}",
				self.sreq.pid, PAGE_SIZE, ret
			);
			return Err(AccessRequestError::ShortReadProcessMemory(
				self.sreq.pid,
				PAGE_SIZE,
				ret as usize,
			));
		}

		Err(AccessRequestError::InvalidSyscallData(
			"provided path string exceeds PATH_MAX",
		))
	}

	/// Reads the syscall argument at `fd_arg_index` and opens it as a
	/// `ForeignFd` via `/proc/{pid}/...`.  Handles `AT_FDCWD` (→ cwd),
	/// non-negative fds (→ `/proc/{pid}/fd/{fd}`), and returns an error for
	/// negative non-`AT_FDCWD` values or values that don't fit in `c_int`.
	pub(crate) fn arg_to_fd(
		&mut self,
		fd_arg_index: usize,
	) -> Result<ForeignFd, AccessRequestError> {
		let raw = self.arg(fd_arg_index) as i64;
		let fd = libc::c_int::try_from(raw)
			.map_err(|_| AccessRequestError::InvalidSyscallData("fd arg not a valid c_int"))?;
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
			warn!(
				"Short read from /proc/{}/mem: expected {} bytes, got {}",
				self.sreq.pid, size, ret
			);
			return Err(AccessRequestError::ShortReadProcessMemory(
				self.sreq.pid,
				size,
				ret as usize,
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
