use std::{
	ffi::{CStr, OsString},
	fs::File,
	io::{self, Read},
	mem::MaybeUninit,
	os::unix::ffi::OsStringExt,
	slice,
};

use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use log::warn;

use crate::{AccessRequestError, TurnstileTracer, access::fs::ForeignFd};
use std::os::unix::io::{AsRawFd, RawFd};

pub mod fs;
pub mod net;

// `_IOC`-style ioctl number for `SECCOMP_IOCTL_NOTIF_ADDFD`, computed
// with the asm-generic encoding used by all architectures libseccomp
// supports natively here (x86-64 / aarch64 / etc.).  This evaluates to
// 0x40182103 on those platforms, which a unit test below asserts.
const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_SIZEBITS: u32 = 14;
const _IOC_NRSHIFT: u32 = 0;
const _IOC_TYPESHIFT: u32 = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + _IOC_SIZEBITS;
const _IOC_WRITE: u32 = 1;

const fn _ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
	(dir << _IOC_DIRSHIFT)
		| (ty << _IOC_TYPESHIFT)
		| (nr << _IOC_NRSHIFT)
		| (size << _IOC_SIZESHIFT)
}

const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;
const SECCOMP_IOCTL_NOTIF_ADDFD: u32 = _ioc(
	_IOC_WRITE,
	SECCOMP_IOC_MAGIC,
	3,
	std::mem::size_of::<libc::seccomp_notif_addfd>() as u32,
);

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

/// Raw `ioctl(SECCOMP_IOCTL_NOTIF_ADDFD)` wrapper.  Returns the new fd
/// number installed in the target on success.
fn notif_addfd(notify_fd: ScmpFd, addfd: &libc::seccomp_notif_addfd) -> io::Result<libc::c_int> {
	let ret = unsafe {
		libc::ioctl(
			notify_fd,
			SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
			addfd as *const libc::seccomp_notif_addfd,
		)
	};
	if ret < 0 {
		Err(io::Error::last_os_error())
	} else {
		Ok(ret)
	}
}

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

	/// Get the `index+1`-th syscall argument as a raw `u64`.
	pub fn arg(&self, index: usize) -> u64 {
		self.sreq.data.args[index]
	}

	pub fn still_valid(&mut self) -> Result<bool, AccessRequestError> {
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

	pub(crate) fn send_response_impl(
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
		self.send_response_impl(ScmpNotifResp::new_continue(
			self.sreq.id,
			ScmpNotifRespFlags::empty(),
		))
	}

	/// Send an error value for the currently traced syscall (without
	/// actually executing it).
	///
	/// Users are reminded that this should not be used to deny access
	/// unless there is a separate sandboxing mechanism making sure that
	/// the access would be denied should the traced process attempt to
	/// modify any path buffers from another thread.
	pub fn send_error(&mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.send_response_impl(ScmpNotifResp::new_error(
			self.sreq.id,
			errno,
			ScmpNotifRespFlags::empty(),
		))
	}

	/// Send a non-error value for the currently traced syscall (without
	/// actually executing it).
	pub fn send_value(&mut self, val: i64) -> Result<(), AccessRequestError> {
		self.send_response_impl(ScmpNotifResp::new_val(
			self.sreq.id,
			val,
			ScmpNotifRespFlags::empty(),
		))
	}

	/// Returns the syscall number that triggered this notification.
	pub fn syscall(&self) -> libseccomp::ScmpSyscall {
		self.sreq.data.syscall
	}

	/// Install `srcfd` into the traced process and atomically complete the
	/// notification such that the newly installed fd is returned from the
	/// syscall.
	///
	/// On success the context is marked answered and the new descriptor number
	/// (as seen by the traced process, but may not be a valid fd for the
	/// caller) is returned.
	pub fn install_fd_and_respond(
		&mut self,
		srcfd: RawFd,
		cloexec: bool,
	) -> Result<i64, AccessRequestError> {
		if !self.valid {
			return Err(AccessRequestError::NotificationAlreadyAnswered);
		}
		let addfd = libc::seccomp_notif_addfd {
			id: self.sreq.id,
			flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
			srcfd: srcfd as u32,
			newfd: 0,
			newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
		};
		let newfd = notif_addfd(self.notify_fd, &addfd).map_err(AccessRequestError::AddFd)?;
		// SECCOMP_ADDFD_FLAG_SEND completes the notification for us.
		self.valid = false;
		Ok(newfd as i64)
	}

	/// Install `srcfd` into the traced process as `newfd`, replacing any
	/// existing fds in the traced process, but without sending any responses
	/// for this syscall.
	pub fn replace_fd(
		&mut self,
		srcfd: RawFd,
		newfd: RawFd,
		cloexec: bool,
	) -> Result<(), AccessRequestError> {
		if !self.valid {
			return Err(AccessRequestError::NotificationAlreadyAnswered);
		}
		let addfd = libc::seccomp_notif_addfd {
			id: self.sreq.id,
			flags: libc::SECCOMP_ADDFD_FLAG_SETFD as u32,
			srcfd: srcfd as u32,
			newfd: newfd as u32,
			newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
		};
		notif_addfd(self.notify_fd, &addfd).map_err(AccessRequestError::AddFd)?;
		Ok(())
	}

	/// Read a NUL-terminated C string from the traced process's memory at
	/// `src`.
	pub fn cstr_from_target_memory(
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

	/// Reads the `fd_arg_index+1`-th syscall argument and opens it as a
	/// `ForeignFd` via `/proc/{pid}/...`.  Does error checking and
	/// handles AT_FDCWD.
	pub fn arg_to_fd(&mut self, fd_arg_index: usize) -> Result<ForeignFd, AccessRequestError> {
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

	/// Reads exactly `buf.len()` bytes from the traced process's memory
	/// at `src` into `buf`.
	pub fn read_target_memory(
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

	/// Reads a value of type `T` from the traced process's memory at
	/// `src`.
	pub fn value_from_target_memory<T: Copy>(
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

	pub fn pid(&self) -> libc::pid_t {
		libc::pid_t::try_from(self.sreq.pid).expect("PID overflowed i32")
	}

	pub fn comm(&self) -> Result<OsString, AccessRequestError> {
		let pid = self.pid();
		let mut f = File::open(format!("/proc/{}/comm", pid))
			.map_err(|e| AccessRequestError::ReadPidComm(pid as u32, e))?;
		let mut buf = Vec::new();
		f.read_to_end(&mut buf)
			.map_err(|e| AccessRequestError::ReadPidComm(pid as u32, e))?;
		while let Some(b) = buf.last()
			&& b.is_ascii_whitespace()
		{
			buf.pop();
		}
		Ok(OsString::from_vec(buf))
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn addfd_ioctl_number_and_struct_layout() {
		// `struct seccomp_notif_addfd` is exactly 24 bytes on all LP64
		// targets (two u32s pack into the u64's tail).
		assert_eq!(std::mem::size_of::<libc::seccomp_notif_addfd>(), 24);
		// _IOW('!', 3, struct seccomp_notif_addfd) on asm-generic archs.
		assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, 0x4018_2103);
		assert_eq!(libc::SECCOMP_ADDFD_FLAG_SETFD, 1);
		assert_eq!(libc::SECCOMP_ADDFD_FLAG_SEND, 2);
	}
}
