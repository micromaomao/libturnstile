use std::{
	ffi::{CStr, CString, OsStr, OsString},
	io,
	os::unix::{
		ffi::{OsStrExt, OsStringExt},
		io::AsRawFd,
	},
};

use crate::{AccessRequestError, syscalls::RequestContext};

use log::debug;

/// An O_PATH / O_CLOEXEC file descriptor opened in the tracer process that
/// refers to a path in the traced process's filesystem namespace.
///
/// The fd is closed automatically on drop.  Cloning uses `F_DUPFD_CLOEXEC`
/// so the duplicate always has the close-on-exec flag set.
#[derive(Debug)]
pub struct ForeignFd {
	local_fd: libc::c_int,
}

impl ForeignFd {
	pub(crate) fn from_path_with_flags<P: AsRef<CStr>>(
		path: P,
		oflags: libc::c_int,
	) -> Result<Self, io::Error> {
		let c_path = path.as_ref();
		let local_fd = unsafe { libc::open(c_path.as_ptr(), oflags, 0) };
		if local_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { local_fd })
	}

	pub(crate) fn from_path<P: AsRef<CStr>>(path: P) -> Result<Self, io::Error> {
		Self::from_path_with_flags(path, libc::O_PATH | libc::O_CLOEXEC)
	}

	/// Read the path of an open file descriptor via /proc/self/fd.
	pub fn readlink(&self) -> Result<OsString, io::Error> {
		// /proc/self/fd/{fd} is always valid ASCII, so a format! string with a
		// manual NUL terminator is safe to pass to readlink.
		let proc_path = format!("/proc/self/fd/{}\0", self.local_fd);
		let mut buf = vec![0u8; libc::PATH_MAX as usize];
		let ret = unsafe {
			libc::readlink(
				proc_path.as_ptr() as *const libc::c_char,
				buf.as_mut_ptr() as *mut libc::c_char,
				buf.len(),
			)
		};
		if ret < 0 {
			return Err(io::Error::last_os_error());
		}
		buf.truncate(ret as usize);
		// readlink does not include a NUL terminator
		if buf.len() > 1 && buf.last().copied() == Some(b'/') {
			buf.pop();
		}
		Ok(OsString::from_vec(buf))
	}
}

impl AsRawFd for ForeignFd {
	fn as_raw_fd(&self) -> libc::c_int {
		self.local_fd
	}
}

impl Drop for ForeignFd {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.local_fd);
		}
	}
}

impl Clone for ForeignFd {
	fn clone(&self) -> Self {
		let duped_fd = unsafe { libc::fcntl(self.local_fd, libc::F_DUPFD_CLOEXEC, 0) };
		if duped_fd < 0 {
			panic!("Failed to dup fd: {}", io::Error::last_os_error());
		}
		Self { local_fd: duped_fd }
	}
}

/// Most filesystem syscalls on Linux accept target paths in the form of a
/// "base" fd (which may implicitly be the current working directory), and
/// a path either relative to that fd, or absolute (in which case the base
/// fd is ignored).
///
/// Since the base fd is provided by the traced process, unless it
/// provides an invalid fd, it is always guaranteed to exist.  The path,
/// however, may either point to an non-existent entry in an existing
/// directory, or a completely non-existent place even ignoring the last
/// component.
///
/// Some syscalls also accepts an empty path, in which case the target is
/// the base fd itself.
///
/// This struct preserves what was passed by the traced process, except
/// that the base fd is opened by us from /proc, and so we have a local
/// reference to the base location that will still be valid even if the
/// traced process terminates.
#[derive(Debug, Clone)]
pub struct FsTarget {
	/// None iff path is absolute, in which case path must start with '/'.
	pub(crate) dfd: Option<ForeignFd>,

	pub(crate) path: CString,

	/// Whether to avoid following the final symlink component when resolving
	/// this target (corresponds to AT_SYMLINK_NOFOLLOW).
	pub(crate) no_follow: bool,
}

impl FsTarget {
	pub(crate) fn from_path(
		req: &mut RequestContext,
		path_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let pathb = path.as_bytes();
		let absolute = pathb.len() > 0 && pathb[0] == b'/';
		let mut ret = Self {
			dfd: None,
			path,
			no_follow: false,
		};
		if !absolute {
			let cwdstr = format!("/proc/{}/cwd\0", req.sreq.pid);
			ret.dfd = Some(
				ForeignFd::from_path(CStr::from_bytes_with_nul(cwdstr.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
			);
		}
		Ok(ret)
	}

	pub(crate) fn from_at_path(
		req: &mut RequestContext,
		dfd_arg_index: u8,
		path_arg_index: u8,
		at_flags: Option<u64>,
	) -> Result<Self, AccessRequestError> {
		let _at_empty_path = at_flags.map_or(false, |f| f & libc::AT_EMPTY_PATH as u64 != 0);
		let no_follow = at_flags.map_or(false, |f| f & libc::AT_SYMLINK_NOFOLLOW as u64 != 0);

		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let pathb = path.as_bytes();

		if pathb.len() > 0 && pathb[0] == b'/' {
			return Ok(Self {
				dfd: None,
				path,
				no_follow,
			});
		}

		// ??? what happens if AT_EMPTY_PATH is not set but path is empty

		Ok(Self {
			dfd: Some(req.arg_to_fd(dfd_arg_index as usize)?),
			path,
			no_follow,
		})
	}

	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<ForeignFd, io::Error> {
		let path_bytes = self.path.to_bytes();

		if path_bytes.is_empty() {
			let dfd = self
				.dfd
				.as_ref()
				.expect("Expected dfd to exist for non-absolute path");
			return Ok(dfd.clone());
		}

		let mut flags = libc::O_PATH | libc::O_CLOEXEC;
		if self.no_follow {
			flags |= libc::O_NOFOLLOW;
		}
		let fd = match &self.dfd {
			None => unsafe { libc::open(self.path.as_ptr(), flags, 0) },
			Some(dfd) => unsafe { libc::openat(dfd.as_raw_fd(), self.path.as_ptr(), flags, 0) },
		};
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(ForeignFd { local_fd: fd })
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	pub fn open_target_dir(&self) -> Result<(ForeignFd, &CStr), io::Error> {
		let path_bytes_nul = self.path.to_bytes_with_nul();

		if let Some(last_slash) = path_bytes_nul.iter().rposition(|&b| b == b'/')
			&& last_slash != 0
		{
			let dir_bytes = &path_bytes_nul[..last_slash];
			let file_bytes_nul = &path_bytes_nul[last_slash + 1..];
			let actual_parent_fd_raw = match &self.dfd {
				Some(dfd) => unsafe {
					// We have to allocate a new CString to have NUL at the end
					libc::openat(
						dfd.as_raw_fd(),
						CString::new(dir_bytes)
							.expect("self.path should not have NUL in the middle")
							.as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
						0,
					)
				},
				None => unsafe {
					// We have to allocate a new CString to have NUL at the end
					libc::open(
						CString::new(dir_bytes)
							.expect("self.path should not have NUL in the middle")
							.as_ptr(),
						libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
						0,
					)
				},
			};
			if actual_parent_fd_raw < 0 {
				return Err(io::Error::last_os_error());
			}
			let file_name = CStr::from_bytes_with_nul(file_bytes_nul).unwrap();
			Ok((
				ForeignFd {
					local_fd: actual_parent_fd_raw,
				},
				file_name,
			))
		} else {
			let file_name = match path_bytes_nul {
				// In the AT_EMPTY_PATH case, we can't recover the
				// filename, so just represent it as "." to the
				// caller.  Should it need the full path it can always
				// realpath().
				b"\0" => CStr::from_bytes_with_nul(b".\0").unwrap(),
				other if other.first().copied() == Some(b'/') => {
					// Absolute path with a single filename, remove leading /
					CStr::from_bytes_with_nul(&other[1..]).unwrap()
				}
				other => CStr::from_bytes_with_nul(other).unwrap(),
			};
			let actual_parent_fd = match &self.dfd {
				Some(dfd) => dfd.clone(),
				None => {
					// Absolute path, open root.
					ForeignFd::from_path(CStr::from_bytes_with_nul(b"/\0").unwrap())?
				}
			};
			Ok((actual_parent_fd, file_name))
		}
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<OsString, io::Error> {
		let path_bytes = self.path.to_bytes();

		// AT_EMPTY_PATH: the target is the dfd itself — read its proc symlink.
		if path_bytes.is_empty() {
			let dfd = self
				.dfd
				.as_ref()
				.expect("Expected dfd to exist for non-absolute path");
			return dfd.readlink();
		}

		let (dir_fd, file_name) = self.open_target_dir()?;
		let dir_path = dir_fd.readlink()?;
		let file_name_bytes = file_name.to_bytes();
		if file_name_bytes.is_empty() {
			return Ok(dir_path);
		}
		let mut result = dir_path.into_encoded_bytes();
		if result.last().copied() != Some(b'/') {
			result.push(b'/');
		}
		result.extend_from_slice(file_name_bytes);
		Ok(OsString::from_vec(result))
	}

	pub fn dfd(&self) -> Option<&ForeignFd> {
		self.dfd.as_ref()
	}

	pub fn path(&self) -> &CStr {
		&self.path
	}
}

impl std::fmt::Display for FsTarget {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let rp = self.realpath();
		match rp {
			Ok(rp) => {
				write!(f, "{:?}", rp)
			}
			Err(rp_err) => {
				debug!("realpath() on FsTarget failed: {}", rp_err);
				match &self.dfd {
					Some(dfd) => {
						let mut dfd_path_bytes = dfd
							.readlink()
							.unwrap_or_else(|e| {
								debug!("unable to readlink() on FsTarget's dfd: {}", e);
								OsString::from("???")
							})
							.into_encoded_bytes();
						if dfd_path_bytes.last().copied() != Some(b'/') {
							dfd_path_bytes.push(b'/');
						}
						dfd_path_bytes.extend_from_slice(self.path.to_bytes());
						write!(f, "{:?} (invalid)", OsString::from_vec(dfd_path_bytes))
					}
					None => {
						// self.path is absolute, so already have leading '/'
						write!(f, "{:?} (invalid)", OsStr::from_bytes(self.path.as_bytes()))
					}
				}
			}
		}
	}
}

#[derive(Debug)]
pub struct OpenOperation {
	pub target: FsTarget,
	pub need_read: bool,
	pub need_write: bool,
}

#[derive(Debug)]
pub struct CreateOperation {
	pub target: FsTarget,
	pub mode: libc::mode_t,
	pub kind: CreateKind,
}

#[derive(Debug)]
pub enum CreateKind {
	File,
	Directory,
	Symlink { target: CString },
	Device { dev: libc::dev_t },
}

impl CreateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			CreateKind::File => "file",
			CreateKind::Directory => "directory",
			CreateKind::Symlink { .. } => "symlink",
			CreateKind::Device { .. } => "device",
		}
	}
}

impl std::fmt::Display for CreateKind {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

#[derive(Debug)]
pub struct RenameOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub exchange: bool,
}

#[derive(Debug)]
pub struct UnlinkOperation {
	pub target: FsTarget,
	pub dir: bool,
}

#[derive(Debug)]
pub struct LinkOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub follow_src_symlink: bool,
}

#[derive(Debug)]
pub struct ExecOperation {
	pub target: FsTarget,
}
