use std::{
	borrow::Cow,
	ffi::{CStr, CString, OsStr, OsString},
	io,
	os::{
		fd::IntoRawFd,
		unix::{
			ffi::{OsStrExt, OsStringExt},
			io::AsRawFd,
		},
	},
};

use crate::{AccessRequestError, syscalls::RequestContext};

use smallvec::{SmallVec, smallvec};

use log::{debug, error};

/// An O_PATH / O_CLOEXEC file descriptor opened in the tracer process that
/// refers to a path in the traced process's filesystem namespace.
///
/// The fd is closed automatically on drop.  Cloning uses `F_DUPFD_CLOEXEC`
/// so the duplicate always has the close-on-exec flag set.
#[derive(Debug)]
pub struct ForeignFd {
	pub(crate) local_fd: libc::c_int,
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

impl IntoRawFd for ForeignFd {
	fn into_raw_fd(self) -> libc::c_int {
		let fd = self.local_fd;
		std::mem::forget(self);
		fd
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
/// traced process terminates.  For absolute paths, we open the root of
/// the process as the dfd, and remove the leading '/' from the path.
#[derive(Debug, Clone)]
pub struct FsTarget {
	/// The base fd of the target, which may be the root of the process
	/// being traced if the path is absolute.
	pub(crate) dfd: ForeignFd,

	/// The path as originally passed by the traced process, except with
	/// leading '/'s removed.
	pub(crate) path: CString,

	/// Whether to avoid following the final symlink component when resolving
	/// this target (corresponds to AT_SYMLINK_NOFOLLOW).
	pub(crate) no_follow: bool,
}

fn trim_leading_slashes(path: &CStr) -> &CStr {
	let bytes = path.to_bytes_with_nul();
	let mut start = 0;
	while start < bytes.len() && bytes[start] == b'/' {
		start += 1;
	}
	CStr::from_bytes_with_nul(&bytes[start..]).unwrap()
}

impl FsTarget {
	pub(crate) fn from_path(
		req: &mut RequestContext,
		path_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path;
		if path_ptr.is_null() {
			path = CString::default();
		} else {
			path = req.cstr_from_target_memory(path_ptr)?;
		}
		Self::from_path_str(req, path)
	}

	pub(crate) fn from_path_str<P: AsRef<CStr>>(
		req: &mut RequestContext,
		path: P,
	) -> Result<Self, AccessRequestError> {
		let absolute = {
			let pathb = path.as_ref().to_bytes();
			pathb.len() > 0 && pathb[0] == b'/'
		};
		let path = if absolute {
			trim_leading_slashes(path.as_ref())
		} else {
			path.as_ref()
		};
		let dfd_path = match absolute {
			true => format!("/proc/{}/root\0", req.sreq.pid),
			false => format!("/proc/{}/cwd\0", req.sreq.pid),
		};
		let dfd = ForeignFd::from_path(CStr::from_bytes_with_nul(dfd_path.as_bytes()).unwrap())
			.map_err(|e| AccessRequestError::OpenFd(dfd_path, e))?;
		Ok(Self {
			dfd,
			path: path.to_owned(),
			no_follow: false,
		})
	}

	pub(crate) fn from_at_path(
		req: &mut RequestContext,
		dfd_arg_index: u8,
		path_arg_index: u8,
		at_flags: Option<u64>,
	) -> Result<Self, AccessRequestError> {
		let at_empty_path = at_flags.map_or(false, |f| f & libc::AT_EMPTY_PATH as u64 != 0);
		let no_follow = at_flags.map_or(false, |f| f & libc::AT_SYMLINK_NOFOLLOW as u64 != 0);

		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path;
		if path_ptr.is_null() {
			path = CString::default();
		} else {
			path = req.cstr_from_target_memory(path_ptr)?;
		}
		let pathb = path.as_bytes();

		if pathb.len() > 0 && pathb[0] == b'/' {
			let root_path = format!("/proc/{}/root\0", req.sreq.pid);
			return Ok(Self {
				dfd: ForeignFd::from_path(CStr::from_bytes_with_nul(root_path.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(root_path, e))?,
				path: trim_leading_slashes(&path).to_owned(),
				no_follow,
			});
		}

		if pathb.len() == 0 && !at_empty_path {
			return Err(AccessRequestError::InvalidSyscallData(
				"empty path without AT_EMPTY_PATH",
			));
		}

		Ok(Self {
			dfd: req.arg_to_fd(dfd_arg_index as usize)?,
			path,
			no_follow,
		})
	}

	pub(crate) fn from_fd(
		req: &mut RequestContext,
		fd_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let fd = req.arg_to_fd(fd_arg_index as usize)?;
		Ok(Self {
			dfd: fd,
			path: CString::from(c""),
			no_follow: false,
		})
	}

	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<ForeignFd, io::Error> {
		if self.path.is_empty() || self.path.as_bytes() == b"." || self.path.as_bytes() == b"./" {
			return Ok(self.dfd.clone());
		}

		let mut flags = libc::O_PATH | libc::O_CLOEXEC;
		if self.no_follow {
			flags |= libc::O_NOFOLLOW;
		}

		// We should have gotten rid of any absolute paths.
		debug_assert!(self.path.as_bytes().first().copied() != Some(b'/'));

		let fd = unsafe { libc::openat(self.dfd.as_raw_fd(), self.path.as_ptr(), flags, 0) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(ForeignFd { local_fd: fd })
	}

	fn open_target_dfd_in_root(&self, root: libc::c_int) -> Result<ForeignFd, io::Error> {
		let mut dfd_path = self.dfd.readlink()?.into_encoded_bytes();
		dfd_path.push(b'\0');
		if dfd_path.first().copied() != Some(b'/') {
			error!(
				"readlink of dfd did not return an absolute path: {:?} returned",
				OsStr::from_bytes(&dfd_path)
			);
			return Err(io::Error::from_raw_os_error(libc::ENOENT));
		}
		let dfd_path = CString::from_vec_with_nul(dfd_path).unwrap();
		let dfd_in_new_root = unsafe {
			let mut openhow: libc::open_how = std::mem::zeroed();
			openhow.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
			openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_IN_ROOT;
			libc::syscall(
				libc::SYS_openat2,
				root,
				dfd_path.as_ptr(),
				&openhow,
				std::mem::size_of_val(&openhow),
			)
		} as libc::c_int;
		if dfd_in_new_root < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(ForeignFd {
			local_fd: dfd_in_new_root,
		})
	}

	pub fn in_root(&self, root: libc::c_int) -> Result<Self, io::Error> {
		Ok(Self {
			dfd: self.open_target_dfd_in_root(root)?,
			path: self.path.clone(),
			no_follow: self.no_follow,
		})
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	///
	/// This function tries to be the equivalent of filename_parentat /
	/// path_parentat in fs/namei.c, except with simplified last component
	/// cases.  If the path ends with a ".", the returned "parent" will be
	/// the part without the ".", and the returned "file name" will be "."
	/// A path ending with a "/" or an empty path will be treated as if it
	/// ended with "/.".  If the path ends with "/..", the parent of the
	/// dfd will be returned, and the file name will be ".".
	pub fn open_target_dir(&self) -> Result<(ForeignFd, &CStr), io::Error> {
		let p = self.path.to_bytes();
		let p_with_nul = self.path.to_bytes_with_nul();
		let mut dotdot = false;
		let mut dot = false;
		let dir_path: Cow<'_, CStr>;
		let filename: &CStr;
		let mut can_skip_open = false;
		let opened_dfd;

		if p.is_empty() {
			dot = true;
		} else if p.ends_with(b"/") {
			dot = true;
		} else if p.ends_with(b"/.") {
			dot = true;
		} else if p.ends_with(b"/..") {
			dotdot = true;
		}

		if dot || dotdot {
			dir_path = Cow::Borrowed(self.path.as_c_str());
			filename = c".";
			if p == b"." || p == b"" {
				can_skip_open = true;
			}
		} else if let Some(last_slash) = p_with_nul.iter().rposition(|&b| b == b'/') {
			// We have to allocate a new CString to have NUL at the end
			dir_path = Cow::Owned(CString::new(&p_with_nul[..last_slash + 1]).unwrap());
			filename = CStr::from_bytes_with_nul(&p_with_nul[last_slash + 1..]).unwrap();
		} else {
			dir_path = Cow::Borrowed(c"./");
			filename = CStr::from_bytes_with_nul(p_with_nul).unwrap();
			can_skip_open = true;
		}

		if can_skip_open {
			opened_dfd = self.dfd.clone();
		} else {
			// We should have gotten rid of any absolute paths
			debug_assert!(dir_path.to_bytes().first().copied() != Some(b'/'));
			let parent_fd = unsafe {
				libc::openat(
					self.dfd.as_raw_fd(),
					dir_path.as_ptr(),
					libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
					0,
				)
			};
			if parent_fd < 0 {
				return Err(io::Error::last_os_error());
			}
			opened_dfd = ForeignFd {
				local_fd: parent_fd,
			};
		}

		Ok((opened_dfd, filename))
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<OsString, io::Error> {
		let path_bytes = self.path.to_bytes();

		// AT_EMPTY_PATH: the target is the dfd itself — read its proc symlink.
		if path_bytes.is_empty() {
			return self.dfd.readlink();
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

	pub fn dfd(&self) -> &ForeignFd {
		&self.dfd
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
				let mut dfd_path_bytes = self
					.dfd
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
		}
	}
}

#[derive(Debug)]
pub struct AccessOperation {
	pub target: FsTarget,
	pub need_read: bool,
	pub need_write: bool,
	pub need_exec: bool,
}

#[derive(Debug)]
pub struct OpenOperation {
	pub target: FsTarget,
	pub need_read: bool,
	pub need_write: bool,
	pub create_mode: Option<libc::mode_t>,
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

#[derive(Debug)]
pub struct StatOperation {
	pub target: FsTarget,
	pub lstat: bool,
}

#[derive(Debug)]
pub struct UnixBindOperation {
	pub target: FsTarget,
}

#[derive(Debug)]
pub enum FsOperation {
	FsOpen(OpenOperation),
	FsAccess(AccessOperation),
	FsCreate(CreateOperation),
	FsRename(RenameOperation),
	FsUnlink(UnlinkOperation),
	FsLink(LinkOperation),
	FsExec(ExecOperation),
	FsReadlink(FsTarget),
	FsChdir(FsTarget),
	FsStat(StatOperation),
	UnixConnect(FsTarget),
	UnixBind(UnixBindOperation),
	UnixSendto(FsTarget),
}

#[derive(Debug)]
pub struct RwxPermission {
	/// Target path.
	///
	/// For directory operations (create / delete / rename etc), this
	/// points to the source or destination being operated on, which may
	/// or may not exist yet.  In this case,
	/// [`is_dir_op`](Self::is_dir_op) is true.
	pub target: FsTarget,
	/// The operation refers to a target within a directory, and the
	/// permission is in fact required on the directory (i.e. parent of
	/// [`target`](Self::target)).
	pub is_dir_op: bool,
	/// Need read access on either a file, device, symlink (for readlink),
	/// directory, to connect to a Unix socket (for which write is also
	/// required), or to create a link from this file.
	pub read: bool,
	/// Need write access for file or devices, ability to create or delete
	/// the pointed to directory entry, connect to a Unix socket (for
	/// which read is also required), or to link something else into the
	/// pointed to entry.
	pub write: bool,
	/// Need execute access for files (not directories, as search
	/// permission is always implied).
	pub exec: bool,
	/// Need the ability to stat the target path (but not necessarily read
	/// it)
	pub metadata_read: bool,
}

macro_rules! make_rwx {
	($target:expr,$($field:ident),*) => {{
		let mut perm = RwxPermission {
			target: $target,
			is_dir_op: false,
			read: false,
			write: false,
			exec: false,
			metadata_read: false,
		};
		// Get rid of unused mut warning
		perm.read = false;
		$(
			perm.$field = true;
		)*
		perm
	}};
}

fn write_rwx(
	f: &mut std::fmt::Formatter<'_>,
	need_read: bool,
	need_write: bool,
	need_exec: bool,
) -> std::fmt::Result {
	if need_read {
		write!(f, "r")?;
	}
	if need_write {
		write!(f, "w")?;
	}
	if need_exec {
		write!(f, "x")?;
	}
	if !need_read && !need_write && !need_exec {
		write!(f, "_")?;
	}
	Ok(())
}

impl std::fmt::Display for FsOperation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::FsOpen(OpenOperation {
				target,
				need_read,
				need_write,
				create_mode,
			}) => {
				write!(f, "open ")?;
				write_rwx(f, *need_read, *need_write, false)?;
				if create_mode.is_some() {
					write!(f, "+")?;
				}
				write!(f, " {}", target)?;
			}
			Self::FsAccess(AccessOperation {
				target,
				need_read,
				need_write,
				need_exec,
			}) => {
				write!(f, "access ")?;
				write_rwx(f, *need_read, *need_write, *need_exec)?;
				write!(f, " {}", target)?;
			}
			Self::FsCreate(CreateOperation { kind, target, .. }) => {
				write!(f, "create {} {}", kind, target)?;
			}
			Self::FsRename(RenameOperation { from, to, exchange }) => {
				write!(
					f,
					"rename {} {} {}",
					from,
					if *exchange { "<->" } else { "->" },
					to
				)?;
			}
			Self::FsUnlink(UnlinkOperation { target, dir }) => {
				let ty = match dir {
					true => "rmdir",
					false => "unlink",
				};
				write!(f, "{} {}", ty, target)?;
			}
			Self::FsLink(LinkOperation { from, to, .. }) => {
				write!(f, "link {} -> {}", from, to)?;
			}
			Self::FsExec(ExecOperation { target, .. }) => {
				write!(f, "exec {}", target)?;
			}
			Self::FsReadlink(target) => {
				write!(f, "readlink {}", target)?;
			}
			Self::FsChdir(target) => {
				write!(f, "chdir {}", target)?;
			}
			Self::FsStat(StatOperation { target, lstat }) => {
				write!(f, "{} {}", if *lstat { "lstat" } else { "stat" }, target)?;
			}
			Self::UnixConnect(target) => {
				write!(f, "connect unix:{}", target)?;
			}
			Self::UnixBind(UnixBindOperation { target }) => {
				write!(f, "bind unix:{}", target)?;
			}
			Self::UnixSendto(target) => {
				write!(f, "sendto unix:{}", target)?;
			}
		}
		Ok(())
	}
}

impl FsOperation {
	/// Simplify the operation into a list (up to two entries) of
	/// effective r/w/x permissions needed.
	pub fn as_rwx_permissions(&self) -> SmallVec<[RwxPermission; 2]> {
		match self {
			Self::FsOpen(OpenOperation {
				target,
				need_read,
				need_write,
				create_mode,
			}) => {
				let mut p = make_rwx!(target.clone(),);
				if *need_read {
					p.read = true;
				}
				if *need_write || create_mode.is_some() {
					p.write = true;
				}
				if create_mode.is_some() {
					p.is_dir_op = true;
				}
				smallvec![p]
			}
			Self::FsAccess(AccessOperation {
				target,
				need_read,
				need_write,
				need_exec,
			}) => {
				let mut p = make_rwx!(target.clone(),);
				if *need_read {
					p.read = true;
				}
				if *need_write {
					p.write = true;
				}
				if *need_exec {
					p.exec = true;
				}
				smallvec![p]
			}
			Self::FsCreate(CreateOperation { target, .. }) => {
				smallvec![make_rwx!(target.clone(), write, is_dir_op)]
			}
			Self::FsRename(RenameOperation { from, to, .. }) => {
				smallvec![
					make_rwx!(from.clone(), write, is_dir_op),
					make_rwx!(to.clone(), write, is_dir_op),
				]
			}
			Self::FsUnlink(UnlinkOperation { target, .. }) => {
				smallvec![make_rwx!(target.clone(), write, is_dir_op)]
			}
			Self::FsLink(LinkOperation { from, to, .. }) => {
				smallvec![
					make_rwx!(from.clone(), read),
					make_rwx!(to.clone(), write, is_dir_op),
				]
			}
			Self::FsExec(ExecOperation { target, .. }) => {
				smallvec![make_rwx!(target.clone(), exec)]
			}
			Self::FsReadlink(target) => {
				smallvec![make_rwx!(target.clone(), read)]
			}
			Self::FsChdir(target) => {
				smallvec![make_rwx!(target.clone(),)]
			}
			Self::FsStat(StatOperation { target, .. }) => {
				smallvec![make_rwx!(target.clone(), metadata_read)]
			}
			Self::UnixConnect(target) => {
				smallvec![make_rwx!(target.clone(), read, write)]
			}
			Self::UnixBind(UnixBindOperation { target }) => {
				smallvec![make_rwx!(target.clone(), read, write)]
			}
			Self::UnixSendto(target) => {
				smallvec![make_rwx!(target.clone(), read, write)]
			}
		}
	}
}

impl std::fmt::Display for RwxPermission {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write_rwx(f, self.read, self.write, self.exec)?;
		write!(f, " {}", self.target)?;
		if self.is_dir_op {
			write!(f, "/..")?;
		}
		Ok(())
	}
}
