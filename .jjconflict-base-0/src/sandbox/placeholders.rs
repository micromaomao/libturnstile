use std::{
	ffi::{CStr, CString},
	io, mem,
};

use crate::{BindMountSandboxError, sandbox::managed_bind_mount_sandbox::ManagedPlaceholder};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serialize")]
use crate::utils::{
	deserialize_cstring, deserialize_timespec, serialize_cstring, serialize_timespec,
};

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct CommonPlaceholderData {
	#[cfg_attr(
		feature = "serialize",
		serde(
			serialize_with = "serialize_timespec",
			deserialize_with = "deserialize_timespec"
		)
	)]
	pub atime: libc::timespec,
	#[cfg_attr(
		feature = "serialize",
		serde(
			serialize_with = "serialize_timespec",
			deserialize_with = "deserialize_timespec"
		)
	)]
	pub mtime: libc::timespec,
}

impl PartialEq for CommonPlaceholderData {
	fn eq(&self, other: &Self) -> bool {
		self.atime.tv_sec == other.atime.tv_sec
			&& self.atime.tv_nsec == other.atime.tv_nsec
			&& self.mtime.tv_sec == other.mtime.tv_sec
			&& self.mtime.tv_nsec == other.mtime.tv_nsec
	}
}

impl Eq for CommonPlaceholderData {}

impl CommonPlaceholderData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			atime: libc::timespec {
				tv_sec: stat.st_atime,
				tv_nsec: stat.st_atime_nsec as _,
			},
			mtime: libc::timespec {
				tv_sec: stat.st_mtime,
				tv_nsec: stat.st_mtime_nsec as _,
			},
		}
	}
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderDirData {
	#[cfg_attr(feature = "serialize", serde(flatten))]
	pub common: CommonPlaceholderData,
	pub mode: u32,
}

/// Create or update a single placeholder entry at (`dirfd`, `name`).
///
/// If nothing exists at the path, the entry is created with the
/// requested type.  If something exists with the wrong type (or, for
/// symlinks, a wrong target), it is removed (recursively for
/// directories) and recreated.
///
/// After the entry exists with the correct type, its mode is updated
/// via `fchmodat` (skipped for symlinks since Linux does not allow
/// changing symlink modes), and timestamps are updated via `utimensat`.
/// Set both `atime.tv_nsec` and `mtime.tv_nsec` to `UTIME_OMIT` to skip
/// the timestamp update entirely (useful when this function is used
/// just to ensure the entry exists with reasonable defaults).
///
/// Symlinks are never followed for any operation.
pub(super) fn create_or_update_placeholder(
	dirfd: libc::c_int,
	name: &CStr,
	placeholder_data: &ManagedPlaceholder,
) -> Result<(), BindMountSandboxError> {
	const MAX_ATTEMPTS: u32 = 2;

	let (common, expected_kind, mode_perms): (
		&CommonPlaceholderData,
		libc::mode_t,
		Option<libc::mode_t>,
	) = match placeholder_data {
		ManagedPlaceholder::Dir(d) => (
			&d.common,
			libc::S_IFDIR,
			Some((d.mode & 0o7777) as libc::mode_t),
		),
		ManagedPlaceholder::File(f) => (
			&f.common,
			libc::S_IFREG,
			Some((f.mode & 0o7777) as libc::mode_t),
		),
		ManagedPlaceholder::Symlink(s) => (&s.common, libc::S_IFLNK, None),
	};

	let mut attempts: u32 = 0;
	loop {
		attempts += 1;
		if attempts > MAX_ATTEMPTS {
			return Err(BindMountSandboxError::SandboxPlaceholderConflict(
				name.to_owned(),
			));
		}

		let create_res: libc::c_int;
		let create_err: io::Error;
		unsafe {
			let res = match placeholder_data {
				ManagedPlaceholder::Dir(_) => {
					libc::mkdirat(dirfd, name.as_ptr(), mode_perms.unwrap())
				}
				ManagedPlaceholder::File(_) => {
					let fd = libc::openat(
						dirfd,
						name.as_ptr(),
						libc::O_CREAT
							| libc::O_EXCL | libc::O_WRONLY
							| libc::O_NOFOLLOW | libc::O_CLOEXEC,
						mode_perms.unwrap() as libc::c_uint,
					);
					if fd < 0 {
						-1
					} else {
						libc::close(fd);
						0
					}
				}
				ManagedPlaceholder::Symlink(s) => {
					libc::symlinkat(s.target.as_ptr(), dirfd, name.as_ptr())
				}
			};
			create_res = res;
			create_err = if res != 0 {
				io::Error::last_os_error()
			} else {
				io::Error::from_raw_os_error(0)
			};
		}

		if create_res == 0 {
			break;
		}

		if create_err.kind() != io::ErrorKind::AlreadyExists {
			return Err(match placeholder_data {
				ManagedPlaceholder::Dir(_) => {
					BindMountSandboxError::Mkdir(name.to_owned(), create_err)
				}
				ManagedPlaceholder::File(_) => {
					BindMountSandboxError::Mkfile(name.to_owned(), create_err)
				}
				ManagedPlaceholder::Symlink(s) => {
					BindMountSandboxError::Symlinkat(name.to_owned(), s.target.clone(), create_err)
				}
			});
		}

		// EEXIST: stat the existing entry and decide what to do.
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		let stat_res =
			unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
		if stat_res != 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				// raced; just retry
				continue;
			}
			return Err(BindMountSandboxError::StatSandboxPath(err));
		}

		let existing_kind = stat.st_mode & libc::S_IFMT;
		if existing_kind != expected_kind {
			// wrong type: remove (recursively if dir) and retry.
			remove_entry_at(dirfd, name)?;
			continue;
		}

		// Right type.  For symlinks, also verify the target.
		if let ManagedPlaceholder::Symlink(s) = placeholder_data {
			let mut buf = vec![0u8; libc::PATH_MAX as usize];
			let n = unsafe {
				libc::readlinkat(dirfd, name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
			};
			if n < 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					continue;
				}
				return Err(BindMountSandboxError::Readlink(name.to_owned(), err));
			}
			let existing_target = &buf[..n as usize];
			if existing_target != s.target.to_bytes() {
				// Wrong target: must unlink (symlinkat is not atomic-replace)
				// before retrying.  ENOENT is fine (race).
				let res = unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) };
				if res != 0 {
					let err = io::Error::last_os_error();
					if err.kind() != io::ErrorKind::NotFound {
						return Err(BindMountSandboxError::RemoveSandboxPath(err));
					}
				}
				continue;
			}
		}

		break;
	}

	// Update mode.  Skipped for symlinks: Linux does not support changing
	// symlink modes (fchmodat with AT_SYMLINK_NOFOLLOW returns ENOTSUP)
	// and symlink permissions are meaningless on Linux anyway.
	if let Some(mode_perms) = mode_perms {
		let res = unsafe { libc::fchmodat(dirfd, name.as_ptr(), mode_perms, 0) };
		if res != 0 {
			return Err(BindMountSandboxError::Chmod(
				name.to_owned(),
				io::Error::last_os_error(),
			));
		}
	}

	// Update timestamps unless both are UTIME_OMIT (caller's signal to
	// leave timestamps untouched).
	if common.atime.tv_nsec != libc::UTIME_OMIT || common.mtime.tv_nsec != libc::UTIME_OMIT {
		let times = [common.atime, common.mtime];
		let res = unsafe {
			libc::utimensat(
				dirfd,
				name.as_ptr(),
				times.as_ptr(),
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};
		if res != 0 {
			return Err(BindMountSandboxError::Utimens(
				name.to_owned(),
				io::Error::last_os_error(),
			));
		}
	}

	Ok(())
}

/// Recursively remove a directory entry, ignoring ENOENT.  Used as the
/// underlying implementation of [`remove_entry_at`].
pub(super) fn remove_dir_recursive_at(
	parent_fd: libc::c_int,
	name: &CStr,
) -> Result<(), BindMountSandboxError> {
	unsafe {
		let mut openhow: libc::open_how = mem::zeroed();
		openhow.flags =
			(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
		openhow.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
		let dir_fd = libc::syscall(
			libc::SYS_openat2,
			parent_fd,
			name.as_ptr(),
			&openhow as *const _,
			std::mem::size_of::<libc::open_how>(),
		) as libc::c_int;
		if dir_fd < 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}
		// dup because fdopendir takes ownership
		let dir_fd_dup = libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0);
		if dir_fd_dup < 0 {
			libc::close(dir_fd);
			let err = io::Error::last_os_error();
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}

		let dir = libc::fdopendir(dir_fd);
		if dir.is_null() {
			libc::close(dir_fd);
			libc::close(dir_fd_dup);
			let err = io::Error::last_os_error();
			return Err(BindMountSandboxError::OpenSandboxDir(err));
		}
		// dir_fd is now owned by dir

		loop {
			*libc::__errno_location() = 0;
			let entry = libc::readdir(dir);
			if entry.is_null() {
				let errno = *libc::__errno_location();
				if errno != 0 {
					libc::closedir(dir);
					libc::close(dir_fd_dup);
					return Err(BindMountSandboxError::OpenSandboxDir(
						io::Error::from_raw_os_error(errno),
					));
				}
				break;
			}

			let entry_name = CStr::from_ptr((*entry).d_name.as_ptr());
			if entry_name == c"." || entry_name == c".." {
				continue;
			}

			let mut stat: libc::stat = std::mem::zeroed();
			if libc::fstatat(
				dir_fd_dup,
				entry_name.as_ptr(),
				&mut stat,
				libc::AT_SYMLINK_NOFOLLOW,
			) != 0
			{
				let err = io::Error::last_os_error();
				libc::closedir(dir);
				libc::close(dir_fd_dup);
				return Err(BindMountSandboxError::StatSandboxPath(err));
			}

			if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
				if let Err(e) = remove_dir_recursive_at(dir_fd_dup, entry_name) {
					libc::closedir(dir);
					libc::close(dir_fd_dup);
					return Err(e);
				}
			} else {
				let res = libc::unlinkat(dir_fd_dup, entry_name.as_ptr(), 0);
				if res != 0 {
					let err = io::Error::last_os_error();
					if err.kind() != io::ErrorKind::NotFound {
						libc::closedir(dir);
						libc::close(dir_fd_dup);
						return Err(BindMountSandboxError::RemoveSandboxPath(err));
					}
				}
			}
		}

		libc::closedir(dir);
		libc::close(dir_fd_dup);

		let res = libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR);
		if res != 0 {
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::RemoveSandboxPath(err));
		}
	}
	Ok(())
}

/// Remove an entry at (`parent_fd`, `name`) regardless of its type.
/// Directories are removed recursively.  Returns `Ok(())` if the entry
/// (or any intermediate child) is already gone.  Symlinks are never
/// followed.
pub(super) fn remove_entry_at(
	parent_fd: libc::c_int,
	name: &CStr,
) -> Result<(), BindMountSandboxError> {
	unsafe {
		let mut stat: libc::stat = mem::zeroed();
		if libc::fstatat(
			parent_fd,
			name.as_ptr(),
			&mut stat,
			libc::AT_SYMLINK_NOFOLLOW,
		) != 0
		{
			let err = io::Error::last_os_error();
			if err.kind() == io::ErrorKind::NotFound {
				return Ok(());
			}
			return Err(BindMountSandboxError::StatSandboxPath(err));
		}
		if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
			remove_dir_recursive_at(parent_fd, name)
		} else {
			let res = libc::unlinkat(parent_fd, name.as_ptr(), 0);
			if res != 0 {
				let err = io::Error::last_os_error();
				if err.kind() == io::ErrorKind::NotFound {
					return Ok(());
				}
				return Err(BindMountSandboxError::RemoveSandboxPath(err));
			}
			Ok(())
		}
	}
}

/// Stat a host path from the caller's mount namespace.  Symlinks are
/// not followed.
pub(super) fn stat_host(host_path: &CStr) -> Result<libc::stat, BindMountSandboxError> {
	let mut stat: libc::stat = unsafe { std::mem::zeroed() };
	let res = unsafe {
		libc::fstatat(
			libc::AT_FDCWD,
			host_path.as_ptr(),
			&mut stat,
			libc::AT_SYMLINK_NOFOLLOW,
		)
	};
	if res != 0 {
		return Err(BindMountSandboxError::StatHostPath(
			host_path.to_owned(),
			io::Error::last_os_error(),
		));
	}
	Ok(stat)
}

/// Compute the host path that a covering mount would expose at a
/// descendant sandbox path.  Given a covering mount at sandbox path
/// `par_sb` bound to host `par_host`, the descendant `path` (which must
/// be `par_sb` plus a `/`-separated suffix) is exposed at
/// `par_host` + that same suffix.  The result is normalised (no trailing
/// or doubled slashes), e.g. `("/etc", "/", "/home/x") -> "/etc/home/x"`,
/// `("/", "/home", "/home/x") -> "/x"`.
pub(super) fn join_host_suffix(par_host: &[u8], par_sb: &[u8], path: &[u8]) -> Vec<u8> {
	let suffix = &path[par_sb.len().min(path.len())..];
	let mut out: Vec<u8> = par_host.to_vec();
	while out.len() > 1 && out.last() == Some(&b'/') {
		out.pop();
	}
	if out == b"/" {
		out.clear();
	}
	for comp in suffix.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
		out.push(b'/');
		out.extend_from_slice(comp);
	}
	if out.is_empty() {
		out.push(b'/');
	}
	out
}

/// Convenience for callers that just need to ensure an entry exists
/// with sensible default mode and without touching timestamps.
pub(super) fn placeholder_default_no_metadata(kind_is_dir: bool) -> ManagedPlaceholder {
	let common = CommonPlaceholderData {
		atime: libc::timespec {
			tv_sec: 0,
			tv_nsec: libc::UTIME_OMIT,
		},
		mtime: libc::timespec {
			tv_sec: 0,
			tv_nsec: libc::UTIME_OMIT,
		},
	};
	if kind_is_dir {
		ManagedPlaceholder::Dir(PlaceholderDirData {
			common,
			mode: 0o755,
		})
	} else {
		ManagedPlaceholder::File(PlaceholderFileData {
			common,
			mode: 0o644,
			len: 0,
		})
	}
}

pub(super) fn placeholder_default_symlink(target: CString) -> ManagedPlaceholder {
	ManagedPlaceholder::Symlink(PlaceholderSymlinkData {
		common: CommonPlaceholderData {
			atime: libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_OMIT,
			},
			mtime: libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_OMIT,
			},
		},
		target,
	})
}

impl PlaceholderDirData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			mode: stat.st_mode,
		}
	}
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderFileData {
	#[cfg_attr(feature = "serialize", serde(flatten))]
	pub common: CommonPlaceholderData,
	pub mode: u32,
	pub len: u64,
}

impl PlaceholderFileData {
	pub fn from_stat(stat: &libc::stat) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			mode: stat.st_mode,
			len: stat.st_size as u64,
		}
	}
}

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderSymlinkData {
	#[cfg_attr(feature = "serialize", serde(flatten))]
	pub common: CommonPlaceholderData,
	#[cfg_attr(
		feature = "serialize",
		serde(
			serialize_with = "serialize_cstring",
			deserialize_with = "deserialize_cstring"
		)
	)]
	pub target: CString,
}

impl PlaceholderSymlinkData {
	pub fn from_stat(stat: &libc::stat, target: CString) -> Self {
		Self {
			common: CommonPlaceholderData::from_stat(stat),
			target,
		}
	}
}
