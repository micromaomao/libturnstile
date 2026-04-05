use std::{ffi::CStr, io, os::fd::AsRawFd};

use super::{ENABLE_LOG_IN_FORK, MountAttributes};
use crate::access::fs::ForeignFd;
use log::error;

#[derive(Debug)]
pub(crate) struct MountObj(pub ForeignFd);

impl MountObj {
	pub fn new_tmpfs() -> io::Result<Self> {
		unsafe {
			// libc::FSOPEN_CLOEXEC does not exist yet
			let fs = libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 0) as libc::c_int;
			if fs < 0 {
				let err = perror!("fsopen(tmpfs)");
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_SET_STRING */ 1,
				c"source".as_ptr(),
				c"tmpfs".as_ptr(),
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(source=tmpfs)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_SET_STRING */ 1,
				c"size".as_ptr(),
				c"16M".as_ptr(),
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(size=16M)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			let ret = libc::syscall(
				libc::SYS_fsconfig,
				fs,
				/* FSCONFIG_CMD_CREATE */ 6,
				0,
				0,
				0,
			);
			if ret != 0 {
				let err = perror!("fsconfig(CMD_CREATE)");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			// libc::FSMOUNT_CLOEXEC does not exist yet
			let mnt = libc::syscall(libc::SYS_fsmount, fs, 0, 0) as libc::c_int;
			if mnt < 0 {
				let err = perror!("fsmount");
				libc::close(fs);
				return Err(io::Error::from_raw_os_error(err));
			}
			libc::close(fs);
			Ok(Self(ForeignFd { local_fd: mnt }))
		}
	}

	pub unsafe fn new_from_fd(fd: libc::c_int) -> Self {
		Self(ForeignFd { local_fd: fd })
	}

	pub fn new_bind(
		source_dfd: libc::c_int,
		source_path: &CStr,
		attrs: MountAttributes,
		follow_source_symlinks: bool,
	) -> io::Result<Self> {
		let mut flags =
			libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_RECURSIVE as libc::c_uint;
		if source_path.is_empty() {
			flags |= libc::AT_EMPTY_PATH as libc::c_uint;
		}
		if !follow_source_symlinks {
			flags |= libc::AT_SYMLINK_NOFOLLOW as libc::c_uint;
		}
		unsafe {
			let mnt = libc::syscall(libc::SYS_open_tree, source_dfd, source_path.as_ptr(), flags)
				as libc::c_int;
			if mnt < 0 {
				let err = perror!("open_tree");
				return Err(io::Error::from_raw_os_error(err));
			}
			let mnt = Self(ForeignFd { local_fd: mnt });
			mnt.setattr(attrs, MountAttributes::default())?;
			Ok(mnt)
		}
	}

	pub fn setattr(
		&self,
		attrs: MountAttributes,
		existing_attr: MountAttributes,
	) -> io::Result<()> {
		unsafe {
			let mut mount_attr = std::mem::zeroed::<libc::mount_attr>();
			if attrs.readonly && !existing_attr.readonly {
				mount_attr.attr_set |= libc::MOUNT_ATTR_RDONLY;
			} else if !attrs.readonly && existing_attr.readonly {
				mount_attr.attr_clr |= libc::MOUNT_ATTR_RDONLY;
			}
			if attrs.noexec && !existing_attr.noexec {
				mount_attr.attr_set |= libc::MOUNT_ATTR_NOEXEC;
			} else if !attrs.noexec && existing_attr.noexec {
				mount_attr.attr_clr |= libc::MOUNT_ATTR_NOEXEC;
			}
			let res = libc::syscall(
				libc::SYS_mount_setattr,
				self.0.as_raw_fd(),
				c"".as_ptr(),
				libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
				&mount_attr as *const _,
				std::mem::size_of::<libc::mount_attr>(),
			);
			if res != 0 {
				let err = perror!("mount_setattr");
				return Err(io::Error::from_raw_os_error(err));
			}
			Ok(())
		}
	}

	pub fn mount(
		&self,
		dest_dfd: libc::c_int,
		dest_path: &CStr,
		follow_dest_symlink: bool,
	) -> io::Result<()> {
		let mut flags = libc::MOVE_MOUNT_F_EMPTY_PATH;
		if follow_dest_symlink {
			flags |= libc::MOVE_MOUNT_T_SYMLINKS;
		}
		if dest_path.is_empty() {
			flags |= libc::MOVE_MOUNT_T_EMPTY_PATH;
		}
		unsafe {
			let res = libc::syscall(
				libc::SYS_move_mount,
				self.0.as_raw_fd(),
				c"".as_ptr(),
				dest_dfd,
				dest_path.as_ptr(),
				flags,
			);
			if res != 0 {
				let err = perror!("move_mount");
				return Err(io::Error::from_raw_os_error(err));
			}
		}
		Ok(())
	}
}
