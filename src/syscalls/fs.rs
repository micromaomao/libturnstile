use std::io;

use libseccomp::{ScmpFd, ScmpFilterContext, ScmpNotifData, ScmpNotifReq};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracer, TurnstileTracerError,
	syscalls::RequestContext,
};

#[derive(Debug)]
pub(crate) struct ForeignFd {
	local_fd: libc::c_int,
}

impl ForeignFd {
	pub(crate) fn from_path(path: &str) -> Result<Self, io::Error> {
		let local_fd = unsafe {
			libc::open(
				path.as_ptr() as *const libc::c_char,
				libc::O_PATH | libc::O_CLOEXEC,
				0,
			)
		};
		if local_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { local_fd })
	}

	pub(crate) fn from_proc_pid_fd(pid: libc::pid_t, fd: libc::c_int) -> Result<Self, io::Error> {
		let path = format!("/proc/{pid}/fd/{fd}");
		Self::from_path(&path)
	}

	pub(crate) fn from_proc_pid_cwd(pid: libc::pid_t) -> Result<Self, io::Error> {
		let path = format!("/proc/{pid}/cwd");
		Self::from_path(&path)
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
		let duped_fd = unsafe { libc::dup(self.local_fd) };
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
	/// None if path is absolute.
	pub(crate) dfd: Option<ForeignFd>,

	pub(crate) path: String,
}

impl FsTarget {
	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<libc::c_int, io::Error> {
		unimplemented!()
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	pub fn open_target_dir(&self) -> Result<(libc::c_int, &str), io::Error> {
		unimplemented!()
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<String, io::Error> {
		todo!("open_target_dir, then readlink that, then append final component")
	}
}

#[derive(Debug)]
pub struct OpenOperation {
	pub target: FsTarget,
	pub flags: libc::c_int,
}

impl OpenOperation {
	pub fn has_read(&self) -> bool {
		(self.flags & libc::O_RDONLY != 0 || self.flags & libc::O_RDWR != 0)
			&& self.flags & libc::O_WRONLY == 0
			&& self.flags & libc::O_PATH == 0
	}

	pub fn has_write(&self) -> bool {
		(self.flags & libc::O_WRONLY != 0 || self.flags & libc::O_RDWR != 0)
			&& self.flags & libc::O_RDONLY == 0
			&& self.flags & libc::O_PATH == 0
	}
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
	Symlink { target: String },
	Device { dev: libc::dev_t },
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

type SyscallHandler1 = fn(
	sdata: &ScmpNotifData,
	target: &FsTarget,
) -> Result<(Operation, Option<Operation>), io::Error>;

type SyscallHandler2 = fn(
	sdata: &ScmpNotifData,
	target1: &FsTarget,
	target2: &FsTarget,
) -> Result<(Operation, Option<Operation>), io::Error>;

type SyscallHandlerCustom =
	fn(sreq: &ScmpNotifReq, notify_fd: ScmpFd) -> Result<(Operation, Option<Operation>), io::Error>;

// (name, handler, arg index of the path)
const FS_SYSCALLS_PATH: &'static [(&'static str, SyscallHandler1, u8)] = &[
	("open", |sdata, target| unimplemented!(), 0),
	("access", |sdata, target| unimplemented!(), 0),
	("mkdir", |sdata, target| unimplemented!(), 0),
	("rmdir", |sdata, target| unimplemented!(), 0),
	("creat", |sdata, target| unimplemented!(), 0),
	("mknod", |sdata, target| unimplemented!(), 0),
	("unlink", |sdata, target| unimplemented!(), 0),
	("execve", |sdata, target| unimplemented!(), 0),
];
// (name, handler, arg index of the dfd, arg index of the path)
const FS_SYSCALLS_DFD_PATH: &'static [(&'static str, SyscallHandler1, u8, u8)] = &[
	("openat", |sdata, target| unimplemented!(), 0, 1),
	("openat2", |sdata, target| unimplemented!(), 0, 1),
	("faccessat", |sdata, target| unimplemented!(), 0, 1),
	("faccessat2", |sdata, target| unimplemented!(), 0, 1),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	("symlinkat", |sdata, target| unimplemented!(), 1, 2),
	("unlinkat", |sdata, target| unimplemented!(), 0, 1),
	("mkdirat", |sdata, target| unimplemented!(), 0, 1),
	("mknodat", |sdata, target| unimplemented!(), 0, 1),
	("execveat", |sdata, target| unimplemented!(), 0, 1),
];
// (name, handler, arg index of the first path, arg index of the second path)
const FS_SYSCALLS_PATH_PATH: &'static [(&'static str, SyscallHandler2, u8, u8)] = &[
	("symlink", |sdata, target1, target2| unimplemented!(), 0, 1),
	("rename", |sdata, target1, target2| unimplemented!(), 0, 1),
	("link", |sdata, target1, target2| unimplemented!(), 0, 1),
];
// (name, handler, arg index of the first dfd, arg index of the first path, arg index of the second dfd, arg index of the second path)
const FS_SYSCALLS_DFD_PATH_DFD_PATH: &'static [(&'static str, SyscallHandler2, u8, u8, u8, u8)] = &[
	(
		"renameat",
		|sdata, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
	(
		"renameat2",
		|sdata, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
	(
		"linkat",
		|sdata, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
];

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	unimplemented!()
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	unimplemented!()
}
