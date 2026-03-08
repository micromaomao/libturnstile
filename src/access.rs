use crate::syscalls::fs;

/// Represents a traced syscall, which may itself involve multiple
/// operations executed atomically (e.g. an openat() with O_CREAT is
/// really a mknod + open from our perspective, since the file may or may
/// not exist yet).
#[derive(Debug)]
pub struct AccessRequest {
	pub(crate) operations: Vec<Operation>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Operation {
	FsOpen(fs::OpenOperation),
	FsCreate(fs::CreateOperation),
	FsRename(fs::RenameOperation),
	FsUnlink(fs::UnlinkOperation),
	FsLink(fs::LinkOperation),
	FsExec(fs::ExecOperation),
	UnixConnect(fs::FsTarget),
	UnixListen(fs::FsTarget),
	UnixSendto(fs::FsTarget),
	UnixRecvfrom(fs::FsTarget),
}

impl<'a> IntoIterator for &'a AccessRequest {
	type Item = &'a Operation;
	type IntoIter = std::slice::Iter<'a, Operation>;

	fn into_iter(self) -> Self::IntoIter {
		self.operations.iter()
	}
}
