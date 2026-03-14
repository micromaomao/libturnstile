pub mod fs;

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
	FsOperation(fs::FsOperation),
}

impl<'a> IntoIterator for &'a AccessRequest {
	type Item = &'a Operation;
	type IntoIter = std::slice::Iter<'a, Operation>;

	fn into_iter(self) -> Self::IntoIter {
		self.operations.iter()
	}
}

impl std::fmt::Display for Operation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Operation::FsOperation(fs_op) => fs_op.fmt(f),
		}
	}
}
