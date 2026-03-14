pub mod fs;

/// Represents a traced syscall.
#[derive(Debug)]
pub struct AccessRequest {
	pub(crate) operation: Operation,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Operation {
	FsOperation(fs::FsOperation),
}

impl AccessRequest {
	pub fn operation(&self) -> &Operation {
		&self.operation
	}
}

impl std::fmt::Display for Operation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Operation::FsOperation(fs_op) => fs_op.fmt(f),
		}
	}
}
