#[cfg(feature = "serialize")]
use serde::Serialize;

pub mod fs;

/// Represents a traced syscall.
#[cfg_attr(feature = "serialize", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct AccessRequest {
	pub(crate) operation: Operation,
}

#[cfg_attr(feature = "serialize", derive(Serialize))]
#[derive(Debug, Clone)]
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
