pub use crate::syscalls::fs;

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

impl std::fmt::Display for Operation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Operation::FsOpen(fs::OpenOperation {
				target,
				need_read,
				need_write,
			}) => {
				write!(f, "open ")?;
				if *need_read {
					write!(f, "r")?;
				}
				if *need_write {
					write!(f, "w")?;
				}
				if !*need_read && !*need_write {
					write!(f, "path")?;
				}
				write!(f, " {}", target)?;
			}
			Operation::FsCreate(fs::CreateOperation { kind, target, .. }) => {
				write!(f, "create {} {}", kind, target)?;
			}
			Operation::FsRename(fs::RenameOperation { from, to, exchange }) => {
				write!(
					f,
					"rename {} {} {}",
					from,
					if *exchange { "<->" } else { "->" },
					to
				)?;
			}
			Operation::FsUnlink(fs::UnlinkOperation { target, dir }) => {
				let ty = match dir {
					true => "rmdir",
					false => "unlink",
				};
				write!(f, "{} {}", ty, target)?;
			}
			Operation::FsLink(fs::LinkOperation { from, to, .. }) => {
				write!(f, "link {} -> {}", from, to)?;
			}
			Operation::FsExec(fs::ExecOperation { target, .. }) => {
				write!(f, "exec {}", target)?;
			}
			Operation::UnixConnect(target) => {
				write!(f, "connect unix:{}", target)?;
			}
			Operation::UnixListen(target) => {
				write!(f, "listen unix:{}", target)?;
			}
			Operation::UnixSendto(target) => {
				write!(f, "sendto unix:{}", target)?;
			}
			Operation::UnixRecvfrom(target) => {
				write!(f, "recvfrom unix:{}", target)?;
			}
		}
		Ok(())
	}
}
