use thiserror::Error;

#[derive(Error, Debug)]
pub enum TurnstileTracerError {
	#[error("seccomp_init : {0}")]
	Init(libseccomp::error::SeccompError),
	#[error("seccomp_arch_add : {0}")]
	AddArch(libseccomp::error::SeccompError),
	#[error("seccomp_load : {0}")]
	Load(libseccomp::error::SeccompError),
	#[error("seccomp_notify_fd : {0}")]
	NotifyFd(libseccomp::error::SeccompError),
	#[error("socketpair: {0}")]
	Socketpair(std::io::Error),
	#[error("failed to spawn child process: {0}")]
	Spawn(std::io::Error),
	#[error("failed to transfer notify fd from child process: {0}")]
	TransferNotifyFd(std::io::Error),
	#[error("failed to resolve syscall {0}: {1}")]
	ResolveSyscall(&'static str, libseccomp::error::SeccompError),
	#[error("failed to add filter rule for syscall {0}: {1}")]
	AddRule(libseccomp::ScmpSyscall, libseccomp::error::SeccompError),
}

#[derive(Error, Debug)]
pub enum AccessRequestError {
	#[error("seccomp_notify_receive: {0}")]
	NotifyReceive(libseccomp::error::SeccompError),
	#[error("seccomp_notify_respond: {0}")]
	NotifyRespond(libseccomp::error::SeccompError),
	#[error("failed to send continue response: {0}")]
	SendContinue(libseccomp::error::SeccompError),
	#[error("failed to send error response: {0}")]
	SendError(libseccomp::error::SeccompError),
	#[error("failed to check seccomp_notify_id_valid(): {0}")]
	NotifyIdValid(libseccomp::error::SeccompError),
	#[error("Open /proc/{0}/mem failed: {1}")]
	ReadProcessMemory(u32, std::io::Error),
	#[error("Traced process issued invalid syscall: {0}")]
	InvalidSyscallData(&'static str),
	#[error("Failed to open {0}: {1}")]
	OpenFd(String, std::io::Error),
	#[error("Short read from /proc/{0}/mem: expected {1} bytes, got {2}")]
	ShortReadProcessMemory(u32, usize, usize),
}
