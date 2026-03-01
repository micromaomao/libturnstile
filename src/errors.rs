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
}
