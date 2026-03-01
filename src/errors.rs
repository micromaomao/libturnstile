use thiserror::Error;

#[derive(Error, Debug)]
pub enum TurnstileTracerError {
	#[error("seccomp_init : {0}")]
	Init(libseccomp::error::SeccompError),
	#[error("seccomp_arch_add : {0}")]
	AddArch(libseccomp::error::SeccompError),
	#[error("seccomp_notify_fd : {0}")]
	NotifyFd(libseccomp::error::SeccompError),
	#[error("seccomp_notify_receive: {0}")]
	NotifyReceive(libseccomp::error::SeccompError),
	#[error("seccomp_notify_respond: {0}")]
	NotifyRespond(libseccomp::error::SeccompError),
	#[error("socketpair: {0}")]
	Socketpair(std::io::Error),
}
