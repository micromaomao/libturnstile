use std::ffi::CString;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TurnstileTracerError {
	#[error("seccomp_init : {0}")]
	Init(#[source] libseccomp::error::SeccompError),
	#[error("seccomp_arch_add : {0}")]
	AddArch(#[source] libseccomp::error::SeccompError),
	#[error("seccomp_load failed with error code {0}")]
	Load(libc::c_int),
	#[error("seccomp_set_ctl_tsync : {0}")]
	SetCtlTsync(#[source] libseccomp::error::SeccompError),
	#[error("seccomp_set_ctl_no_new_privs : {0}")]
	SetCtlNoNewPrivs(#[source] libseccomp::error::SeccompError),
	#[error("seccomp_notify_fd failed with error code {0}")]
	NotifyFd(libc::c_int),
	#[error("socketpair: {0}")]
	Socketpair(#[source] std::io::Error),
	#[error("failed to spawn child process: {0}")]
	Spawn(#[source] std::io::Error),
	#[error("failed to send notify fd to parent process: {0}")]
	SendNotifyFd(#[source] std::io::Error),
	#[error("failed to receive notify fd from child process: {0}")]
	ReceiveNotifyFd(#[source] std::io::Error),
	#[error("failed to resolve syscall {0}: {1}")]
	ResolveSyscall(&'static str, #[source] libseccomp::error::SeccompError),
	#[error("failed to add filter rule for syscall {0}: {1}")]
	AddRule(
		libseccomp::ScmpSyscall,
		#[source] libseccomp::error::SeccompError,
	),
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
	ReadProcessMemoryOpen(u32, std::io::Error),
	#[error("Read from /proc/{0}/mem failed: {1}")]
	ReadProcessMemoryPread(u32, std::io::Error),
	#[error("Traced process issued invalid syscall: {0}")]
	InvalidSyscallData(&'static str),
	#[error("Failed to open {0}: {1}")]
	OpenFd(String, std::io::Error),
	#[error("Short read from /proc/{0}/mem: expected {1} bytes, got {2}")]
	ShortReadProcessMemory(u32, usize, usize),
}

#[derive(Error, Debug)]
pub enum BindMountSandboxError {
	#[error("Failed to set up tracer: {0}")]
	TurnstileTracerError(#[from] TurnstileTracerError),
	#[error("getcwd failed: {0}")]
	Getcwd(std::io::Error),
	#[error("socketpair: {0}")]
	Socketpair(std::io::Error),
	#[error("Failed to fork process: {0}")]
	ForkError(std::io::Error),
	#[error("Failed to set up namespaces: errno {0}")]
	NamespaceSetupFailed(libc::c_int),
	#[error("Setting up new user namespace is denied")]
	UserNsNotAllowed,
	#[error("Failed to receive namespace fd from child: {0}")]
	ReceiveNamespaceFd(std::io::Error),
	#[error("failed to spawn child process: {0}")]
	Spawn(std::io::Error),
	#[error("Failed to make detached tmpfs mount: errno {0}")]
	MakeDetachedTmpfsMountFailed(libc::c_int),
	#[error("Failed to receive mount object fd from child: {0}")]
	ReceiveMountFd(std::io::Error),
	#[error("mount failed: errno {0}")]
	MountFailed(libc::c_int),
	#[error("Failed to open path within sandbox: {0}")]
	ResolveSandboxPath(#[source] std::io::Error),
	#[error("Failed to open path on host: {0:?}: {1}")]
	ResolveHostPath(CString, #[source] std::io::Error),
	#[error("Failed to mkdir within sandbox: {0}")]
	Mkdir(#[source] std::io::Error),
	#[error("Failed to create file for mountpoint within sandbox: {0}")]
	Mkfile(#[source] std::io::Error),
	#[error("Failed to set attribute on mountpoint within sandbox: {0}")]
	MountSetAttrsFailed(libc::c_int),
	#[error("Failed to stat path on host: {0:?}: {1}")]
	StatHostPath(CString, #[source] std::io::Error),
	#[error("Failed to stat path within sandbox: {0}")]
	StatSandboxPath(#[source] std::io::Error),
	#[error("Failed to remove path within sandbox: {0}")]
	RemoveSandboxPath(#[source] std::io::Error),
}
