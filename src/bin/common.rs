use std::{env, io, os::fd::FromRawFd, sync::OnceLock};

use log::{error, info};

pub fn init_logger() {
	let mut log_builder = env_logger::builder();
	if env::var_os("RUST_LOG").is_none() {
		log_builder.filter_level(log::LevelFilter::Info);
	} else {
		log_builder.parse_default_env();
	}
	log_builder.init();
}

#[derive(Debug)]
pub struct ProcPidFd {
	pidfd: libc::c_int,
}

impl ProcPidFd {
	pub fn from_pid(pid: u32) -> io::Result<Self> {
		let pidfd = unsafe {
			libc::open(
				format!("/proc/{}\0", pid).as_ptr() as *const libc::c_char,
				libc::O_PATH | libc::O_CLOEXEC,
			)
		};
		if pidfd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { pidfd })
	}

	pub fn is_alive(&self) -> io::Result<bool> {
		let pidfd = self.pidfd;
		let status_fd =
			unsafe { libc::openat(pidfd, c"status".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
		if status_fd < 0 {
			let errno = unsafe { libc::__errno_location().read() };
			if errno == libc::ENOENT {
				// The process has already exited and its pidfd is now a zombie.
				return Ok(false);
			} else {
				return Err(io::Error::last_os_error());
			}
		}
		let mut status_file = unsafe { std::fs::File::from_raw_fd(status_fd) };
		let mut status_contents = String::new();
		std::io::Read::read_to_string(&mut status_file, &mut status_contents)?;
		if status_contents.contains("State:\tZ") {
			return Ok(false);
		}
		Ok(true)
	}
}

pub fn handle_child_result<E: std::fmt::Display>(
	child_result: Result<std::process::Child, E>,
	pidfd_out: &OnceLock<ProcPidFd>,
) -> ! {
	match child_result {
		Ok(mut child) => {
			let pidfd = match ProcPidFd::from_pid(child.id()) {
				Ok(pidfd) => pidfd,
				Err(e) => {
					error!("error opening pidfd: {}", e);
					std::process::exit(1);
				}
			};
			pidfd_out.set(pidfd).unwrap();
			let status = match child.wait() {
				Ok(status) => status,
				Err(e) => {
					error!("error waiting for child process: {}", e);
					std::process::exit(1);
				}
			};
			if status.success() {
				info!("child process exited with status {}", status);
			} else {
				error!("child process exited with status {}", status);
			}
			std::process::exit(status.code().unwrap_or(1));
		}
		Err(e) => {
			error!("error spawning child: {}", e);
			std::process::exit(1);
		}
	}
}
