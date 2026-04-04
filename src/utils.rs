use log::{debug, error};

/// Send a file descriptor to another process via a Unix socket using
/// SCM_RIGHTS.  This function can safely be used in pre_exec context
pub unsafe fn unix_send_fd(sock: libc::c_int, fd: libc::c_int) -> std::io::Result<()> {
	// Use a [u64] buffer to ensure 8-byte alignment required by cmsghdr.
	const CMSG_SPACE: usize =
		unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize };
	const NUM_U64S: usize = (CMSG_SPACE + 7) / 8;
	let mut cmsg_buf = [0u64; NUM_U64S];

	let mut dummy: u8 = 0;
	let mut iov = libc::iovec {
		iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
		iov_len: 1,
	};

	let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
	msg.msg_controllen = CMSG_SPACE as libc::size_t;

	unsafe {
		let cmsg = libc::CMSG_FIRSTHDR(&msg);
		if cmsg.is_null() {
			// io::Error::new() allocates and is not safe in a pre_exec context;
			// this branch is unreachable since we sized the buffer correctly above.
			panic!("CMSG_FIRSTHDR returned null");
		}
		(*cmsg).cmsg_level = libc::SOL_SOCKET;
		(*cmsg).cmsg_type = libc::SCM_RIGHTS;
		(*cmsg).cmsg_len =
			libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as libc::size_t;
		let fd_data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
		std::ptr::write_unaligned(fd_data, fd);
	}

	let ret = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
	if ret < 0 {
		return Err(std::io::Error::last_os_error());
	}
	Ok(())
}

/// Receive a file descriptor sent via SCM_RIGHTS over a Unix socket.
pub fn unix_recv_fd(sock: libc::c_int) -> std::io::Result<libc::c_int> {
	const CMSG_SPACE: usize =
		unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize };
	const NUM_U64S: usize = (CMSG_SPACE + 7) / 8;
	let mut cmsg_buf = [0u64; NUM_U64S];

	let mut dummy: u8 = 0;
	let mut iov = libc::iovec {
		iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
		iov_len: 1,
	};

	let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
	msg.msg_controllen = CMSG_SPACE as libc::size_t;

	let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
	if ret < 0 {
		return Err(std::io::Error::last_os_error());
	}
	if ret == 0 {
		return Err(std::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			"child closed socket without sending fd",
		));
	}

	let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
	if cmsg.is_null() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"no control message received",
		));
	}
	let received_fd =
		unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int) };
	Ok(received_fd)
}

/// ## Safety
///
/// `f` must be async signal safe.  This means no allocations (because
/// they may deadlock in the child), avoiding most std library functions,
/// and no panics.
pub unsafe fn fork_wait<F: FnOnce() -> libc::c_int + Send>(f: F) -> std::io::Result<libc::c_int> {
	unsafe {
		match libc::fork() {
			-1 => {
				let err = std::io::Error::last_os_error();
				error!("fork failed: {}", err);
				Err(err)
			}
			0 => {
				// In child process
				let exit_code = f();
				libc::_exit(exit_code)
			}
			pid => {
				let mut wstatus: libc::c_int = 0;
				loop {
					match libc::waitpid(pid, &mut wstatus, 0) {
						-1 => {
							if libc::__errno_location().read() == libc::EINTR {
								continue;
							}
							let err = std::io::Error::last_os_error();
							error!("waitpid failed: {}", err);
							break Err(err);
						}
						_ => {
							if libc::WIFEXITED(wstatus) {
								let exit_code = libc::WEXITSTATUS(wstatus);
								debug!("Forked child exited with code {}", exit_code);
								break Ok(exit_code);
							} else if libc::WIFSIGNALED(wstatus) {
								let signal = libc::WTERMSIG(wstatus);
								error!("Forked child killed by signal {}", signal);
								break Err(std::io::Error::from_raw_os_error(libc::EINTR));
							} else {
								error!("Unknown return from waitpid");
								break Err(std::io::Error::new(
									std::io::ErrorKind::Other,
									"Unknown return from waitpid",
								));
							}
						}
					}
				}
			}
		}
	}
}
