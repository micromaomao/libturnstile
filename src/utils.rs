use log::{debug, error};

#[cfg(feature = "serialize")]
use serde::{Deserialize, Serialize};

/// Send a file descriptor to another process via a Unix socket using
/// SCM_RIGHTS.  This function can safely be used in pre_exec context
pub unsafe fn unix_send_fd(sock: libc::c_int, fd: libc::c_int) -> std::io::Result<()> {
	assert!(sock >= 0);
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

/// Serializable `{ sec, nsec }` representation of a `libc::timespec`.
#[cfg(feature = "serialize")]
#[derive(Serialize, Deserialize)]
struct Timespec {
	sec: i64,
	nsec: i64,
}

#[cfg(feature = "serialize")]
impl From<&libc::timespec> for Timespec {
	fn from(t: &libc::timespec) -> Self {
		Timespec {
			sec: t.tv_sec as i64,
			nsec: t.tv_nsec as i64,
		}
	}
}

#[cfg(feature = "serialize")]
impl From<Timespec> for libc::timespec {
	fn from(t: Timespec) -> Self {
		libc::timespec {
			tv_sec: t.sec as libc::time_t,
			tv_nsec: t.nsec as libc::c_long,
		}
	}
}

/// Serialize a `libc::timespec` as a `{ sec, nsec }` object.
#[cfg(feature = "serialize")]
pub fn serialize_timespec<S>(time: &libc::timespec, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	Timespec::from(time).serialize(serializer)
}

/// Deserialize a `libc::timespec` from a `{ sec, nsec }` object.
#[cfg(feature = "serialize")]
pub fn deserialize_timespec<'de, D>(deserializer: D) -> Result<libc::timespec, D::Error>
where
	D: serde::Deserializer<'de>,
{
	Ok(Timespec::deserialize(deserializer)?.into())
}

/// Serialize a `[libc::timespec; 2]` as a two-element array of `{ sec,
/// nsec }` objects.
#[cfg(feature = "serialize")]
pub fn serialize_timespec_pair<S>(
	times: &[libc::timespec; 2],
	serializer: S,
) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	use serde::ser::SerializeSeq;

	let mut seq = serializer.serialize_seq(Some(times.len()))?;
	for t in times {
		seq.serialize_element(&Timespec::from(t))?;
	}
	seq.end()
}

/// Deserialize a `[libc::timespec; 2]` from a two-element array of `{ sec,
/// nsec }` objects.
#[cfg(feature = "serialize")]
pub fn deserialize_timespec_pair<'de, D>(deserializer: D) -> Result<[libc::timespec; 2], D::Error>
where
	D: serde::Deserializer<'de>,
{
	let times: Vec<Timespec> = Vec::deserialize(deserializer)?;
	if times.len() != 2 {
		return Err(serde::de::Error::custom(format!(
			"expected array of length 2, got length {}",
			times.len()
		)));
	}
	let mut iter = times.into_iter();
	Ok([iter.next().unwrap().into(), iter.next().unwrap().into()])
}

/// Serialize a `CString` as a human-readable string.
///
/// serde already has a built-in `CString` impl, but it encodes the value
/// as a sequence of raw bytes (e.g. a JSON array of numbers).  For paths
/// in a human-facing protocol we instead emit a plain string when the
/// bytes are valid UTF-8, falling back to a byte array for the rare
/// non-UTF-8 path so the value still round-trips losslessly.
#[cfg(feature = "serialize")]
pub fn serialize_cstring<S>(value: &std::ffi::CString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	let bytes = value.to_bytes();
	match std::str::from_utf8(bytes) {
		Ok(s) => serializer.serialize_str(s),
		Err(_) => serializer.serialize_bytes(bytes),
	}
}

/// Deserialize a `CString` from either a string or a byte array (the two
/// forms produced by [`serialize_cstring`]).
#[cfg(feature = "serialize")]
pub fn deserialize_cstring<'de, D>(deserializer: D) -> Result<std::ffi::CString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	struct CStringVisitor;

	impl<'de> serde::de::Visitor<'de> for CStringVisitor {
		type Value = std::ffi::CString;

		fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			f.write_str("a string or byte array without interior NUL bytes")
		}

		fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
			self.visit_bytes(v.as_bytes())
		}

		fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
			std::ffi::CString::new(v).map_err(|_| E::custom("interior NUL byte in CString"))
		}

		fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
		where
			A: serde::de::SeqAccess<'de>,
		{
			let mut bytes = Vec::new();
			while let Some(b) = seq.next_element::<u8>()? {
				bytes.push(b);
			}
			self.visit_bytes(&bytes)
		}
	}

	deserializer.deserialize_any(CStringVisitor)
}
