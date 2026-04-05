use super::{ENABLE_LOG_IN_FORK, write_to_path};
use crate::{
	BindMountSandboxError,
	access::fs::ForeignFd,
	utils::{fork_wait, unix_recv_fd, unix_send_fd},
};
use log::{debug, error};
use smallvec::SmallVec;
use std::{ffi::OsStr, io, os::fd::AsRawFd, thread};

#[derive(Debug)]
pub(crate) struct ManagedNamespaces {
	pub l0_user: ForeignFd,
	pub l0_mnt: ForeignFd,
	pub l1_user: ForeignFd,
	pub l1_mnt: ForeignFd,
}

impl ManagedNamespaces {
	pub fn new(disable_userns: bool) -> Result<Self, BindMountSandboxError> {
		// These functions are always successful
		let uid = unsafe { libc::getuid() };
		let gid = unsafe { libc::getgid() };

		let uid_map = format!("0 {} 1\n", uid);
		let gid_map = format!("0 {} 1\n", gid);
		let uid_map_back = format!("{} 0 1\n", uid);
		let gid_map_back = format!("{} 0 1\n", gid);

		let mut sock = [-1, -1];
		let res = unsafe {
			libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				sock.as_mut_ptr(),
			)
		};
		if res != 0 {
			error!("socketpair failed: {}", io::Error::last_os_error());
			return Err(BindMountSandboxError::Socketpair(io::Error::last_os_error()));
		}
		let parent_sock = sock[0];
		let child_sock = sock[1];

		let namespaces = thread::scope(
			|s| -> Result<
				(libc::c_int, libc::c_int, libc::c_int, libc::c_int),
				BindMountSandboxError,
			> {
				let jh = s.spawn(|| unsafe {
					let fds = unix_recv_fd(parent_sock).and_then(|fd1| {
						unix_recv_fd(parent_sock).and_then(|fd2| {
							unix_recv_fd(parent_sock).and_then(|fd3| {
								unix_recv_fd(parent_sock).map(|fd4| (fd1, fd2, fd3, fd4))
							})
						})
					});
					libc::close(parent_sock);
					match fds {
						Ok(fds) => Ok(fds),
						Err(e) => Err(BindMountSandboxError::ReceiveNamespaceFd(e)),
					}
				});
				let res = unsafe {
					let res = fork_wait(|| {
						libc::close(parent_sock);

						let res = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS);
						if res != 0 {
							return perror!("unshare(CLONE_NEWUSER|CLONE_NEWNS)");
						}
						let res = write_to_path(c"/proc/self/uid_map", &uid_map);
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/setgroups", "deny");
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/gid_map", &gid_map);
						if res != 0 {
							return res;
						}
						let ns_fd = libc::open(
							c"/proc/self/ns/user".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if ns_fd < 0 {
							return perror!("open user ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, ns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 0 userns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(ns_fd);

						if disable_userns {
							let res = write_to_path(c"/proc/sys/user/max_user_namespaces", "1");
							if res != 0 {
								return res;
							}
						}

						let mntns_fd = libc::open(
							c"/proc/self/ns/mnt".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if mntns_fd < 0 {
							return perror!("open mount ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, mntns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!(
									"Failed to send level 0 mount namespace fd to parent: {}",
									e
								);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(mntns_fd);

						let res = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS);
						if res != 0 {
							return perror!("unshare(CLONE_NEWUSER|CLONE_NEWNS)");
						}
						let res = write_to_path(c"/proc/self/uid_map", &uid_map_back);
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/setgroups", "deny");
						if res != 0 {
							return res;
						}
						let res = write_to_path(c"/proc/self/gid_map", &gid_map_back);
						if res != 0 {
							return res;
						}
						let l1_ns_fd = libc::open(
							c"/proc/self/ns/user".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if l1_ns_fd < 0 {
							return perror!("open nested user ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, l1_ns_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 1 user ns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(l1_ns_fd);

						let l1_mnt_fd = libc::open(
							c"/proc/self/ns/mnt".as_ptr(),
							libc::O_RDONLY | libc::O_CLOEXEC,
						);
						if l1_mnt_fd < 0 {
							return perror!("open nested mount ns fd");
						}
						if let Err(e) = unix_send_fd(child_sock, l1_mnt_fd) {
							if ENABLE_LOG_IN_FORK {
								error!("Failed to send level 1 mount ns fd to parent: {}", e);
							}
							return e.raw_os_error().unwrap_or(libc::EIO);
						}
						libc::close(l1_mnt_fd);
						0
					})
					.map_err(BindMountSandboxError::ForkError)?;
					libc::close(child_sock);
					res
				};
				if res != 0 {
					_ = jh.join();
					return Err(match res {
						libc::EPERM | libc::ENOSPC => BindMountSandboxError::UserNsNotAllowed,
						err => BindMountSandboxError::NamespaceSetupFailed(err),
					});
				}
				let namespaces = jh.join().expect("Namespace setup thread panicked")?;
				Ok(namespaces)
			},
		)?;
		let l0u = ForeignFd {
			local_fd: namespaces.0,
		};
		let l0m = ForeignFd {
			local_fd: namespaces.1,
		};
		let l1u = ForeignFd {
			local_fd: namespaces.2,
		};
		let l1m = ForeignFd {
			local_fd: namespaces.3,
		};
		debug!(
			"Successfully set up namespaces: {:?}, {:?}, {:?}, {:?}",
			l0u.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l0m.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l1u.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
			l1m.readlink()
				.as_deref()
				.unwrap_or(OsStr::new("<readlink failed>")),
		);
		Ok(Self {
			l0_user: l0u,
			l0_mnt: l0m,
			l1_user: l1u,
			l1_mnt: l1m,
		})
	}

	pub unsafe fn nsenter_fn(
		&self,
		usr_0: bool,
		mnt_0: bool,
		mnt_1: bool,
		usr_1: bool,
	) -> impl Fn() -> io::Result<()> + 'static {
		let mut ns_fds = SmallVec::<[libc::c_int; 4]>::new();
		if usr_0 {
			ns_fds.push(self.l0_user.as_raw_fd());
		}
		if mnt_0 {
			ns_fds.push(self.l0_mnt.as_raw_fd());
		}
		if mnt_1 {
			ns_fds.push(self.l1_mnt.as_raw_fd());
		}
		if usr_1 {
			ns_fds.push(self.l1_user.as_raw_fd());
		}
		move || unsafe {
			for (i, &fd) in ns_fds.iter().enumerate() {
				let res = libc::setns(fd, 0);
				if res != 0 {
					let err = libc::__errno_location().read();
					if ENABLE_LOG_IN_FORK {
						error!(
							"setns for fd ns_fds[{}] (= {}) failed with errno {}",
							i, fd, err
						);
					}
					return Err(io::Error::from_raw_os_error(err));
				} else if ENABLE_LOG_IN_FORK {
					debug!("Joined namespace ns_fds[{}] = {}", i, fd);
				}
			}
			Ok(())
		}
	}
}
