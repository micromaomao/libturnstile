use std::io;

use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};

use crate::{AccessRequestError, TurnstileTracer};

pub mod fs;
pub mod net;

#[derive(Debug)]
pub struct RequestContext<'a> {
	pub(crate) tracer: &'a TurnstileTracer,
	pub(crate) sreq: ScmpNotifReq,
	pub(crate) notify_fd: ScmpFd,
	pub(crate) valid: bool,
}

impl<'a> RequestContext<'a> {
	pub fn sreq(&self) -> &ScmpNotifReq {
		&self.sreq
	}

	pub(crate) fn still_valid(&mut self) -> Result<bool, AccessRequestError> {
		if !self.valid {
			return Ok(false);
		}
		match libseccomp::notify_id_valid(self.notify_fd, self.sreq.id) {
			Ok(()) => Ok(true),
			Err(e) => {
				if e.errno() == Some(libseccomp::error::SeccompErrno::ENOENT) {
					self.valid = false;
					Ok(false)
				} else {
					Err(AccessRequestError::NotifyIdValid(e))
				}
			}
		}
	}

	pub(crate) fn send_response(
		&mut self,
		resp: libseccomp::ScmpNotifResp,
	) -> Result<(), AccessRequestError> {
		resp.respond(self.notify_fd)
			.map_err(AccessRequestError::NotifyRespond)
	}

	pub fn send_continue(mut self) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_continue(
			self.sreq.id,
			ScmpNotifRespFlags::empty(),
		))
	}

	pub fn send_error(mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_error(
			self.sreq.id,
			errno,
			ScmpNotifRespFlags::empty(),
		))
	}

	pub(crate) fn cstr_from_target_memory(
		&mut self,
		src: *const libc::c_char,
	) -> Result<Option<std::ffi::CString>, io::Error> {
		unimplemented!()
	}
}
