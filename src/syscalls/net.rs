use libseccomp::{ScmpFd, ScmpFilterContext, ScmpNotifReq};

use crate::{
	AccessRequest, AccessRequestError, TurnstileTracer, TurnstileTracerError,
	syscalls::RequestContext,
};

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	unimplemented!()
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	unimplemented!()
}
