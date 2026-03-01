use libseccomp::{ScmpFilterContext, ScmpNotifReq, ScmpNotifResp};

use crate::{AccessRequest, TurnstileTracer, TurnstileTracerError};

pub fn add_filter_rules(filter_ctx: &mut ScmpFilterContext) -> Result<(), TurnstileTracerError> {
	unimplemented!()
}

pub fn handle_notification<'a>(
	tracer: &'a TurnstileTracer,
	req_data: &ScmpNotifReq,
) -> Result<Option<(ScmpNotifResp, Option<AccessRequest<'a>>)>, TurnstileTracerError> {
	unimplemented!()
}
