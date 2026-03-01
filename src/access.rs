use crate::tracer::TurnstileTracer;

pub struct AccessRequest<'a> {
	tracer: &'a TurnstileTracer,
}
