//! Turnstile implements a
//! [seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)-based
//! access tracer, which may be used together with other sandboxing
//! mechanisms (like mount namespaces or Landlock) to find out what
//! accesses are attempted.
//!
//! <div class="warning">
//! Seccomp-unotify is not a sandboxing solution on its own due to the
//! limitations of syscall-based filtering (such as TOCTOU problems with
//! memory references).  This crate does not provide any security when
//! used alone.
//! </div>

mod access;
mod errors;
mod syscalls;
mod tracer;

pub use crate::access::*;
pub use crate::errors::*;
pub use crate::syscalls::RequestContext;
pub use crate::tracer::*;
