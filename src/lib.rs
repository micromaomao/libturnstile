//! Turnstile implements a
//! [seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)-based
//! access tracer, and a namespace / bind-mount based sandbox that can be used
//! with the tracer to dynamically find out about access requests and allow
//! them.
//!
//! The tracer may also be used together with other sandboxing mechanisms
//! (like Landlock), or used on its own for non-security scenarios to find out
//! what files are used by a program.

pub mod access;
mod errors;
mod sandbox;
mod syscalls;
mod tracer;
mod utils;

pub use crate::errors::*;
pub use crate::sandbox::*;
pub use crate::syscalls::RequestContext;
pub use crate::tracer::*;
