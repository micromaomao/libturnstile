# Tools and library for "interactive" sandboxing

Turnstile implements a
[seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)-based
access tracer, which may be used together with other sandboxing mechanisms
(like mount namespaces or Landlock) to find out what accesses are
attempted.

> [!WARNING]
> **Work in progress**. API will not be stable at all.

> [!WARNING]
> Seccomp-unotify is not a sandboxing solution on its own due to the
limitations of syscall-based filtering (such as TOCTOU problems with
memory references).  This crate does not provide any security when used
alone.

> [!NOTE]
> There is plan to turn this library into a full-fledged sandboxing tool
using, for now, namespace and bind-mount, and eventually Landlock with
mutable rulesets.

## Features

- Supports most non-metadata fs accesses, including Unix socket connects
- API is designed to be maximally data-preserving: files are identified by their original path as passed from the application, possibly with a dir fd for *at() operations.

## Goals

- Completely unprivileged
- The library itself should be non-opinionated
- (Eventually) supports a batteries-included, fully dynamic and inspectable sandbox, as an extension of this library

## Example

```
> target/release/examples/fstrace cargo build
fstrace[828276] exec "/usr/local/bin/cargo"
fstrace[828276] exec "/usr/bin/cargo"
cargo[828276] open r "/etc/ld.so.preload"
cargo[828276] open r "/etc/ld.so.cache"
cargo[828276] open r "/usr/lib/liblzma.so.5"
cargo[828276] open r "/usr/lib/libgcc_s.so.1"
...
rustc[828297] unlink "/home/mao/turnstile/target/debug/deps/libturnstile-00c39746b8f0f2b9.ehas8k75ezbnsay69cv9snhj1.0sbwwi3.rcgu.o"
rustc[828297] unlink "/home/mao/turnstile/target/debug/deps/libturnstile-00c39746b8f0f2b9.eqlnbk1spzsmryvhy6r7il0y6.0sbwwi3.rcgu.o"
rustc[828297] unlink "/home/mao/turnstile/target/debug/deps/libturnstile-00c39746b8f0f2b9.f0bf248u890rb6cl3b6abihvl.0sbwwi3.rcgu.o"
cargo[828294] open r "/home/mao/turnstile/target/debug/deps/libturnstile-00c39746b8f0f2b9.d"
cargo[828294] create file "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/dep-lib-libturnstile"
cargo[828294] open w "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/dep-lib-libturnstile"
cargo[828294] open r "/home/mao/turnstile/target/debug/deps/liblibturnstile-00c39746b8f0f2b9.rlib"
cargo[828294] open r "/home/mao/turnstile/target/debug/liblibturnstile.rlib"
cargo[828294] unlink "/home/mao/turnstile/target/debug/liblibturnstile.rlib"
cargo[828294] link "/home/mao/turnstile/target/debug/deps/liblibturnstile-00c39746b8f0f2b9.rlib" -> "/home/mao/turnstile/target/debug/liblibturnstile.rlib"
cargo[828294] create file "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/lib-libturnstile"
cargo[828294] open w "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/lib-libturnstile"
cargo[828294] create file "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/lib-libturnstile.json"
cargo[828294] open w "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/lib-libturnstile.json"
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.15s
cargo[828276] open r "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-00c39746b8f0f2b9/dep-lib-libturnstile"
cargo[828276] open r "/home/mao/turnstile/target/debug/liblibturnstile.d"
cargo[828276] create file "/home/mao/turnstile/target/debug/liblibturnstile.d"
cargo[828276] open w "/home/mao/turnstile/target/debug/liblibturnstile.d"
fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp
fstrace: child process exited with status exit status: 0
```

```
> cargo clean && time cargo build
     Removed 1697 files, 497.1MiB total
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.45
   Compiling libc v0.2.183
   Compiling libseccomp-sys v0.3.0
   Compiling pkg-config v0.3.32
   Compiling thiserror v2.0.18
   Compiling bitflags v2.11.0
   Compiling log v0.4.29
   Compiling libseccomp v0.4.0
   Compiling syn v2.0.117
   Compiling page_size v0.6.0
   Compiling thiserror-impl v2.0.18
   Compiling libturnstile v0.1.0 (/home/mao/turnstile)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.21s

________________________________________________________
Executed in    1.24 secs    fish           external
   usr time    2.64 secs  391.00 micros    2.64 secs
   sys time    0.44 secs   46.00 micros    0.44 secs

> cargo clean && time /tmp/fstrace -o fstrace.log cargo build
     Removed 333 files, 90.2MiB total
   Compiling proc-macro2 v1.0.106
   Compiling quote v1.0.45
   Compiling unicode-ident v1.0.24
   Compiling libc v0.2.183
   Compiling libseccomp-sys v0.3.0
   Compiling pkg-config v0.3.32
   Compiling thiserror v2.0.18
   Compiling bitflags v2.11.0
   Compiling log v0.4.29
   Compiling libseccomp v0.4.0
   Compiling syn v2.0.117
   Compiling page_size v0.6.0
   Compiling thiserror-impl v2.0.18
   Compiling libturnstile v0.1.0 (/home/mao/turnstile)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.40s
fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp
fstrace: child process exited with status exit status: 0

________________________________________________________
Executed in    1.43 secs    fish           external
   usr time    2.70 secs    3.51 millis    2.69 secs
   sys time    0.62 secs    0.05 millis    0.62 secs

> wc -l fstrace.log
7377 fstrace.log

```

## TODO

- Improve API for performance and ergonomics
- Exec handling - merge with `OpenOperation`??
- Don't print `fstrace: error: seccomp_notify_receive: There was a system failure beyond the control of libseccomp` when the child process exits
- sendmm?msg, recvmm?sg handling (hard to do without deadlocking at the start)
- io_uring (very hard to do properly, but maybe we can just disable)
- Landlock support to restrict the tracer itself
