# libturnstile

[![crates.io](https://img.shields.io/crates/v/libturnstile?style=flat)](https://crates.io/crates/libturnstile)

Turnstile implements a
[seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)-based
access tracer, and a namespace / bind-mount based sandbox that can be used
with the tracer to dynamically find out about access requests and allow
them.

The tracer may also be used together with other sandboxing mechanisms
(like Landlock), or used on its own for non-security scenarios to find out
what files are used by a program.

https://github.com/user-attachments/assets/7aa7cb20-e4b2-49d6-98bd-31069f352ebf

> [!WARNING]
> **Work in progress**. API and implementation not stable.

> [!WARNING]
> Using the BindMountSandbox struct on its own is likely to be insecure.
> Also consider restricting sending signals or other actions on
> outside-sandbox processes via Landlock, terminal escape sequences from
> output, restricting direct access to the tty via stdin/stdout/stderr, etc.
>
> At this moment, the included `turnstile-sandbox` binary is also not
> protected against the above, but this is WIP.

## Features

### Tracer

- Support most non-metadata fs accesses, including Unix socket connects
  and discovering mmaps that needs execute permissions
- API is designed to be maximally data-preserving: files are identified by
  their original path as passed from the application, possibly with a dir
  fd for *at() operations.

### Sandbox

- Support dynamic manipulation of the sandbox's view of the filesystem
  using bind mounts or placeholder files in a tmpfs.
- Supports differentiating read and execute permission needs.
- The example `turnstile-sandbox` binary implements config parsing, launching
  a program on denials to prompt the user, symlink chasing to expose the
  full set of required paths, and mapping places like /tmp to a separate
  location, as specified in the config.

## Goals

- Completely unprivileged
- The library itself should be non-opinionated
- The library will support building a batteries-included, fully dynamic
  and inspectable sandbox.
- The included turnstile-sandbox binary should be such an implementation, ready for general use.

## Example: fstrace

```
> target/release/fstrace cargo build
fstrace[163263] exec "/home/mao/.local/qemu/bin/cargo"
fstrace[163263] exec "/usr/local/sbin/cargo"
fstrace[163263] exec "/usr/local/bin/cargo"
fstrace[163263] exec "/usr/bin/cargo"
cargo[163263] access r "/etc/ld.so.preload"
...
cargo[163658] link "/home/mao/turnstile/target/debug/deps/liblibturnstile-63cec22bf0999bf8.rlib" -> "/home/mao/turnstile/target/debug/liblibturnstile.rlib"
cargo[163658] stat "/home/mao/turnstile/target/debug/deps/liblibturnstile-63cec22bf0999bf8.rmeta"
cargo[163658] open w+ "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-63cec22bf0999bf8/lib-libturnstile"
cargo[163658] open w+ "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-63cec22bf0999bf8/lib-libturnstile.json"
warning: `libturnstile` (lib) generated 2 warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.70s
cargo[163263] open r "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-63cec22bf0999bf8/dep-lib-libturnstile"
cargo[163263] stat "/home/mao/turnstile/target/debug/.fingerprint/libturnstile-63cec22bf0999bf8/dep-lib-libturnstile"
cargo[163263] open r "/home/mao/turnstile/target/debug/liblibturnstile.d"
cargo[163263] open w+ "/home/mao/turnstile/target/debug/liblibturnstile.d"
cargo[163263] stat "/home/mao/.cargo/.global-cache"
cargo[163263] stat "/home/mao/.cargo/.global-cache"
cargo[163263] stat "/home/mao/.cargo/.global-cache"
[2026-05-09T16:35:43Z INFO  fstrace::common] child process exited with status exit status: 0
```

```
> hyperfine --warmup 1 --prepare 'cargo clean' 'cargo build --features tools'
Benchmark 1: cargo build --features tools
  Time (mean ± σ):      3.466 s ±  0.023 s    [User: 19.449 s, System: 1.700 s]
  Range (min … max):    3.422 s …  3.500 s    10 runs

> hyperfine --warmup 1 --prepare 'cargo clean' '/tmp/fstrace -o /tmp/fstrace.log cargo build --features tools'
Benchmark 1: /tmp/fstrace -o /tmp/fstrace.log cargo build --features tools
  Time (mean ± σ):      3.751 s ±  0.035 s    [User: 19.223 s, System: 2.140 s]
  Range (min … max):    3.689 s …  3.797 s    10 runs

> wc -l /tmp/fstrace.log
802098 /tmp/fstrace.log
```

## Example: turnstile-sandbox

```
> rm -r target/release/
> time RUST_LOG=none target/debug/turnstile-sandbox --permissive src/bin/sandbox-config-default.yaml cargo build --release
   Compiling proc-macro2 v1.0.106
   Compiling quote v1.0.45
   Compiling unicode-ident v1.0.24
   Compiling libc v0.2.183
   Compiling libseccomp-sys v0.3.0
   Compiling pkg-config v0.3.32
   Compiling thiserror v2.0.18
   Compiling bitflags v2.11.0
   Compiling log v0.4.29
   Compiling smallvec v1.15.1
   Compiling libseccomp v0.4.0
...

    Finished `release` profile [optimized] target(s) in 5.51s
Denials:
rules:
  /dev/pts/11: ''
  /dev/tty: r
  /home/mao/.cargo: rw
  /home/mao/.gitconfig: r
  /home/mao/code/libturnstile/target: rw
  /home/mao/code/libturnstile/target/release/build/libc-504a5ce082bd595c/build-script-build: rx
  /home/mao/code/libturnstile/target/release/build/libseccomp-d738e9bb4eb6d81f/build-script-build: rx
  /home/mao/code/libturnstile/target/release/build/libseccomp-sys-c627e7d1953383fd/build-script-build: rx
  /home/mao/code/libturnstile/target/release/build/proc-macro2-bbe06dc318ece6a7/build-script-build: rx
  /home/mao/code/libturnstile/target/release/build/quote-23db72bd56e2b78a/build-script-build: rx
  /home/mao/code/libturnstile/target/release/build/thiserror-abd8cf72cc63e711/build-script-build: rx
  /home/mao/code/libturnstile/target/release/deps/libthiserror_impl-163ddbb09a2d8755.so: rx
  /sys/devices/system/cpu/online: r
  /sys/fs/cgroup/user.slice/cpu.max: r
  /sys/fs/cgroup/user.slice/user-1000.slice/cpu.max: r
  /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/cpu.max: r
  /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/kitty-249158-0.scope/cgroup.controllers: ''
  /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cpu.max: r
  /tmp: rwx

________________________________________________________
Executed in    5.57 secs    fish           external
   usr time   13.54 secs    0.21 millis   13.54 secs
   sys time    2.17 secs    1.02 millis    2.17 secs

> rm -r target/release/
> time cargo build --release
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.45
   Compiling libc v0.2.183
   Compiling libseccomp-sys v0.3.0
   Compiling pkg-config v0.3.32
...
    Finished `release` profile [optimized] target(s) in 4.39s

________________________________________________________
Executed in    4.40 secs    fish           external
   usr time   13.36 secs  100.00 micros   13.36 secs
   sys time    1.37 secs  997.00 micros    1.37 secs
```

## TODO

- Improve API for performance and ergonomics
- sendmm?msg, recvmm?sg handling (hard to do without deadlocking at the start)
- Landlock support to restrict fstrace itself
