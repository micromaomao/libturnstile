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

> [!WARNING]
> **Work in progress**. API will not be stable at all.

> [!WARNING]
> Using the BindMountSandbox struct on its own is likely to be insecure.
> Also consider restricting sending signals or other actions on
> outside-sandbox processes via Landlock, terminal escape sequences from
> output, restricting direct access to the tty via stdin/stdout/stderr, etc.
>
> At this moment, the included turnstile-sandbox binary is not protected
> against the above.

## Features

### Tracer

- Support most non-metadata fs accesses, including Unix socket connects
- API is designed to be maximally data-preserving: files are identified by
  their original path as passed from the application, possibly with a dir
  fd for *at() operations.

### Sandbox

- Support dynamic manipulation of the sandbox's view of the filesystem
  using bind mounts or placeholder files in a tmpfs.

## Goals

- Completely unprivileged
- The library itself should be non-opinionated
- The library will support building a batteries-included, fully dynamic
  and inspectable sandbox.
- The included turnstile-sandbox binary will eventually be such an implementation, ready for general use.

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
> cat /tmp/sandbox-config.yaml
rules:
  /usr: rx
  /bin: rx
  /lib: rx
  /lib64: rx
  /proc: r
  /home: r
  /home/mao/turnstile: rwx
  /home/mao/.rustup: rx

> target/debug/turnstile-sandbox /tmp/sandbox-config.yaml --permissive cargo build --features tools
...
[2026-05-09T17:37:23Z INFO  turnstile_sandbox] rust-lld[226136] need fs permission r-- on "/sys/devices/system/cpu/online"
[2026-05-09T17:37:23Z INFO  libturnstile::sandbox] Mount bind "/sys/devices/system/cpu/online" "/sys/devices/system/cpu/online" ro,noexec
warning: `libturnstile` (bin "turnstile-sandbox") generated 5 warnings (run `cargo fix --bin "turnstile-sandbox" -p libturnstile` to apply 4 suggestions)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.38s
[2026-05-09T17:37:23Z INFO  turnstile_sandbox] Child process exited successfully
Denials:
rules:
  /: rw
  /dev/null: r
  /dev/urandom: r
  /etc/ca-certificates/extracted/tls-ca-bundle.pem: ''
  /etc/ld.so.cache: r
  /etc/ssl: ''
  /home/mao/.cache/ccache/4/b: w
  /home/mao/.cargo: rw
  /run/user/1000: ''
  /run/user/1000/ccache-tmp: w
  /sys/devices/system/cpu/online: r
  /sys/fs/cgroup/user.slice/cpu.max: r
  /sys/fs/cgroup/user.slice/user-1000.slice/cpu.max: r
  /sys/fs/cgroup/user.slice/user-1000.slice/session-27.scope/cgroup.controllers: ''
  /sys/fs/cgroup/user.slice/user-1000.slice/session-27.scope/cpu.max: r
  /sys/kernel/mm/transparent_hugepage/enabled: r
  /tmp: rwx
```

## TODO

- Rework sandbox to move child mount into new parent mount when parent needs to be remounted, e.g. allowing /home/mao when /home/mao/turnstile is already allowed, without breaking existing fds / cwd to /home/mao/turnstile
- Rework sandbox to support resolve-only permissions (with placeholders)
- Improve API for performance and ergonomics
- sendmm?msg, recvmm?sg handling (hard to do without deadlocking at the start)
- io_uring (very hard to do properly, but maybe we can just disable)
- Landlock support to restrict fstrace itself
