# Sandbox redesign (`ManagedBindMountSandbox` v2 — fd-upgrade design)

This document describes a redesign of `ManagedBindMountSandbox` that
preserves fd / cwd identity across mount-layout changes, and that keeps
the sandboxed app's view consistent with the live mount layout by
*upgrading* held fds via `SECCOMP_IOCTL_NOTIF_ADDFD` rather than by
creating a bind mount for every path the app touches.

Two problems motivate it:

1. **Identity loss on mount updates.**  The original implementation
   reacts to "the desired mount set changed" by unmounting old entries
   with `MNT_DETACH` and remounting new ones.  That breaks any held fd
   or cwd that referenced the old mount:
   - The old mount becomes detached (alive via the held reference, but
     `mnt_ns == NULL`).
   - A newly mounted entry at the same path is a *different*
     `struct mount`; the app's fd does not migrate to it.
   - `..` from a cwd inside the detached mount stays inside it.
   - `getcwd()` returns `(unreachable)` until something fixes it.

   Concrete trace: the sandbox starts with only `rw /home/mao/turnstile`
   granted.  bash inside the sandbox runs `ls /home`; to satisfy it we
   grant additional read on `/home` and add a `ro /home` mount.  To
   re-mount the already-covered `/home/mao/turnstile` under the new
   `/home`, the old code unmounts it; the cwd (set to
   `/home/mao/turnstile`) goes invalid and `realpath .` fails with
   `ENOENT`.

2. **Stale fds after a grant.**  An fd opened *before* its covering
   mount existed (or before a sub-path was upgraded to rw) keeps
   pointing at the old `struct path`; a later mount layered on top is
   invisible to it.

The redesign avoids `MNT_DETACH` in the steady state, uses `move_mount`
choreography to preserve `struct mount` identity, and upgrades held fds
on demand where identity preservation isn't enough.

## Core ideas

### 1. Scratch tmpfs shadowed beneath root_tmpfs

The *scratch* tmpfs introduced here is **not** the existing
`root_tmpfs` that holds the placeholder hierarchy.  `root_tmpfs` is
created in `m0` and later bind-mounted into m1's `/` (step 4 below) on
top of the now-shadowed scratch.  The scratch is a separate, brand-new
tmpfs whose sole purpose is to be a hidden, m1-owned parent into which
mounts can be parked (see §6 `Unmount`); the app never sees it.

At sandbox init, in `m1` (the inner mount namespace):

1. `fsmount(tmpfs)` → a *new* scratch tmpfs (distinct from
   `root_tmpfs`).
2. `move_mount(scratch_fd, "", AT_FDCWD, "/", MOVE_MOUNT_F_EMPTY_PATH)`:
   the scratch becomes m1's root.  It now belongs to m1 (`check_mnt`
   passes) so it can serve as a target parent for future `move_mount`s.
3. `openat("/", O_PATH | O_DIRECTORY | O_NOFOLLOW)` → `m1_scratch_fd`,
   kept in `BindMountSandbox` for the sandbox's lifetime.
4. Bind-mount `root_tmpfs` (the m0-created placeholder tmpfs) over `/`.
   The scratch is now shadowed beneath; the app sees only the
   placeholder tmpfs.

The app cannot reach the scratch via path walks (`/` resolves to the
`root_tmpfs` bind mount; `..` at `/` stays at `/`) and has no mount
privileges to peel back that bind mount.  `m1_scratch_fd` resolves to the
scratch from the supervisor side and is the dirfd we use when parking
mounts.

### 2. Unified mount tree

`current_mount_tree: Mutex<FsTree<MountInternal>>` holds every active
bind mount.  Each reconcile decides what to do with each entry by
diffing against the desired tree; the kernel's `EBUSY` on a
non-`MNT_DETACH` `umount2` is the source of truth on whether an entry
is still in use.

```rust
struct MountInternal {
    user: ManagedMountPoint,  // host_path + currently-applied attrs
    mnt_id: u64,              // kernel mnt_id captured at mount-creation time
                              // (statx STATX_MNT_ID via a forked m1 helper);
                              // used for fd-staleness checks (§11) and
                              // mountinfo refresh (§13).
    expired: bool,            // set by refresh when mountinfo shows the bind
                              // source as `//deleted`; forces umount-and-readd
                              // on the next reconcile if still desired.
    // No cached mount fd — see §9.
}
```

User-facing APIs accept `ManagedTreeEntry` / `ManagedMountPoint`; the
internal fields are not exposed.

### 3. Covering a child: `move_mount` the old child into the new parent

The recurring hard case is **adding a mount that covers an existing
sub-mount**.  Example: `/home/mao/turnstile` is already bind-mounted
`rw`, and we now want to additionally grant `ro /home`.  Naively
bind-mounting the host `/home` at `/home` *shadows* the old layout: the
existing `/home/mao/turnstile` mount is buried beneath the new bind
mount, the app can no longer reach it, and any cwd / fd inside it is
stranded.

The key idea is that we do **not** unmount-and-recreate the child
(which would change its `struct mount` identity and break held fds —
problem 1 above).  Instead we keep the child's *original* mount object
and re-expose it inside the new parent:

1. While the child is still reachable, grab an `O_PATH` handle to it in
   m1: `fd1 = openat2("/home/mao/turnstile", O_PATH)`.
2. Bind-mount the host parent at `/home` (this shadows the old layout).
3. `move_mount(fd1 → "/home/mao/turnstile")` — the path now resolves
   *inside* the new `/home` bind mount (whose backing host fs naturally
   has the `mao/turnstile` dentry to mount on), and the **same** child
   `struct mount` is reattached there.

The child is visible again at the same path with identical identity:
held fds, cwd, and `..` traversal across it all keep working.

**Ordering is load-bearing.**  The child handle must be opened in
step 1 *before* the parent shadows it in step 2 — once the new bind
mount is in place, a fresh path walk can no longer reach the now-buried
child.

This "open child → shadow parent → move child back" choreography is
what the plan's `Mount` op (planned in §4, executed in the §7 `Added`
cascade) does whenever the mount it adds covers an existing sub-mount.
The same move_mount-to-preserve-identity trick also backs the plan's
`Unmount` op (§6, parking children while unmounting a parent) and the
host_path replacement path.  In this document **`Mount` and `Unmount`
always mean these full child-aware operations**, not the bare
bind-mount / `umount2` syscalls.

### 4. Plan-then-execute reconcile

A single diff event is sometimes not enough to describe an action
(e.g. "rebuild a parent while preserving its children").  Reconcile
therefore runs in two stages:

1. **Plan**: walk the diff and emit `HighLevelOp`s into a `Vec`.
2. **Execute**: process the list in order, each op as one m1 helper
   round-trip.

Because the children to move are always derivable from the live mount
tree, the plan stores only paths, never child lists; each op
rediscovers its children at execute time from `new_mt` — a clone of
`current_mt` made at the start of reconcile and mutated as each op runs,
so it always reflects the mount layout *as of the current point in the
plan*.  This keeps the plan a flat
list and lets `Mount` / `Unmount` each subsume what would otherwise be
two ops: a `Mount` whose path covers no sub-mount is a plain bind
mount, and an `Unmount` with no kept children is a plain `umount2`.

**Invariant: no tracked mount is ever left path-shadowed.**  Child
rediscovery works by *opening the child's path* in m1, so a child left
buried under a shadowing mount would be unreachable — or a lookup would
grab the shadowing mount instead.  `Mount` shadows a child only
transiently (between the parent bind and the child `move_mount`, inside
one op under the tree lock, never observed) and ends with every child
re-exposed on top; `Unmount` restores its parked children onto the
placeholder layer we control; `ReplaceHostPath` `MNT_DETACH`es a busy
old mount rather than shadowing the new host over it.  The only child
that can't be re-exposed — its mountpoint dentry missing from the new
parent's host fs — is dropped, never shadowed (see §7).

`HighLevelOp` variants (every op below is one entry in the plan `Vec`;
`Mount` and `Unmount` always perform the child choreography of §3):

- `CreatePlaceholder(path, placeholder)` / `RemovePlaceholder(path)`
- `SetAttr(path, new_attrs, old_attrs)`
- `Mount(path, host, attrs)` — bind-mount `host` at `path` (over
  its current location, shadowing whatever layout is there), then
  `move_mount` each *existing direct sub-mount* of `path` — discovered
  from `new_mt` at execute time — onto its own path inside the new bind
  mount (§3).  No scratch needed.  With no sub-mounts this is a plain
  bind mount.  Opening the fds for the direct submounts before mounting
  the new mount is important (see §7).
- `Unmount(path)` — the inverse.  `move_mount` **every** direct
  sub-mount under `path` in `new_mt` (the topmost mounts beneath it —
  e.g. with mountpoints `/a/b`, `/a/b/c/d`, `/a/b/c/d/e/f`, the only
  direct sub-mount of `/a/b` is `/a/b/c/d`, which carries `/a/b/c/d/e/f`
  along when moved) to `scratch/<uuid>`, then `umount(path)` non-detach.
  Note this parks *all* present sub-mounts, not just still-desired
  ones: an undesired child whose own `Removed` op hasn't run yet is
  still in `new_mt` and still mounted, so we must move it out of the
  way too — otherwise it would pin `path` and the umount would EBUSY for
  a reason that has nothing to do with the app.  With everything under
  `path` parked, the only thing that can still pin `path` is the app
  itself (an open fd or cwd on `path`'s own files):
    - Success: recreate the placeholder hierarchy on the revealed layer
      and `move_mount` the parked descendants back (each will later be
      re-evaluated or removed by its own op).
    - EBUSY (app holds `path`): keep `path`, restore the parked
      descendants under it, and emit `SetAttrToCovering` for `path` and
      each restored descendant.
  With nothing mounted under it this is a plain `umount2` (on EBUSY →
  `SetAttrToCovering(path)`).
- `ReplaceHostPath(path, new_host, new_attrs)` — park any children to
  scratch, then `MNT_DETACH` the old bind unconditionally (its identity
  is being discarded anyway, so there's no reason to branch on EBUSY:
  if unheld the kernel reclaims it at once, if held the app's fds keep
  reading the old host until they close — nothing left shadowed. (see
  Limitation #1)).  Then `Mount(path, new_host, new_attrs)` to overlay
  the new host over `path` and restore the parked children onto it.
- `SetAttrToCovering(path)` — for an entry we tried but failed to
  remove: set its attrs to those of the deepest desired entry that is
  a prefix of `path`, or `ro,noexec` if none covers.

### 5. Diff settings

- `split_on` returns `true` on `host_path` mismatch.  The diff then
  emits `Removed(P)` (bottom-up) followed by `Added(P)` (top-down) for
  `P`; the planner pairs these into a `ReplaceHostPath`.
- `split_on_one_side = false`, so children common to both sides of an
  `Added`/`Removed` parent are still visited as `Updated` — required
  for `Mount` to enumerate them.

### 6. `Removed` cascade

For each `Removed(P)`: emit `Unmount(P)`.  Order does **not** matter for
correctness, because `Unmount(P)` effectively "surfaces" any child mounts,
so `umount(P)` EBUSYs only when the app itself holds `P`.  Any parked
descendant that was move_mount'd back but is actually removed in the
desired tree is simply removed by its own op later (its mount is still in
`new_mt` until then).  An app-held `P` is kept and locked down via
`SetAttrToCovering`; a later reconcile retries once the app lets go
(eventual consistency).

**Optional optimisations** (neither needed for correctness):

- *Process deepest-path-first.*  Sorting the `Unmount` ops by depth
  (descending) means a fully-removed subtree is torn down leaf-first,
  so each parent finds its to-be-removed children already gone and
  parks fewer mounts.  This is purely a `move_mount`-count saving.

  This does not rely on `FsTree::diff`'s emission order.  (For reference,
  diff emits a removed subtree bottom-up only when the *entire* subtree is
  left-only; a removed node on a path with surviving descendants is
  emitted top-down — e.g. diffing `{ /home/mao, /home/mao/turnstile,
  /home/mao/turnstile/target }` against `{ /home/mao/turnstile/target }`
  yields `Removed(/home/mao)` then `Removed(/home/mao/turnstile)`.  Since
  correctness doesn't depend on order, this doesn't matter.)

### 7. `Added` cascade

For `Added(P)`: emit `Mount(P, host, attrs)`.  The op (§4) discovers
the direct (immediate, not transitive) sub-mounts of `P` in `new_mt` at
execute time and re-exposes them inside the new bind mount; ancestor
placeholders are already created in phase 1 of reconcile.  With no
sub-mounts this is a plain mount.

**Ordering is load-bearing** (restated from §3).  Within the op the
child `O_PATH` fds must be opened *before* the parent bind-mount: once
the new parent shadows the old layout, a path lookup to a child
resolves through the new bind mount and can no longer reach the old
(now-shadowed) child mount.  Execute order: open all child `O_PATH` fds
in m1 → bind-mount parent → `move_mount` children → close child fds.

**Child not reachable through the new parent's host fs.**  `Mount(P)`
may rediscover a child at `P/foo` while the new parent's host fs has no
`foo` dentry, so the child can't be `move_mount`ed into the new bind
mount.  This never leaves a shadowed mount, by cases:

- **The child's mountpoint is on a real (bind-mounted) host fs.**  A
  missing `foo` means the host directory entry is gone, so the child
  mount is already doomed — its mountpoint disappeared.  The mountinfo
  refresh that runs *before every reconcile* (§13) no longer finds it
  and drops it from the tree, so it never reaches the `Mount` op in the
  first place.  Nothing to do.
- **The child is a bind mount on the placeholder tmpfs.**  There is no
  real dentry to move it onto, so we `umount` it with `MNT_DETACH`.
  Any app fd / cwd still on it keeps it alive (with `..` broken, just
  as if the child's mountpoint is removed from the host) and the kernel
  reclaims it once the last reference drops — no shadowed mount to
  remember or clean up.

### 8. `Updated` cascade

For `Updated(P)` (host_path matches, attrs differ): emit `SetAttr(P,
new, old)`.  Children drive their own ops via their own diff events.

### 9. No cached mount fds

A cached mount handle (`open_tree`/`O_PATH`) held in the supervisor
would pin the mount, so a non-`MNT_DETACH` `umount2` would always
EBUSY on our own reference.  We'd then have to drop the fd before each
umount attempt and re-open on failure — expensive in the common "app
is using it" case.  Instead, every mount-fd-requiring operation opens
lazily from the m1 fork (one `openat2` per op), which is cheap at
interactive rates.

### 10. Symlink mirroring

The placeholder tmpfs mirrors host symlinks along ancestor paths
(`mirror_intent_path_symlinks`) so pre-resolution paths stay meaningful
for the read-only `*at` syscalls (§11) where the supervisor lets the
kernel resolve a relative path from the dirfd's mount.

### 11. Integrated tracer with per-request fd upgrade

Mount-identity preservation (§3) keeps *already-open* fds working across
layout changes, but it cannot by itself *widen* an fd's access.  An fd's
`struct file` pins a `(mnt, dentry)` pair at open time, and the mount in
that pair fixes the access (`mount_attr`s) the fd gets — a later mount
layered on top is invisible to it.  Concretely: with only `/a` mounted
`ro`, the app opens `/a/b/c`, getting an fd whose `f_path` is
`(mnt=/a, dentry=b/c)` — read-only.  If we now grant write by mounting
`/a/b` `rw`, the app's existing fd still points at the old `ro` `/a`
mount and keeps failing writes; only a path lookup *started after* the
new mount would resolve `/a/b/c` through the `rw` `/a/b` mount.

The fd-upgrade machinery closes that gap: when a request needs an fd to
reflect a newly added/widened covering mount, the supervisor reopens the
same abspath in m1 (so it resolves through the *current* layout, e.g.
`(mnt=/a/b, dentry=c)` — now `rw`), verifies it is the same inode
(§11.3), and hands the fresh fd to the app via `SECCOMP_IOCTL_NOTIF_ADDFD`
— either as the syscall's returned fd (`openat`) or by replacing the
app's dirfd/file fd in place (`ADDFD_SETFD`).

#### 11.1 Tracer ownership

`ManagedBindMountSandbox` owns the `TurnstileTracer`:

```rust
impl ManagedBindMountSandbox {
    pub fn yield_request(&self)
        -> Result<Option<(Request<'_>, RequestHandle<'_>)>, AccessRequestError>;
}

pub struct RequestHandle<'a> { /* req ctx + resolved request */ }

impl RequestHandle<'_> {
    pub fn target(&self) -> &ResolvedRequest;
    pub fn allow(self) -> Result<(), Error>;
    pub fn deny(self, errno: i32) -> Result<(), Error>;
}
```

Workflow: user / the turnstile-sandbox bin calls `yield_request`, inspects
`target()`, optionally calls `update_from_tree` / `update_from_list` to
change mounts, then `allow()` or `deny(errno)`.  The library never
auto-mounts based on a request — but `allow()` may transparently "upgrade"
fds or proxy a syscall so the app's view matches the live mount layout.

#### 11.2 What `allow()` does, by syscall

The choice between an `ADDFD_SETFD` **swap** (replace the app's fd with a
fresh one resolved on the current layout) and a **proxy** (perform the op
supervisor-side in m1 and return its result, leaving the app's fd
untouched) comes down to one thing — **is the fd upgradable?** — *not*
whether the call is an `f*` or an `*at`:

- **Upgradable**: a *directory* fd (or an `O_PATH` fd).  It carries no
  read/write `f_pos` or open state we'd lose by swapping; the only
  casualty is a `getdents` cursor reset (Limitation #5).
- **Unupgradable**: a *regular-file* fd (and other types).  Swapping
  would clobber `f_pos`, open flags, locks, mmap backing — so the design
  never touches it, and we proxy instead.

So whenever a syscall's access is governed by a held fd whose `mnt_id`
is stale, we swap it if it's upgradable and proxy it if not.  An
`*at(dirfd, "nonempty")` is simply the case where the governing fd is
*guaranteed* a directory → always upgradable → always swapped (never
proxied); `f*` / `*at(fd, "", AT_EMPTY_PATH)` is the case where the fd
may be either, so the fd's *type* decides.

Upgradability is read from the app's fd directly: directory-ness from
`statx` (`S_ISDIR`) and `O_PATH`-ness from the `flags:` field of
`/proc/<pid>/fdinfo/<fd>` (§11.3).  The two roles an `O_PATH` fd can play
are handled differently:

- **As an `f*` target** (`fchmod(fd)` / `fchown(fd)` / `fsetxattr(fd)` /
  an `AT_EMPTY_PATH` op): the kernel rejects it with `EBADF` regardless
  of the mount layout, so we neither swap nor proxy — just CONTINUE and
  let it fail natively.
- **As an `*at` dirfd**: a legitimate use; if the dirfd is stale we
  swap-upgrade it like any directory fd (an `O_PATH` fd is swap-safe —
  no `f_pos`/state to lose).

So the only fd that ever *proxies* is a non-`O_PATH` *regular-file* fd,
and the swap-vs-proxy choice really comes down to `S_ISDIR`.

**`ftruncate` is exempt entirely — always a plain CONTINUE, never proxied
or swapped.**  Unlike `fchmod`/`fchown`/`fsetxattr`/`fremovexattr` (which
run fine on a *read-only* fd and only need the *mount* writable, so a
stale ro-fd whose rw cover is a separate leaf mount still needs the
proxy), `ftruncate` needs a *writable* fd (`FMODE_WRITE`; a read-only fd
is `EINVAL`, an `O_PATH` fd `EBADF`).  A writable fd can only have been
opened on a **rw** mount (`O_WRONLY`/`O_RDWR` on a ro mount is `EROFS` at
open), and that mount cannot then be downgraded to `ro` while the
writable fd is open (remount-ro / `mount_setattr` with active writers is
`EBUSY`).  So an `ftruncate` target fd is *guaranteed* to still sit on a
writable mount: CONTINUE truncates correctly, and the not-writable cases
reproduce the very `EINVAL`/`EBADF` the app would get natively.

| Syscall | Action in `allow()` |
|---|---|
| `openat` / `openat2` | Always returns a *fresh* fd: re-resolve abspath, open in m1 with the requested flags, identity-check, hand back via `ADDFD` — so the result is anchored on the current layout regardless of the dirfd's mount. |
| `chdir` / `fchdir` | Ensure a bind mount exists on the target (§11.5), then CONTINUE.  (cwd itself can't be swapped — §11.5.) |
| Access governed by a held fd whose `mnt_id` is stale — the dirfd of an `*at(dirfd, relpath)`, or the target fd of an `f*` / `*at(fd, "", AT_EMPTY_PATH)` (`fchmod`/`fchown`/`fsetxattr`/`fremovexattr`/…; **not** `ftruncate` — always CONTINUE, see above) | m1-open the fd's abspath, identity-check, then: **upgradable** (dir / `O_PATH` dirfd) → `ADDFD_SETFD`-swap at the same fd number and CONTINUE (the kernel then resolves / acts through the live layout); **unupgradable** (regular file, …) → perform the op in m1 and return via `notif_resp`, don't touch the app's fd.  (An `f*` whose *target* fd is `O_PATH` is neither swapped nor proxied — CONTINUE; it fails `EBADF` natively.) |
| Path-based `chmod`/`chown`/`truncate`/`setxattr`/`removexattr` resolved from `/` (absolute) or cwd (`AT_FDCWD`) | The kernel resolves the path afresh on CONTINUE against the live layout, so it lands on the current mount; no proxy.  (cwd is kept current by §11.5, with that section's caveat.  An `*at(dirfd, relpath)` form instead resolves from `dirfd` and rides the held-fd row above.) |
| Anything else | CONTINUE. |

Because `*at(dirfd, "nonempty")` always carries a directory dirfd, it is
always swap-upgradable; the only ops that ever proxy are `f*` /
`AT_EMPTY_PATH` ops landing on an unupgradable (regular-file) fd.
Swapping a dirfd has the usual trade-off — an in-progress
`getdents`/`getdents64` loop on that fd may see duplicates (the swapped
fd is at `f_pos = 0`), see Limitation #5 — which is one reason we *could*
also choose to proxy an upgradable `f*` on a dir fd; the table upgrades
it for uniformity with the `*at` path.

#### 11.3 fd identity check

Every supervisor-side reopen verifies inode identity:

```rust
let (exp_dev, exp_ino) = app_fd_proxy.inode_id()?;   // pidfd_getfd + statx
let new_fd = m1_helper.openat2(abspath, flags)?;
if new_fd.inode_id()? != (exp_dev, exp_ino) { /* retry once */ }
```

After 2 mismatched retries: log `error!` and fail closed —
`openat`/`f*`-proxy return `EIO`; a dirfd upgrade is skipped (plain
CONTINUE without replacement).

**Exception — a dirfd that resolves to `/`.**  When the held dirfd being
re-resolved is the sandbox root itself (its `/proc/<pid>/fd/<n>` readlink
is `/`), the reopen skips the identity check and simply `dup`s the target
root fd.  The app's `/` and the supervisor's target root are *legitimately
distinct inodes* (the app sees the `root_tmpfs` bind mount; the reopen
root is a separate handle), so an identity comparison there would
spuriously fail — yet "the root, re-resolved under the new root" is by
definition just that new root.

The other per-fd properties the upgrade path needs are also read
supervisor-side from the app's fd: the staleness key (`mnt_id`) and the
open flags (for the `O_PATH` upgradability test, §11.2) both appear in
`/proc/<pid>/fdinfo/<fd>` — `mnt_id:`, `ino:`, and `flags:` (octal
`file->f_flags`, in which `O_PATH` is preserved) — so a single fdinfo
read covers them.  `fdinfo` carries `ino` but not `st_dev`, so the
full `(dev, ino)` identity check above still goes through `statx` on
the `pidfd_getfd`'d fd.

#### 11.4 Why m1, not m0

Every supervisor-side open for the proxy/upgrade path runs inside m1
(via a forked helper that `setns`es into m1), resolving through m1's
mount layout.  Opening from m0 (the supervisor's host view) would use
the supervisor's own credentials and could reach paths the sandbox is
not supposed to see; doing it in m1 makes the sandbox's own mount
layout and `mount_attr`s authoritative, so we cannot accidentally
over-grant.

#### 11.5 `AT_FDCWD` and cwd

`AT_FDCWD` can't be upgraded — there's no fd number, and the kernel
resolves it from the task's `fs_struct.pwd`, which is not addressable
from the supervisor.  So cwd is handled preemptively:

- `chdir(path)` / `fchdir(fd)` is intercepted in `allow()`.  Before
  CONTINUE, ensure a bind mount exists *exactly at* the resolved target
  (a mount only at an ancestor is not enough: a later attribute change
  must reach the existing cwd handle, and reconcile must be able to
  preserve the cwd mount's identity rather than detach it):
  - A mount already exists exactly at the target → no action.
  - Covered only by an ancestor mount → add a bind mount at the target,
    reconcile, then CONTINUE: inherit that mount's attrs and bind its
    `host_path` joined with the relative suffix, so the cwd keeps seeing
    the same host subtree and is not over-restricted.
  - No covering mount → the policy does not grant this chdir, so do
    nothing and CONTINUE (the syscall then fails / is handled by the
    caller's deny).
- This implicitly means that every `chdir` requires read access on the target.
  The caller needs to add the correct policy rules (which may be granting a parent),
  otherwise we should fail with `EPERM`.

The host fs is guaranteed to have the dentry to mount on: the only
preemptive mounts are `chdir` targets, whose existence the app already
established (else its chdir would have ENOENT'd before reaching
seccomp).

Impact: cwd churn (`cd a; cd b; cd c`) accumulates a mount per target.
These are **not** reclaimed automatically — there is no background GC.
A mount is only removed when the caller updates the desired tree to drop
it and triggers a reconcile, at which point the diff finds it present in
`current_mt` but absent from the desired tree and emits an `Unmount` for
it (which still succeeds only once the app's cwd / fds let go).

#### 11.6  `execve` and `mmap(PROT_EXEC)`

- **`fexecve` / `execveat(fd, "", AT_EMPTY_PATH)`** and **`mmap(
  PROT_EXEC, fd, ...)`** with `fd` opened on a `noexec` mount: the
  kernel checks `path_noexec(&file->f_path)` against the fd's mount and
  fails.  We could SETFD-replace the fd (exec has no `f_pos` concern),
  but it carries the app's open flags/state, so we leave it for now.
  Workaround: grant exec before the open, or re-open by abspath.  See
  Limitation #4 and the TODO.
- **`execve("/abs", ...)`** and **`execveat(AT_FDCWD, "/abs", ...)`**
  re-resolve from `/` and see the latest layout — no upgrade needed
  (after an exec grant + reconcile, CONTINUE replays successfully).
- **`execveat(dirfd, "relpath", ...)`** resolves from `dirfd`; the
  dirfd-upgrade path (§11.2) covers it.

#### 11.7 No "interactions tree"

There is no separate interaction-tracking state.  The only
mount-related state besides the policy is `current_mount_tree`.  When
the bin wants a mount in response to a request, it calls
`update_from_tree` / `update_from_list` between `yield_request` and
`allow`/`deny`.  fd staleness is handled orthogonally by the
upgrade-in-`allow()` machinery.  The sole exception is `chdir`/`fchdir`
(§11.5), where the library must act before letting the syscall through.

## 12. Syscalls that the bind-mount layout could corrupt

- **`linkat` / `renameat` / `renameat2`** across two *different* sandbox
  mounts spuriously fail with `EXDEV`, even when both are bind mounts of
  the **same** underlying fs (same superblock).  The syscall wrappers
  `do_linkat` / `do_renameat2` check `old_path.mnt != new_path.mnt` and
  bail with `EXDEV` *before* `vfs_link` / `vfs_rename` run — so the
  superblock-equality check inside those vfs helpers is never reached.
  Natively (a single host mount) the same operation would succeed, so
  splitting one host directory across several bind mounts can break
  link/rename that the app expects to work.  Within a *single* sandbox
  mount (`old_path.mnt == new_path.mnt`) it works normally.  A correct
  fix would proxy the op in m1 against a layout where both paths live
  under one mount; not done here (documented corner case).
- **`unlinkat` / `rmdir`** of a path that we have bind-mounted returns
  `EBUSY` (it's a mountpoint).  This only happens if the policy granted
  access to a mountpoint dir and the app tries to delete that exact
  path.  Rare; left as a documented corner case (proxying it via m0
  would mean deleting a path the policy grants access to — odd
  semantics).

No host-side (m0) proxying is part of this design.  If a future need
arises (e.g. linkat / renameat across bind mounts, or unlinking a
mountpoint), it can be added behind an explicit opt-in, but it is out of
scope here.

## 13. Refreshing the mount tree from `/proc/<pid>/mountinfo`

The host fs can change under an active sandbox.  In particular the
source dentry backing one of our bind mounts can be unlinked while the
mount is still alive:

- The mount keeps working either way (the kernel pins the inode; the
  source dentry stays valid whether it was renamed or
  unlinked-while-mounted).
- `/proc/<pid>/mountinfo`'s root field (field 4) tracks the source
  dentry's live location within its superblock:
  - **unlinked** (`rm` / `rmdir` of a still-mounted source) → the field
    gains a trailing `//deleted` (it's now a `d_unlinked()` dentry).
  - **renamed** (`mv`) → the field shows the *new* source path; the
    dentry is alive, so there is **no** `//deleted` marker.

Only the **unlinked** case sets `expired`.  Its point is to *recreate* a
mount whose source no longer exists, so that if the host later puts a
fresh file/dir at the original `host_path` the sandbox picks it up (an
unlinked-but-mounted inode would otherwise keep serving stale,
now-orphaned contents forever).  A rename is **not** expired — the
source still exists (just elsewhere) and the mount keeps serving it
correctly — but the refresh does update the entry's recorded `host_path`
to the new location so it stays accurate for a later re-bind /
`ReplaceHostPath`.

The app's syscalls don't reveal an unlinked source, so we refresh from
mountinfo on demand and before each reconcile.

### Storage

Each `MountInternal` records the mount's kernel `mnt_id` (captured at
creation via `statx(STATX_MNT_ID)` from the m1 helper).  It doubles as
the staleness key for fd upgrades (§11) and the join key for refresh.

### When to refresh

- **Before every reconcile diff** — so the diff input is
  kernel-truthful.
- **On suspected staleness** — when a request looks not-covered,
  refresh before concluding that it's actually not covered and letting
  the caller know.  Catches "host dir moved out from under our mount,
  so the path is no longer reachable".
- Optionally on a timer for long-running sandboxes.

### How to refresh

1. Fork a short-lived helper (the same fork-then-`setns`-into-m1
   pattern every m1 op uses), have it read its own
   `/proc/self/mountinfo` (now m1's view), write the bytes back over the
   socket, and exit.  No long-lived process is kept around.
2. Parse each line into `(mnt_id, parent_mnt_id, root_from_fs,
   mountpoint_in_ns, options, …)`.
3. Build a fresh `new_current_mt`:
   - mnt_id present in old `current_mt` → copy its `MountInternal` to
     `new_current_mt` at the mountinfo `mountpoint_in_ns` (the path may
     have moved if a parent moved).
   - mnt_id in old `current_mt` but absent from mountinfo → the mount
     is gone (see below); drop it.
   - `root_from_fs` ends in `//deleted` (source unlinked) → copy with
     `expired = true`.
   - `root_from_fs` shows a *different* path than the recorded
     `host_path` (source renamed) → copy with its `host_path` updated to
     the new `root_from_fs`, **not** `expired`; the mount still works,
     and keeping `host_path` accurate means a later `ReplaceHostPath` /
     re-bind targets the real source.
4. Replace `current_mt` with `new_current_mt`.

**Expired entries** (the bind source was unlinked on the host —
`//deleted` — while the mount is still alive) are always re-evaluated on
the next reconcile:

- Still desired with the same `host_path` → `Unmount` +
  `Mount` (the fresh `openat2` of `host_path` succeeds if the host
  recreated the dentry, else ENOENT — propagate the error so the policy
  author can fix it).
- No longer desired → treat as `Removed`.
- Desired with a new `host_path` → `ReplaceHostPath`.

**Mount-gone entries** (mnt_id absent from mountinfo) are dropped with
no further action.  Causes: an external host process unlinked the
mountpoint dentry directly (a plain `unlink` from another mntns
suffices — no mount privilege needed); or an earlier
`forcibly_remove_mount` (`MNT_DETACH`).

### Concerns

- **Parsing.**  mountinfo is documented but quirky (octal-escaped
  paths).  A small hand-rolled parser for the few needed fields
  suffices.
- **Parked entries are always transient.**  The scratch is only ever
  used *within* a single op (parking a child for the duration of an
  `Unmount` / `ReplaceHostPath`, then moving it back out before the op
  returns); there is no durable `scratch/<uuid>` state.  Since reconcile
  holds the tree lock for the whole op and refresh runs only between
  reconciles, a refresh never observes a mid-park `scratch/<uuid>`
  entry.

## Assumptions

1. `fs.mount-max` is comfortably larger than the working set of mounts.
2. Kernel ≥ 5.12 for the full `open_tree` / `move_mount` / `fsmount` /
   `mount_setattr` set; `SECCOMP_IOCTL_NOTIF_ADDFD` needs ≥ 5.9.

## Limitations

1. **`ReplaceHostPath` on a busy mount isn't immediate revocation.**
   `ReplaceHostPath` `MNT_DETACH`es the old mount and mounts the new
   host cleanly on the revealed layer (nothing left shadowed); if the
   old mount is held, those fds keep reading the *old* host until they
   close, then the kernel reclaims the detached mount.  For immediate
   revocation, kill the app (`forcibly_remove_mount` with `MNT_DETACH`
   of the subtree is the opt-in escape hatch).
2. **Scratch parking briefly breaks `..` from inside a parked mount.**
   The library does not service notify requests during the parking
   window (reconcile holds the tree lock).
3. **`fs.mount-max` bounds accumulated mounts.**  No GC thread.  A
   mount is freed only when the caller drops it from the desired tree
   and a reconcile emits an `Unmount` for it; until then (e.g. churned
   `chdir` targets) it stays in `current_mt`.
4. **Exec via pre-grant held fds fails.**  `fexecve(fd)` /
   `execveat(fd, "", AT_EMPTY_PATH)` / `mmap(PROT_EXEC, fd, …)` check
   `path_noexec` against the fd's mount; if it was `noexec` at open
   time and exec was granted later, the held fd doesn't see it.
   Workarounds: re-open by abspath after the grant (the `openat` proxy
   returns a fresh fd), or grant exec before the open.  TODO: consider
   SETFD-replacing the fd for `fexecve` (no `f_pos` concern).
5. **Mid-`getdents` dirfd replacement causes duplicates / misses.**  A
    replaced non-`O_PATH` dirfd starts at `f_pos = 0`; an app
    interleaving `getdents` with modifying `*at`s on the same dirfd may
    re-see early entries or miss some.  Rare; the library logs a
    `warn!` on each non-`O_PATH` dirfd replacement.
6. **f\* modifying ops on a stale *regular-file* fd are proxied, not
    transparent.**  A regular-file fd is unupgradable (§11.2), so
    `fchmod`/`fchown`/`fsetxattr`/`fremovexattr` on a stale
    one run against the abspath in m1.  If the
    abspath now resolves to a different inode, the op hits the current
    inode, not the app's pinned one; the identity check (§11.3) catches
    the common case, but a race remains.  m1 errors map 1:1 to the
    syscall return.  (`ftruncate` is exempt — §11.2: a writable fd
    implies a still-writable mount, so it always CONTINUEs.)

## Changes needed (relative to current code)

### `BindMountSandbox`

- `new(...)`: insert the scratch-tmpfs step between namespace creation
  and the `root_tmpfs` bind mount; store `m1_scratch_fd: ForeignFd`.
- `park_to_scratch(path, uuid)` / `restore_from_scratch(uuid, dest)`.
- `unmount(path)`: non-`MNT_DETACH` by default; add a `forcibly: bool`.
- `open_in_m1(path, openhow) -> Result<ForeignFd>`: fork helper, setns
  into m1, `openat2`, send the fd back.  Backs the upgrade/proxy path.
- `read_m1_mountinfo() -> Result<Vec<u8>>`: fork helper, setns into m1,
  read `/proc/self/mountinfo`, send the bytes back.  Backs the §13
  refresh.
- `set_mount_attr(path, new, old)`: unchanged.

### `ManagedBindMountSandbox`

- Owns `TurnstileTracer`; exposes `yield_request → (Request,
  RequestHandle)`.
- `RequestHandle::allow()` dispatches per §11.2; `deny(errno)` sends an
  error.
- `current_mount_tree` value type → `MountInternal` (`mnt_id`,
  `expired`).
- `update_from_tree` / `update_from_list`: same signatures; internally
  refresh from mountinfo before diffing.
- `reconcile`: rewritten as plan-then-execute.
- New `FsTree` helper:
  ```rust
  // Walk data entries under `root` top-down.  With `topmost_only`, stop
  // descending into a branch once its first data entry is visited (the
  // "direct-most" descendants — e.g. the topmost sub-mounts of a path);
  // otherwise visit every data entry in the subtree.
  pub fn walk_subtree_top_down<F>(&self, root: &OsStr, topmost_only: bool, f: F);
  ```

### `ForeignFd`

- `pub fn inode_id(&self) -> Result<(dev_t, ino_t)>`.
- `pub fn mnt_id(&self) -> Result<u64>` (statx `STATX_MNT_ID`).

### `turnstile-sandbox` bin

- Loop simplifies to: `yield_request` → inspect → either
  `update_from_list` + `allow()` (granted) or `deny(EPERM)` (denied).
  No per-syscall categorization in the bin.
- `--permissive`: on a not-covered request, auto-`update_from_list`
  with the requested attrs, then `allow()`.

### `design.md`

Replace with this document once the approach is committed.

## Open questions

- **A. Concurrency.**  `yield_request` may return to multiple worker
  threads; `allow`/`deny` are independent.  `update_from_*` takes the
  trees write lock; the upgrade/proxy machinery in `allow()` takes only
  a read lock on `current_mt` for mnt_id checks.  So allows proceed in
  parallel except briefly while an `update_from_*` holds the write
  lock.
- **B. Crash recovery.**  Single-process; namespaces die with the
  supervisor; no external state to reconcile.
- **C. Propagation.**  `fsmount` mounts are private; we never set
  `MS_SHARED`, so host mount changes don't propagate in.
- **D. fexecve / mmap PROT_EXEC upgrade** (Limitation #4 TODO): if
  pursued, open the same abspath with the fd's flags (read from
  `/proc/<pid>/fdinfo/<n>`) in m1 and SETFD-replace, with the same
  identity check.  Deferred until needed.

---

# Scenario walk-throughs

Notation: `policy` = explicit desired tree; `current_mt` = active
mounts at the start of the step.

## Case 1 — Add a parent over an existing child (cwd inside child)

**Initial**: `policy = { /a/b/c: rw }`, `current_mt = { /a/b/c: rw }`,
cwd = `/a/b/c`.

**Event**: app opens `/a/b`; the bin grants `/a: rw` and
`update_from_list`s it.

**Reconcile**: `Added(/a, rw)`, `Updated(/a/b/c, rw, rw)`.  `Added(/a)`
→ `Mount("/a", rw)`; at execute time the op finds `/a/b/c` as a
direct sub-mount in `new_mt` and re-exposes it.  The `Updated` is a
noop.

**Execute `Mount`** (ordering matters):
1. `fd1 = openat2("/a/b/c", O_PATH)` in m1 (child still reachable).
2. Bind-mount host `/a` at `/a` rw (shadows the old layout).
3. `move_mount(fd1 → "/a/b/c")` (resolves in the new bind mount).
4. `close(fd1)`.

**Outcome**: `/a` rw; `/a/b/c` is the *same* `struct mount`, now on the
new `/a` bind mount's `b/c` dentry.  Cwd unchanged; `..` from cwd reaches
the new `/a/b`.  Open of `/a/b` succeeds.  **Expected.**

**Variant — policy becomes just `{ /a: rw }`**: diff is `Added(/a)`,
`Removed(/a/b/c)`.  `Mount("/a", rw)` still finds `/a/b/c` in
`new_mt` and moves it into the new bind mount (we don't yet know the umount
outcome); then `Removed(/a/b/c)` → `Unmount("/a/b/c")` (no kept
children) → `umount` → EBUSY (cwd) → `SetAttrToCovering` applies `/a`'s
rw (noop); entry kept.  Next reconcile, once cwd moves, `/a/b/c`
umounts.

## Case 2 — Add a parent ro, rw child, `..` across mount

**Initial**: `policy = { /a/b/c: rw }`, `current_mt = { /a/b/c: rw }`,
cwd = `/a/b/c`.

**Event**: app opens `../d` (= `/a/b/d`); bin grants `/a/b: ro` and
`/a/b/d: ro,noexec`.

**Reconcile**: `Added(/a/b, ro)`, `Updated(/a/b/c)`, `Added(/a/b/d)`.
`Added(/a/b)` → `Mount("/a/b", ro)` (discovers child `/a/b/c`);
`Added(/a/b/d)` → `Mount("/a/b/d", …)` with no sub-mounts (a plain
mount).

**Execute**: `fd1 = openat2("/a/b/c", O_PATH)` → bind `/a/b` ro →
`move_mount(fd1 → /a/b/c)` → bind `/a/b/d` ro,noexec.

**Outcome**: `/a/b` ro with `/a/b/c` (same mount) and `/a/b/d` on top.
`..` from cwd reaches the new `/a/b`; `openat(cwd, "../d")` crosses
into `/a/b/d`.  **Expected.**

## Case 3 — Remove a parent, held child

**Initial**: `policy = { /a: ro, /a/b/c: rw }`, `current_mt` matching;
app holds an `O_PATH` fd on `/a/b/c/file`.

**Event**: remove `/a`.  `policy = { /a/b/c: rw }`.

**Reconcile**: `Removed(/a)`, `Updated(/a/b/c)` → `Unmount("/a")`;
at execute time it finds `/a/b/c` still desired under `/a` and keeps it.

**Execute**: `fd1 = openat2("/a/b/c", O_PATH)` → `move_mount(fd1 →
scratch/<uuid>)` → `umount("/a")` Ok → recreate placeholder dirs `/a`,
`/a/b/c` → `move_mount(fd1 → /a/b/c)`.

**Outcome**: `/a` is now a placeholder dir; `/a/b/c` is the same mount
on the placeholder.  The held fd still reads.  `..` from it reaches the
empty placeholder `/a/b` — correct, since `/a` was revoked.
**Expected.**

## Case 4 — Remove a parent, EBUSY on both parent and child

**Initial**: `policy = { /a: ro, /a/b: rw }`, `current_mt` matching;
app has cwd on `/a/b` and a held `O_PATH` fd on `/a`.

**Event**: `policy = { /a/b: rw }`.

**Reconcile**: `Removed(/a)` with kept child `/a/b` → `Unmount`.

**Execute**: park `/a/b` to scratch → `umount("/a")` → EBUSY (held fd
on `/a`) → restore `/a/b` under the still-live `/a` →
`SetAttrToCovering(/a)` (no cover → ro,noexec, noop).  Both kept; next
reconcile retries once the `/a` fd is dropped.  **Expected** (eventual
consistency).

## Case 5 — `chdir` into an uncovered dir

**Initial**: `policy = { /etc: ro }`, `current_mt = { /etc: ro }`, cwd
= `/etc`.

**Event**: app calls `chdir("/home/mao/turnstile")`.

**Behavior**: `yield_request` returns the chdir.  If the policy author
grants `/home/mao/turnstile: ro`, the bin `update_from_list`s it
(reconcile adds the mount), then `allow()` — which recognizes `chdir`,
confirms the target is now covered (≥ read), and CONTINUEs.  The cwd's
`struct path` becomes the new mount's root.  **Expected.**

**Variant — denied**: bin calls `deny(EPERM)`; the kernel returns
`EACCES`/`EPERM`.

## Case 6 — `openat(O_PATH)` on a regular file

**Initial**: `policy = { /lib: rx }`, `current_mt = { /lib: rx }`.

**Event**: `openat(AT_FDCWD, "/etc/passwd", O_PATH | O_NOFOLLOW)`.

**Behavior**: `O_PATH` needs no read at the kernel level.  The bin
decides whether to grant read (a later `/proc/self/fd/N` reopen could
read).  If granted, the bin `update_from_list`s the mount and
`allow()`s — the library re-resolves `/etc/passwd` via m1 `openat2`
with `O_PATH`, identity-checks, and `ADDFD`s the fresh fd back, so the
app's fd is on the new mount.  A later `openat(AT_FDCWD,
"/proc/self/fd/N", O_RDONLY)` resolves to abspath `/etc/passwd` and
goes through the same `openat` path, returning a readable fd on the
bind mount.  **Expected** — no preemptive mount is forced by a
resolve-only open.

## Case 7 — host_path change

**Initial**: `policy = { /work: rw → /tmp/work-a }`, `current_mt`
matching.

**Event**: policy updated to `/work: rw → /tmp/work-b`.

**Reconcile**: host mismatch → `Removed(/work → a)` + `Added(/work →
b)` paired into `ReplaceHostPath("/work", /tmp/work-b, rw)`.

**Execute**: `MNT_DETACH` work-a, then `Mount(/work, work-b, rw)` — if
work-a is unheld the kernel reclaims it at once; if held, those fds
keep reading the detached work-a until they close (kernel then reclaims
it); new lookups see work-b; nothing left shadowed.  **Expected**, with
the documented identity-loss caveat for host_path changes.

## Case 8 — Stale dirfd, modifying `*at` after a grant

**Initial**: `policy = { /work: ro }`, `current_mt = { /work: ro,
mnt_id 101 }`; app holds fd 3 = `openat("/work", O_RDONLY|O_DIRECTORY)`
on mnt 101.

**Event**: `unlinkat(3, "stale.lock", 0)`.  Bin grants and chooses to
upgrade the parent: `update_from_list({ /work: rw })`.

**Reconcile**: `Updated(/work, rw, ro)` → `SetAttr` toggles RDONLY off
on mnt 101 (same mnt_id, now rw).

**`allow()`**: `unlinkat` with `dirfd ≠ AT_FDCWD`; `statx(fd 3).mnt_id`
= 101, expected for `/work` = 101 → match → no upgrade → CONTINUE.  The
kernel resolves `stale.lock` under the now-rw mnt 101 → succeeds.
**Expected.**

**Anti-pattern variant**: if the bin instead adds a *leaf* mount at
`/work/stale.lock`, the unlinkat target becomes a mountpoint and the
kernel returns `EBUSY`.  Guidance: when the op target *is* the path,
prefer upgrading the covering mount's attrs over adding a leaf mount.

## Case 9 — Stale file fd, `fchmod` after a grant

**Initial**: `policy = { /work: ro }`, `current_mt = { /work: ro,
mnt_id 101 }`; app holds fd 3 = `openat("/work/conf", O_RDONLY)`.

**Event**: `fchmod(3, 0644)`.  Bin grants `/work: rw`.

- **Parent upgrade** (`update_from_list({ /work: rw })`): `SetAttr` on
  mnt 101 (still 101).  `allow()`: `statx(fd 3).mnt_id` = 101 =
  expected → CONTINUE.  fd 3's mount is now rw → `fchmod` succeeds.
- **Leaf-mount variant** (`current_mt = { /work: ro 101, /work/conf:
  rw 102 }`): `allow()` sees mnt 101 ≠ expected 102 → proxy: m1-open
  `/work/conf` (resolves through mnt 102), identity-check, `fchmod` the
  supervisor fd (rw → Ok), return via `notif_resp` (no CONTINUE).

**Expected** for both.

## Case 10 — Host unlinks the bind source

**Initial**: `policy = { /data: ro → /srv/data }`, `current_mt = {
/data: ro, mnt_id 101 }`.

**Event**: an external host process does `rm -r /srv/data` (or replaces
it: `rm -r /srv/data; mkdir /srv/data`).  mnt 101 stays alive on the
now-unlinked inode; mountinfo's root field gains a trailing
`//deleted`.

**App event**: `openat(AT_FDCWD, "/data/file", O_RDONLY)`.

**Behavior**: `allow()`'s m1 `openat2` of `/data/file` enters mnt 101
and resolves `file` against the kernel-pinned, now-orphaned inode tree
— it keeps serving the stale contents.  A refresh (before the next
reconcile or on suspected staleness) sees `//deleted` and marks `/data`
`expired`.  Next reconcile:
- Still desired with `host_path = /srv/data` → `Unmount` + `Mount`: the
  fresh `openat2` of `/srv/data` succeeds if the host recreated it
  (picking up the new dir) and fails ENOENT otherwise (propagate the
  error so the policy author can fix it).  Held fds keep reading the
  orphaned tree until they close.
- No longer desired → treated as `Removed`.

**Expected**, with the held-fd caveat (§13).

## Case 11 — Mid-`getdents` dirfd replacement (illustrates Limitation #5)

**Initial**: `current_mt = { /work: ro, mnt_id 101 }`; app holds fd 3 =
`openat("/work", O_RDONLY|O_DIRECTORY)` and is mid-`getdents64(3, …)`.

- **mnt_id unchanged** (attr upgrade or a deeper leaf mount): `allow()`
  finds fd 3 still on its expected mnt_id → no replacement → `getdents`
  is undisturbed.  This is the common case.
- **mnt_id changed** (host_path change → fd 3's mount `MNT_DETACH`ed →
  path replaced by mnt 103): `allow()` sees fd 3's 101 ≠ expected 103 →
  `ADDFD_SETFD`
  replaces fd 3 (now at `f_pos = 0`).  A subsequent `getdents64(3, …)`
  re-reads from the start → duplicates.  Contrived (host_path change +
  dirfd EBUSY + interleaved getdents); documented, with a `warn!` on
  the replacement.

## Case 12 — Concurrent reconciles

Two worker threads each `update_from_list` a mount.  Each call takes
the trees lock, mutates, reconciles, releases; they serialize, and the
second sees the first's mount in `current_mt`.  No interleaving.

## Case 13 — Re-add after umount-EBUSY

`policy = { /var: rw }`, removed, later re-added.
- First removal: `Removed(/var)` → `Unmount(/var)` (no kept
  children) → umount; succeeds if unheld (current_mt empties) else
  EBUSY-kept.
- Re-add: if it was removed → `Added(/var, rw)` → `Mount` with no
  sub-mounts, i.e. a plain mount (fresh `struct mount`).  If it was
  EBUSY-kept → `Updated(/var, rw, default)` → `SetAttr` (same
  `struct mount`; held fds keep working).

Identity is preserved across remove/re-add iff something held the mount
throughout.

---

## TODOs / future work

- Decide whether to SETFD-replace fds for `fexecve` / `mmap PROT_EXEC`
  (Limitation #4).
- Pidfd-based "graceful revoke" (policy removal + SIGKILL of holders).
- Diagnostics on `umount` EBUSY and dirfd-upgrade events.
- `fs.mount-max` headroom telemetry.
- Optimization: when `Mount` discovers its children in `new_mt`,
  skip moving any child that is absent from the desired tree (i.e.
  being `Removed` later in the same plan) instead of moving it in and
  unmounting it moments later.
