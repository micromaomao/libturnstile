# Sandbox redesign (`ManagedBindMountSandbox` v2 — fd-upgrade variant)

This document is a variant of `design.new.md`.  It keeps the same
mount choreography (sections 1–9) and the same approach to m0 proxies
(§11) and mountinfo refresh (§12), but replaces the "interactions
tree of anchoring bind mounts" mechanism with a tighter integration
between the tracer and the managed sandbox: dirfds and file fds are
*upgraded in place* via `SECCOMP_IOCTL_NOTIF_ADDFD` whenever the
kernel's view through the held fd would otherwise be stale.

The goal: avoid creating "anchor" bind mounts for every `O_PATH` open
or readable directory open, accepting in trade that the supervisor
intercepts a small fixed set of additional syscalls.

## Motivation

The current implementation reacts to "the desired mount set changed" by
unmounting old entries with `MNT_DETACH` and remounting new ones.  This
breaks any held fd or cwd that referenced the old mount:

- The old mount becomes detached (still alive via the held reference,
  but `mnt_ns == NULL`).
- A newly mounted entry at the same sandbox path is a different
  `struct mount`; the app's fd does not migrate.
- `..` from a cwd inside the detached mount stays inside it
  (disconnected).
- `getcwd()` returns `(unreachable)` until something fixes it.

A motivating trace: bash inside the sandbox calls `ls /home`, which we
auto-mount.  We must first unmount `/home/mao/turnstile` (already
covered) to re-mount it under the new `/home` mount.  The cwd, set to
`/home/mao/turnstile`, becomes invalid; subsequent `realpath .` fails
with `ENOENT`.

The redesign avoids `MNT_DETACH` entirely in the steady state and uses
`move_mount` choreography to preserve `struct mount` identity across
reconciles.  Where identity preservation isn't enough (e.g. an fd
opened before its covering mount existed), the supervisor *upgrades*
the fd via `ADDFD` rather than forcing a preemptive bind mount.

## Core ideas

### 1. Scratch tmpfs shadowed beneath root_tmpfs

At sandbox init, in `m1`:

1. `fsmount(tmpfs)` → a scratch tmpfs.
2. `move_mount(scratch_fd, "", AT_FDCWD, "/", MOVE_MOUNT_F_EMPTY_PATH)`:
   the scratch becomes m1's root.  It now belongs to m1 (`check_mnt`
   passes) so it can serve as a target parent for future `move_mount`
   operations.
3. `openat("/", O_PATH | O_DIRECTORY | O_NOFOLLOW)` → `m1_scratch_fd`.
   Kept in `BindMountSandbox` for the rest of the sandbox's lifetime.
4. Bind-mount `root_tmpfs` over `/`.  The scratch is now shadowed
   beneath; the sandboxed app sees only the placeholder tmpfs.

The app cannot reach the scratch via path walks (`/` resolves to the
overlay; `..` at `/` stays at `/`) and has no mount privileges to remove
the overlay.  `m1_scratch_fd` resolves to the scratch from the
supervisor side and is used as the dirfd when parking mounts.

### 2. Unified mount tree

`current_mount_tree: Mutex<FsTree<MountInternal>>` holds every active
bind mount.  Each reconcile decides what to do with each entry based
on the diff against the desired tree, and the kernel's `EBUSY` is the
source of truth on whether an entry is still in use.

```rust
struct MountInternal {
    user: ManagedMountPoint,  // host_path + currently-applied attrs
    mnt_id: u64,              // kernel mnt_id, captured at mount-creation time;
                              // used for fd-staleness comparisons and for
                              // mountinfo-based refresh (§12).
    expired: bool,            // set by refresh when mountinfo shows the
                              // bind source as `//deleted`.  Next reconcile
                              // forcibly umount-and-readd if still desired.
    // No cached mount fd.  All mount-fd-requiring operations open lazily
    // from a forked m1 helper.
}
```

User-facing APIs continue to accept `ManagedTreeEntry` /
`ManagedMountPoint`.

### 3. Plan-then-execute reconcile

The diff produces individual events but the actions we need to perform
span related events (e.g. "rebuild parent while preserving children").
Reconcile therefore proceeds in two stages:

1. **Plan**: walk the diff and emit `HighLevelOp`s into a Vec.
2. **Execute**: process the list in order, each op as one m1 helper
   round-trip.

`HighLevelOp` includes:

- `CreatePlaceholder(path, placeholder)`
- `RemovePlaceholder(path)`
- `SetAttr(path, new_attrs, old_attrs)`
- `Mount(path, host, attrs)`
- `Unmount(path)` — non-detach; if EBUSY, fall through to
  `SetAttrToCovering`.
- `ShadowAdd(parent_path, host, attrs, children: Vec<path>)` — bind
  mount parent over its current location, then for each listed child
  (already in current_mt at parent's mount-time), `move_mount` it onto
  the corresponding path inside the new overlay.  No scratch needed.
- `ScrubAndUnmount(parent_path, keep_children: Vec<path>)` — for each
  child path, `move_mount` the child to `scratch/<uuid>`; attempt
  `umount(parent)`; if successful, recreate placeholder hierarchy for
  each child path along the now-revealed underlying layer, then
  `move_mount` children back to their original paths; if `umount`
  fails, restore children to their original paths under the still-live
  parent and mark all of them and the parent as `kept`.
- `ReplaceHostPath(path, new_host, new_attrs)` — try
  `umount(path)`; if Ok, `Mount(path, new_host, new_attrs)`; if EBUSY,
  shadow: bind-mount the new host over the old (best-effort, may leak
  through still-held fds — see "Limitations").
- `SetAttrToCovering(path)` — for an entry that we tried to remove but
  couldn't: set its attrs to those of the deepest desired entry whose
  path is a prefix of `path`, or to `ro,noexec` as the default if no
  desired entry covers.

### 4. Diff settings

- `split_on` returns `true` on `host_path` mismatch.  The diff then
  emits a `Removed(P)` (bottom-up) followed by `Added(P)` (top-down)
  pair for `P`; the planner converts this into a `ReplaceHostPath` op
  for `P`.
- `split_on_one_side = false`.  Children common to both sides of an
  `Added`/`Removed` parent are still visited as `Updated`, required
  for the `ShadowAdd` path.

### 5. Cascade rule for `Removed`

(Same as design.new.md §5: bottom-up try-umount, fall through to
`ScrubAndUnmount` with kept children, then `SetAttrToCovering` for
anything that stayed.)

### 6. `Added` cascade

(Same as design.new.md §6: `ShadowAdd` if existing sub-mounts are
under the new parent; plain `Mount` otherwise.  `ShadowAdd` opens
child fds *before* the parent bind to avoid path-resolution
shadowing.)

### 7. `Updated` cascade

(Same as design.new.md §7: emit `SetAttr` op; sub-tree events drive
their own ops.)

### 8. No cached fds

(Same as design.new.md §8: lazy open from m1 helper on demand.)

### 9. Symlink mirroring

The placeholder tmpfs still mirrors host symlinks along ancestor
paths (`mirror_intent_path_symlinks`) so that pre-resolution paths
remain meaningful for path-walks that don't go through `openat`.
Mostly relevant for the small set of read-only `*at` syscalls that
take dirfds (see §10) where the supervisor leaves the kernel to
resolve relative paths from the dirfd's mount.

### 10. Integrated tracer with per-request fd upgrade

This is the substantive change from `design.new.md`.

#### 10.1 Tracer ownership

`ManagedBindMountSandbox` owns the `TurnstileTracer` (it is no
longer a separate struct held by the bin).  The public API:

```rust
impl ManagedBindMountSandbox {
    pub fn yield_request(&self)
        -> Result<Option<(Request<'_>, RequestHandle<'_>)>, AccessRequestError>;
}

pub struct RequestHandle<'a> {
    sandbox: &'a ManagedBindMountSandbox,
    req_ctx: RequestContext<'a>,
    resolved: ResolvedRequest,
}

impl RequestHandle<'_> {
    pub fn allow(self) -> Result<(), Error>;
    pub fn deny(self, errno: i32) -> Result<(), Error>;
    pub fn target(&self) -> &ResolvedRequest;
}
```

Workflow: the bin calls `yield_request`, looks at `target()`,
optionally calls `update_from_tree` / `update_from_list` to add
mount(s), and then `allow()` or `deny(errno)`.  The library does
not auto-mount based on the request — but `allow()` may transparently
upgrade fds or proxy syscalls so the app's view stays consistent
with the current mount layout.

#### 10.2 What `allow()` does, by syscall

| Syscall                                                                    | Library action in `allow()`                                                                       |
|----------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `openat` / `openat2`                                                       | Re-resolve abspath, open fresh in m1 with requested flags, identity-check, return fd via `ADDFD`. |
| `chdir` / `fchdir`                                                         | Ensure bind mount exists on target (calls into reconcile if not), then CONTINUE.                  |
| Any `*at` with a `dirfd` other than `AT_FDCWD`                             | Check `statx(dirfd).mnt_id` against `current_mt`'s expected mnt_id for the dirfd's path.<br>If stale, m1-open the dirfd's path fresh, identity-check, replace via `ADDFD_SETFD` at the same fd number, CONTINUE. |
| `fchmod`, `fchown`, `fsetxattr`, `fremovexattr`, `ftruncate` on a file fd  | Check `statx(fd).mnt_id`.  If stale, m1-open the path, identity-check, perform the op there, return result via `notif_resp`.  Don't touch the app's fd. |
| Anything else                                                              | CONTINUE.                                                                                         |

`openat` always returns a fresh fd via `ADDFD` because we need the
fd to be anchored on the latest mount layout (not on whatever the
dirfd happens to be on).

For the dirfd-upgrade case, replacement is permitted even for
non-`O_PATH` dirfds.  The trade-off is that an in-progress
`getdents`/`getdents64` loop using the same fd may see duplicates
(the new fd is at `f_pos = 0`); see Limitation #12.  In practice
dir readers don't interleave dir-read with `*at` operations on the
same dirfd from a context where the supervisor would feel justified
upgrading mid-loop, but it's not impossible.

#### 10.3 fd identity check

Every supervisor-side reopen does an inode identity check:

```rust
let (expected_dev, expected_ino) =
    ForeignFd::inode_id(&app_fd_proxy)?;  // pidfd_getfd + statx STATX_INO
let new_fd = m1_helper.openat2(abspath, flags)?;
let (got_dev, got_ino) = new_fd.inode_id()?;
if (expected_dev, expected_ino) != (got_dev, got_ino) {
    // race; retry once
}
```

After 2 retries with identity mismatch, log `error!` and skip the
upgrade / proxy.  For `openat` we fail the request with `EIO`; for
dirfd upgrade we just CONTINUE without upgrading; for f* proxy we
return `EIO`.  Always fail closed.

#### 10.4 Why m1, not m0

Every supervisor-side open or filesystem op for the proxy/upgrade
path is performed from inside m1 (via a forked helper that
`setns`-es into m1's namespaces), opening the path through m1's
mount layout.  Reason: if we opened from m0 (the supervisor's host
view), the supervisor's own credentials/permissions would govern,
and we could potentially open paths the sandbox is supposed to not
reach.  By doing it in m1, we automatically respect the sandbox's
own mount layout and `mount_attr`s; the supervisor cannot
accidentally over-grant.

#### 10.5 `AT_FDCWD` handling

`AT_FDCWD` cannot be upgraded — there's no fd number to replace,
and the kernel resolves `AT_FDCWD` from the task's `fs_struct.pwd`,
which is not addressable from the supervisor.  Therefore:

- `chdir(path)` / `fchdir(fd)` is intercepted in `allow()`.  Before
  CONTINUE, the library ensures a bind mount exists at the resolved
  target path:
  - If the path is already covered by a current_mt entry with at
    least read access, no action — kernel's chdir succeeds and the
    cwd ends up on the covering mount.
  - If not covered, the library calls `add_or_update_mount` (or
    equivalent internal API) to add a bind mount at the path with
    the current request's effective attrs (chdir → ro,noexec).
    Subsequent reconcile creates the mount.  Then CONTINUE.
- For `chdir`, the implicit grant is "read on the target path".
  The bin's policy callback is expected to either pre-grant it or
  refuse the chdir.  This is the **one** case where the library
  asks the policy for a permission grant in service of the syscall
  itself (the rest of the library is reactive only).

Practical impact: cwd churn (`cd a; cd b; cd c`) creates a
short-lived bind mount per target.  Each subsequent `chdir`-away
triggers a `Removed` on the previous path on the next reconcile;
try-umount frees it.

#### 10.6 Syscalls *not* handled

- **`fexecve` / `execveat(fd, "", AT_EMPTY_PATH)`** with `fd` opened
  on a `noexec` mount: kernel checks `path_noexec(&file->f_path)`,
  fails.  The supervisor cannot rewrite the syscall args (fd is in
  the syscall arg vector) — we could ADDFD-SETFD-replace `fd`, but
  doing so for an fd the app opened with explicit flags risks
  side-effects (lost `f_pos`, lost flags, lost watches).  Document
  as a limitation; workaround is to grant exec on the relevant
  subtree before the fd is opened, or to re-open by abspath.

  Actually: for `fexecve`, we *could* upgrade the fd via SETFD
  before CONTINUE the same way we do for dirfds.  The `f_pos`
  argument doesn't really apply to exec.  This may be worth doing
  for `fexecve` specifically.  TODO: decide.

- **`mmap(PROT_EXEC, fd, ...)`** with `fd` opened on a `noexec`
  mount: similar.  `mmap_region` checks `path_noexec` against
  `file->f_path.mnt`.  Same trade-off as `fexecve`; same TODO.

- **`execveat(dirfd, "relpath", ...)`** with relpath: kernel
  resolves from `dirfd`'s `struct path`; if `dirfd` is stale, the
  dirfd-upgrade path covers it.

- **`execve("/abs/path", ...)`** and `execveat(AT_FDCWD, "/abs",
  ...)`: re-resolves from `/`; sees the latest mount layout.  No
  upgrade needed.

  For exec of a path that's covered by a `noexec` mount, the
  policy author would normally need to grant exec.  After grant
  + reconcile (which may setattr the existing mount or add a leaf
  exec mount), CONTINUE replays and succeeds.

#### 10.7 Why no "interactions tree"

This design has no separate "interactions" tracking.  The current
mount tree is the only mount-related state besides the policy
tree.  When the bin (or any user of the library) wants to add a
mount in response to a request, it just calls
`update_from_tree` / `update_from_list` between `yield_request`
and `allow`/`deny`.  The library handles fd staleness orthogonally
via the upgrade-in-`allow()` mechanism.

The `chdir` case is the exception — the library does need to know
that the request is a `chdir` so it can preemptively ensure a
bind mount before letting it through.  This is wired into `allow()`
based on the resolved syscall kind.

## 11. Proxying syscalls that the bind-mount layout would otherwise corrupt

Some syscalls behave differently inside m1 than they would on the host:

- **`linkat` / `renameat` / `renameat2`** across two sandbox paths
  that are bind mounts of the same underlying host filesystem.
  Actually the kernel checks superblock equality, not mount
  equality, in `vfs_link` / `vfs_rename`; bind mounts of the same
  fs share superblock, so cross-bind-mount link/rename of the
  same fs already works.  EXDEV only fires for genuinely different
  filesystems, where it's correct.  **No proxy needed.**
- **`unlinkat` / `rmdir`** of a path that the library has
  bind-mounted return `EBUSY` because the path is a mountpoint.
  This is real and only happens if the policy author granted access
  to the mountpoint dir itself and the app then tries to delete it.
  Rare; document as a corner case.  Could be proxied via m0 but the
  semantics are weird (deleting a path that the policy grants
  access to).  Leave as-is.

So §11 in design.new.md is mostly obsolete under the fd-upgrade
design.  The `ProxiedHostOps` machinery from design.new.md can be
dropped or deferred until a real need arises.

## 12. Refreshing the mount tree from `/proc/<pid>/mountinfo`

The host filesystem can change underneath an active sandbox.  In
particular the dentry backing one of our bind mounts can be moved
or unlinked on the host:

- The bind mount itself stays alive (the kernel holds a reference
  to the inode; an unlinked-but-still-mounted inode is a valid
  state).
- Path resolution to the same host path may stop working.
- `/proc/<sandbox_pid>/mountinfo` annotates such mounts in the
  fourth field with a trailing `//deleted`.

The library has no in-band way to learn about these changes — the
sandboxed app's syscalls don't reveal them.  We refresh on demand
and before each reconcile.

### Storage

Each `MountInternal` records the kernel `mnt_id` of its bind mount,
captured at mount-creation time via `statx(STATX_MNT_ID)` from the
m1 helper.  This `mnt_id` doubles as the staleness-check key for
dirfd/file-fd upgrades (§10) and as the join key for mountinfo
refresh.

### When to refresh

- **Before every reconcile's diff step**: ensures the diff input
  reflects the current kernel state.
- **On suspected staleness**: if a request looks "not covered" by
  `current_mt` but a coarser ancestor exists in `current_mt` (or
  the policy expects coverage), the library calls refresh first
  before asking the bin to deny.  Catches the case "host dir was
  moved out from under our bind mount, so the path the app is
  trying to use is no longer reachable via our mount".
- Optionally on a timer for long-running sandboxes.

### How to refresh

1. Maintain a long-lived helper process inside m1 (forked once at
   sandbox init, persists for the sandbox's lifetime, just sleeps).
   Call it `mountinfo_pid`.  Its `/proc/<pid>/mountinfo` provides
   m1's view.
2. To refresh:
   - Open `/proc/<mountinfo_pid>/mountinfo`, parse each line into
     `(mnt_id, parent_mnt_id, root_from_fs, mountpoint_in_ns,
     options, ...)`.
   - Walk the *old* `current_mt`, collect its `mnt_id`s into a set.
   - Build a fresh `new_current_mt` by iterating mountinfo
     entries: if `mnt_id` is in the old set, copy the corresponding
     `MountInternal` into `new_current_mt` at the path given by
     `mountpoint_in_ns`.  Path may differ from the old entry's
     path if a parent mount moved.
   - Entries in old `current_mt` whose `mnt_id` is no longer
     present in mountinfo: dropped from `new_current_mt`
     (gone entirely from the kernel — see "mount-gone" case
     below).
   - Entries whose mountinfo shows `root_from_fs` ending in
     `//deleted`: copy into `new_current_mt` with
     `expired = true`.  See "Expired entries".
3. Replace `current_mt` with `new_current_mt`.

#### Expired entries

An entry with `expired = true` is a mount whose bind source on the
host fs has been unlinked while the mount itself is still alive
(the kernel keeps the inode pinned via the mount).  On the next
reconcile:

- If the entry is still in the desired tree (policy still wants
  that path mounted from the same `host_path`), emit `Unmount(path)`
  followed by `Mount(path, host, attrs)` — i.e. force a fresh bind.
  The new openat2 of `host_path` in m1 will succeed if the host
  has recreated the dentry, or fail with ENOENT otherwise.  Either
  way the old expired mount is gone.
- If the entry is no longer in the desired tree, treat as `Removed`
  → try umount.  Same cascade as a normal removal.
- If desired with a different `host_path`, that becomes a
  `ReplaceHostPath` on the expired entry; same plan.

The general rule: expired entries are always re-evaluated on the
next reconcile; we never assume they're still functional.

#### Mount-gone entries

An entry whose `mnt_id` was in the old `current_mt` but is absent
from mountinfo entirely: the mount has been removed from m1.  Causes:

- A `ProxiedHostOps`-enabled `unlinkat`/`rmdir` proxied in m0
  removed the mountpoint dentry on the host: mountpoint protection
  only applies within the current or parent mntns, so an op
  issued from m0 (which is neither in m1's chain nor its
  descendant) is free to unlink it.  The kernel auto-detaches the
  mount.  (Only relevant if `ProxiedHostOps` exists and is enabled.)
- An external host process unlinked the mountpoint dentry directly
  (no special mount privilege needed — a plain `unlink` from a
  different mntns suffices).
- Something `MNT_DETACH`ed the mount (e.g. an earlier
  `forcibly_remove_mount` call).

Either way, there's no mount left to manipulate; drop from tree
entirely.  No retry, no reconcile op.

### Concerns

- **mountinfo parsing.**  Format is documented but quirky
  (octal-escaped paths).  Either pull in a small crate or roll
  our own parser; only a handful of fields needed.
- **Helper process lifetime.**  Must outlive the sandbox.  If it
  dies (shouldn't, but defensively), refresh fails; the library
  falls back to using its in-memory state and logs a warning.
  Re-fork on the next attempt.
- **Path of parked entries.**  If a mount was parked in scratch
  at refresh time, mountinfo shows its mountpoint as
  `scratch/<uuid>`.  Library needs to recognize this and either
  map it back to its intended path (if reconcile is in progress
  and we hold the parking state in memory) or treat it as a
  dangling parked entry to be cleaned up.  Easier: refresh only
  fires *outside* the parking window since reconcile holds the
  tree lock.

## Assumptions

(Same as design.new.md.)

1. The sandboxed application is denied mount-related syscalls via
   seccomp.
2. The user namespace owning m1 grants the supervisor CAP_SYS_ADMIN
   over m1.
3. `fs.mount-max` is comfortably large for the working set.
4. Kernel is recent enough for `open_tree` / `move_mount` /
   `fsmount` / `mount_setattr` / `SECCOMP_IOCTL_NOTIF_ADDFD`.
   `ADDFD` needs ≥ 5.9.
5. The supervisor process has `CAP_SYS_PTRACE` in the user ns
   containing the sandboxed app — required for `pidfd_getfd` used
   in the fd-staleness check.  Already true for the existing
   tracer.

## Limitations

1. **Identity preservation is mount-based.**  An fd opened against
   a placeholder dentry before a covering mount existed cannot be
   migrated onto a later-added mount; the fd's `struct path` is
   fixed at open time.  Mitigated by `openat` proxy (the returned
   fd is always anchored on the latest layout) and by `chdir`
   preemptive mount.  Remaining residue: see Limitations #11 and
   #12.
2. **Tightening attrs is immediately observable to held fds.**
   `mount_setattr` propagates to all access through the mount; an
   app that was writing under an rw mount will start getting
   `EROFS` on the next write the instant the attr changes.
   Correct enforcement, not graceful.
3. **`ReplaceHostPath` may shadow rather than truly replace.**  If
   the old mount is busy, the new host_path is bind-mounted on
   top.  Held fds still reference the *old* host_path.  For
   true revocation, the policy author must kill the sandboxed
   process (`forcibly_remove_mount` with `MNT_DETACH` available
   as an opt-in escape hatch).
4. **Scratch parking briefly breaks `..` from inside a parked
   mount.**  Library does not respond to seccomp-notify requests
   during the parking window (reconcile holds the tree lock).
5. **`getcwd()` race during parking.**  Same mitigation as #4.
6. **`fs.mount-max` is an upper bound on accumulated mounts.**
   No explicit GC thread; rely on each reconcile's try-umount
   pass to free unused mounts.
7. **Plain `open(O_PATH)` for mount handles.**  Mount handles
   inside m1 are acquired via `open(O_PATH)`-style handles, not
   `OPEN_TREE_CLONE`.  These can be used for path-relative ops
   but not as `move_mount` source if the mount becomes detached.
   In the current design we never need this.
8. **Bind sources can vanish on the host.**  See §12.  Detected on
   next refresh, marked `expired`, re-evaluated next reconcile.
9. **`m0` proxies bypass m1's mount layout.**  Only relevant if
   `ProxiedHostOps` is enabled.  Off by default in this design;
   the fd-upgrade approach removes the main motivation (EXDEV
   on bind-mount-across-fs) since the kernel actually allows that.
10. **Exec via held fds may fail after the original open.**
    `fexecve(fd)` / `execveat(fd, "", AT_EMPTY_PATH)` / `mmap(
    PROT_EXEC, fd, ...)` check `path_noexec(&file->f_path)`
    against the fd's mount.  If the mount was `noexec` at open
    time and the policy granted exec later, the held fd doesn't
    see the upgrade.  Workarounds:
    - Re-open by abspath after grant (`openat` proxy returns
      fresh fd).
    - Grant exec on the relevant subtree *before* the original
      open.
    - TODO: consider upgrading fexecve's fd via SETFD-replace
      since `f_pos` semantics don't apply to exec.
11. **Mid-`getdents` dirfd replacement causes duplicates / missed
    entries.**  When the supervisor decides to upgrade a non-O_PATH
    dirfd via `ADDFD_SETFD`, the new fd starts at `f_pos = 0`.
    An app interleaving `getdents` with `*at` ops on the same
    dirfd may see duplicates of early entries (the `getdents` loop
    re-traverses from the start) or miss entries (if the loop is
    pos-tracking).  Practical impact is small (most readers don't
    interleave dir traversal with modifying `*at`s), but
    documented.  Library logs a `warn!` when a non-O_PATH dirfd
    is replaced so policy authors can spot pathological cases.
12. **`dup`'d dirfds self-heal on next use.**  ADDFD-SETFD on
    fd N doesn't touch dup'd copies.  A dup'd dirfd remains stale
    until the next `*at` use, where the dirfd-upgrade path kicks
    in for that fd too.  Eventually consistent.
13. **`AT_FDCWD` cannot be upgraded.**  Cwd's `struct path` is
    in the task's fs_struct and inaccessible from outside.
    Mitigated by §10.5: `chdir` / `fchdir` triggers a preemptive
    bind mount on the target.
14. **f* modifying ops on a stale file fd are proxied, not
    transparent.**  `fchmod`/`fchown`/`fsetxattr`/`fremovexattr`/
    `ftruncate` on a fd whose mount is stale are performed by
    the supervisor against the abspath.  Side effects:
    - The op uses the supervisor's m1 mount layout, not the
      app's fd.  If the abspath now resolves to a different
      inode (host has changed under us), the op affects the
      *current* inode, not the app's pinned one.  Identity check
      (§10.3) catches the common case; race remains.
    - Errors from m1 are mapped 1:1 to the syscall return.

## Changes needed (relative to current code)

### `BindMountSandbox`

- `new(...)`: insert the scratch-tmpfs step between namespace
  creation and the existing `root_tmpfs` overlay.  Store
  `m1_scratch_fd: ForeignFd`.
- Spawn the long-lived `mountinfo_pid` helper at init.
- New low-level primitive `park_to_scratch(path, uuid)` and
  `restore_from_scratch(uuid, dest_path)`.
- `unmount(path)`: stop using `MNT_DETACH` by default.  Add a
  `forcibly: bool` parameter.
- `set_mount_attr(path, new, old)`: unchanged.
- New helper `open_in_m1(path, openhow) -> Result<ForeignFd>` —
  forks helper, setns into m1, openat2, sends fd back.  Used by
  the upgrade/proxy machinery.

### `ManagedBindMountSandbox`

- Owns `TurnstileTracer`.  Exposes `yield_request` returning
  `(Request, RequestHandle)`.
- `RequestHandle::allow()` dispatches per-syscall:
  - `openat`/`openat2`: re-resolve, m1-open, ADDFD return.
  - `chdir`/`fchdir`: ensure bind mount on target.
  - `*at` with non-`AT_FDCWD` dirfd: statx-mnt_id check;
    ADDFD-SETFD replace if stale.
  - `fchmod`/`fchown`/`fsetxattr`/`fremovexattr`/`ftruncate`:
    statx-mnt_id check on the fd; m1-proxy if stale.
  - Everything else: CONTINUE.
- `RequestHandle::deny(errno)`: send error.
- `current_mount_tree` value type → `MountInternal` with
  `mnt_id` and `expired` fields.
- `update_from_tree` / `update_from_list`: unchanged signature;
  internally refreshes from mountinfo before diffing.
- `reconcile`: rewritten as plan-then-execute.
- New helpers on `FsTree`:
  ```rust
  pub fn walk_subtree_top_down<F>(&self, root: &OsStr, f: F);
  pub fn first_data_descendants<F>(&self, root: &OsStr, f: F);
  ```

### `ForeignFd`

- New `pub fn inode_id(&self) -> Result<(dev_t, ino_t)>`.
- New `pub fn mnt_id(&self) -> Result<u64>` (via statx STATX_MNT_ID).

### `turnstile-sandbox` bin

- Loop simplifies dramatically: `yield_request` → look at request
  → either `update_from_list` + `allow()` (granted) or `deny(EPERM)`
  (denied).  No `note_path_interaction`, no per-syscall categorization
  inside the bin.
- `--permissive` mode: on a not-covered request, automatically call
  `update_from_list` to add a mount with the requested attrs, then
  `allow()`.

### `design.md`

To be replaced by either `design.new.md` (interactions-tree design)
or this one, depending on which approach is chosen for
implementation.

## Additional problems / open questions

A. **Host fs missing dentry for anchor.**  Not relevant in this
   design — there are no "anchor" mounts beyond chdir targets,
   which the app already verified the existence of (else its
   chdir would have ENOENT'd before reaching seccomp).

B. **Placeholder vs interaction-mount conflict.**  Not relevant
   — no interaction tree.

C. **Tightening attrs after upgrade.**  Same as design.new.md C.

D. **`ShadowAdd` with non-existent child dentry on new parent.**
   Same as design.new.md D.  Warn and skip; child stays under old
   shadowed parent.

E. **Concurrency.**  `yield_request` can return concurrently to
   multiple worker threads.  `allow`/`deny` are independent.
   `update_from_*` takes the trees lock; the upgrade/proxy machinery
   inside `allow()` takes a *read* lock on `current_mt` only when
   it needs to check expected mnt_ids — never the write lock.  This
   means `allow()` can proceed in parallel with non-mount-changing
   operations from other workers.  `update_from_*` from one worker
   blocks `allow()`-mount-checks in others briefly; tolerable.

F. **Crash recovery.**  Sandbox is single-process; namespaces die
   with the supervisor.  No external state.

G. **Mount propagation.**  Private mounts throughout.

H. **`m1_scratch_fd` lifecycle.**  Lives for the sandbox's lifetime.

I. **fexecve / mmap PROT_EXEC upgrade.**  TODO above.  If we do
   upgrade for these (via SETFD-replace), what does "the right new
   fd" look like?  Probably: open the same abspath with the same
   flags (read from `/proc/<pid>/fdinfo/<n>`) in m1 against the
   latest mount layout, and replace.  Same identity check.  Defer
   until needed.

---

# Scenario walk-throughs

Notation:
- `policy` = user's explicit desired tree.
- `current_mt` = active mounts at start of step.

## Case 1 — Add a parent over an existing child (cwd inside child)

Same as design.new.md Case 1.  `ShadowAdd` choreography with
pre-open of child fds.  Unchanged.

## Case 2 — Add a parent ro, with rw child (cwd inside child, .. across mount)

Same as design.new.md Case 2.  Unchanged.

## Case 3 — Remove a parent with held child

Same as design.new.md Case 3.  `ScrubAndUnmount` with park to
scratch, umount parent, restore.

## Case 4 — Remove a parent with EBUSY on both parent and held child

Same as design.new.md Case 4.  Best-effort, eventual consistency.

## Case 5 — `chdir` into a placeholder dir before mounting (this design)

**Initial state**
- `policy = { /etc: ro }`
- `current_mt = { /etc: ro }`
- App's cwd = `/etc` (set up by bin's `run_command`).

**Event**: app calls `chdir("/home/mao/turnstile")`.

**Library behavior** (fd-upgrade design):
1. `yield_request` returns the chdir request.
2. Bin sees a chdir to an uncovered path.  Decides whether to
   grant: this is the bin's policy logic.  Suppose policy author
   says yes, `/home/mao/turnstile` ro.
3. Bin calls `update_from_list([("/home/mao/turnstile",
   ManagedMountPoint { host_path: "/home/mao/turnstile", attrs: ro
   })])`.  Reconcile runs, adds the bind mount.
4. Bin calls `handle.allow()`.  Library's `allow()` recognizes
   `chdir` request; verifies the target is now covered with at
   least read; CONTINUE.
5. Kernel performs the chdir.  Cwd's `struct path` = (new mount
   root, mount root dentry).

**Expected**: yes.  Identical observable behavior to the
interactions-tree design's Case 5; the bin's role is more explicit
here (bin calls `update_from_list` instead of `note_path_interaction`
+ library auto-mount).

**Variant**: policy author says no.

1. Bin doesn't call `update_from_list`.  Just calls `handle.deny(
   EPERM)`.
2. Kernel returns EACCES (or EPERM) on the chdir.

## Case 6 — `openat(O_PATH)` on a regular file (this design)

**Initial state**
- `policy = { /lib: rx }`
- `current_mt = { /lib: rx }`

**Event**: app does `openat(AT_FDCWD, "/etc/passwd", O_PATH |
O_NOFOLLOW)`.

**Library behavior** (fd-upgrade design):
1. `yield_request` returns the open request.
2. Bin sees the open; it's resolve-only (`O_PATH`), no read/write
   needed by the kernel for `O_PATH` itself.  Bin policy decides
   whether to grant read on the path (since later use of the
   resulting fd via `/proc/self/fd/N` reopen could read it).
3. Two sub-cases:
   a. Policy grants read on `/etc/passwd`: bin calls
      `update_from_list` to add the mount, then `allow()`.
      `allow()` is `openat`-type; library re-resolves
      `/etc/passwd` via m1 openat2 with `O_PATH`, identity-checks,
      `ADDFD`s back to the app.  App's fd is on the new mount.
   b. Policy denies: bin calls `deny(EPERM)`.
4. App calls `openat(AT_FDCWD, "/proc/self/fd/N", O_RDONLY)` (reopen
   via procfs symlink) later.
5. `yield_request` returns this openat; resolves to abspath
   `/etc/passwd`.  Bin grants if not already (case a means already
   granted; case b means denies again).  `allow()` does m1-openat2
   with O_RDONLY on `/etc/passwd`, ADDFDs back.  App's new fd is a
   readable fd on the bind mount.

**Expected**: yes.  Resolve-only `O_PATH` no longer forces a bind
mount; if the bin's policy allows the *open* but doesn't yet want
to grant read, that's the bin's choice.  Bin can mount `O_PATH`-able
without granting read by adding a mount with `ro` attrs anyway
(O_PATH ignores attrs), but typically the policy treats O_PATH as
resolve-only intent.

**Comparison to design.new.md Case 6**: the interactions-tree
design would have added a real bind mount on `/etc/passwd`
preemptively as part of `AnchoringOpen`.  Here we don't — the bin
+ library cooperatively decide per-syscall.

## Case 7 — host_path change

Same as design.new.md Case 7.  `ReplaceHostPath`.

## Case 8 — App holds non-O_PATH dirfd on ro mount, then policy adds rw mount underneath (new case)

**Initial state**
- `policy = { /work: ro }`
- `current_mt = { /work: ro, mnt_id 101 }`
- App did `openat(AT_FDCWD, "/work", O_RDONLY | O_DIRECTORY)` → fd 3,
  on mnt_id 101.

**Event**: app calls `unlinkat(3, "stale.lock", 0)`.

**Library behavior** (fd-upgrade design):
1. `yield_request` returns the unlinkat request.
2. Resolved abspath = `/work/stale.lock`.  Not covered by an
   rw-enough mount in `current_mt`.  Bin asks policy author;
   granted as `/work/stale.lock` rw (or `/work` upgraded to rw).
3. Bin calls `update_from_list` accordingly.  Suppose it adds
   `/work: rw` (Updated):
   - Reconcile diff: `Updated(/work, rw, ro)`.
   - Plan: `SetAttr(/work, rw, ro)` → kernel `mount_setattr`
     toggles the existing mount's RDONLY off.  Same mnt_id 101,
     now rw.
4. Bin calls `handle.allow()`.  Library's `allow()` recognizes
   `unlinkat` with `dirfd != AT_FDCWD`:
   - `statx(app's fd 3).mnt_id` = 101.
   - Expected mnt_id for `/work` in `current_mt` = 101.  Match.
   - No upgrade needed.  CONTINUE.
5. Kernel performs unlinkat through fd 3 → resolves "stale.lock"
   under /work mount (now rw) → succeeds.

**Variant**: suppose bin chose to add a *new* mount at
`/work/stale.lock` rw instead of upgrading `/work`:
   - Reconcile: `Added(/work/stale.lock, rw)` (no children) → plain
     `Mount`.  New mount with mnt_id 102 sits on top of (/work_mnt,
     stale.lock dentry).
   - `allow()` for the unlinkat: statx fd 3 → mnt_id 101.  Expected
     for `/work` = 101.  Match — no dirfd upgrade.  CONTINUE.
   - Kernel resolves `unlinkat(3, "stale.lock")`: starts at (101,
     /work dentry), walks "stale.lock" → crosses into mount 102 →
     `unlinkat` on the inode at the root of mount 102.
   - Wait, can you unlink the root of a mount?  No — kernel returns
     EBUSY because the leaf is a mountpoint.  Bad outcome.
   - Conclusion: bin should prefer the "upgrade parent attrs"
     route over "add leaf mount" when the leaf is the operation
     target.  This is policy-level logic.  Could be documented
     guidance for bin authors.

**Expected**: yes for the parent-upgrade variant.  Sensible
behavior for the leaf-mount variant requires bin discipline.

## Case 9 — App holds O_RDONLY file fd on ro mount, then policy adds rw mount on top, then fchmod (new case)

**Initial state**
- `policy = { /work: ro }`
- `current_mt = { /work: ro, mnt_id 101 }`
- App did `openat(AT_FDCWD, "/work/conf", O_RDONLY)` → fd 3.

**Event**: app calls `fchmod(3, 0644)`.

**Library behavior** (fd-upgrade design):
1. `yield_request` returns the fchmod.
2. Bin sees fchmod on a file in /work.  Asks policy; granted as
   `/work: rw`.
3. Bin calls `update_from_list({ "/work": rw })`.  Reconcile:
   `SetAttr(/work, rw, ro)` → same mnt_id 101, now rw.
4. Bin calls `allow()`.  Library recognizes `fchmod`:
   - `statx(fd 3).mnt_id` = 101.
   - Expected mnt_id for `/work/conf` (deepest mount covering it)
     = 101.  Match.  CONTINUE.
5. Kernel performs fchmod on fd 3.  fd's mount is 101 (now rw).
   `mnt_want_write()` succeeds.  fchmod proceeds.

**Variant**: bin adds a new mount on `/work/conf` instead of
upgrading.

1. After reconcile: `current_mt = { /work: ro mnt_id 101, /work/conf:
   rw mnt_id 102 }`.
2. `allow()`: statx fd 3 → 101.  Expected mnt_id for `/work/conf` =
   102.  Mismatch.  Proxy:
   - m1 helper: openat2 abspath `/work/conf` with O_RDONLY (or
     O_PATH) — kernel resolves through the new mount, gets a fd on
     mnt_id 102.
   - Identity-check: `statx(supervisor_fd).inode_id() ==
     statx(app_fd_proxy).inode_id()`.  Bind mount preserves inode,
     should match.
   - `fchmod(supervisor_fd, 0644)`.  Mnt is rw → succeeds.
   - `notif_resp.error = 0, val = 0`.  No CONTINUE.
3. App sees fchmod return 0.

**Expected**: yes, for both variants.

## Case 10 — Mid-getdents dirfd replacement (new case, illustrating limitation #11)

**Initial state**
- `policy = { /work: ro }`
- `current_mt = { /work: ro, mnt_id 101 }`
- App did `openat(AT_FDCWD, "/work", O_RDONLY|O_DIRECTORY)` → fd 3.
- App calls `getdents64(3, buf, len)` → reads first chunk, `f_pos`
  advances to entry K.

**Event**: in parallel (or interleaved), app calls `unlinkat(3,
"victim", 0)`.

**Library behavior**:
1. Bin grants `/work: rw`.
2. Reconcile: `SetAttr(/work, rw, ro)` on mnt 101.  Same mnt_id.
3. `allow()` for unlinkat: statx fd 3 = 101.  Expected for `/work`
   = 101.  No mismatch → no upgrade.  CONTINUE.
4. Kernel unlinkat succeeds.
5. Subsequent `getdents64(3, buf, len)` continues at the previous
   `f_pos`.

**Expected**: yes — no upgrade happens because mnt_id didn't
change.

**Variant**: bin adds a new mount at `/work/sub` rw on top.

1. `current_mt = { /work: ro 101, /work/sub: rw 102 }`.
2. `unlinkat(3, "sub/victim", 0)`: abspath `/work/sub/victim`,
   covered by mnt 102.  Statx fd 3 = 101.  Expected for fd 3's
   path `/work` = 101.  Match — no upgrade.  CONTINUE.
3. Kernel resolves `sub/victim` from fd 3's path: walks "sub" →
   crosses into mnt 102 → "victim" inside mnt 102 → unlinkat
   succeeds.

Still no upgrade.  Good — `getdents` undisturbed.

**Pathological variant**: app does `unlinkat(3, "foo")` directly
(no subdir) and policy chose to mount `/work` host_path change
instead of attr change.

1. ReplaceHostPath: try umount (EBUSY due to fd 3 holding it),
   shadow with new mount mnt 103 on top.
2. `current_mt = { /work: rw 103 }` (we record the new top-of-stack
   mnt_id).  The old 101 is shadowed but still alive (fd 3 pins).
3. `allow()` for unlinkat: statx fd 3 = 101.  Expected = 103.
   Mismatch — upgrade.
4. ADDFD-SETFD replaces fd 3 with a fresh fd on mnt 103, f_pos = 0.
5. CONTINUE.  unlinkat succeeds.
6. App later resumes `getdents64(3, ...)`: now reads from start of
   `/work` again (through new mnt 103, which is bind of the *new*
   host).  Duplicates / inconsistency.

**Expected**: documented as Limitation #11.  Only happens in the
specific case of host_path change *plus* dirfd EBUSY *plus* the app
interleaving getdents with modifying *at — quite contrived.

## Case 11 — Host moves the bind source out from under us (new case)

**Initial state**
- `policy = { /data: ro }`, `host_path = /srv/data`.
- `current_mt = { /data: ro mnt_id 101, host /srv/data }`.

**Event**: external host process does `mv /srv/data /srv/data.old`.
The bind mount stays alive (kernel pins via inode), but
`/proc/<mountinfo_pid>/mountinfo` now shows mnt 101's `root` as
`/srv/data//deleted`.

**App event**: app does `openat(AT_FDCWD, "/data/file", O_RDONLY)`.

**Library behavior** (fd-upgrade design):
1. `yield_request` returns the open.  Bin: `/data/file` should be
   covered by `/data` ro → would normally `allow()`.
2. `allow()` for `openat` does m1-openat2 of `/data/file`.  m1's
   path resolution: enters mnt 101 at `/data`, then looks up
   `file`.  The mount's underlying dentry tree is still alive
   (kernel pins inode), so `file` may still resolve if it was a
   child of the (now-deleted) `/srv/data` dir.  But subsequent
   external changes to the inode are not visible since the host
   dir is gone.
3. Either way, the openat proceeds against the kernel-pinned
   inode tree.  Returns whatever the pinned state gives.
4. Eventually (before next reconcile, or on next refresh trigger):
   library refreshes from mountinfo, marks `/data` as expired.
5. Next reconcile / policy update: expired entry forces re-bind.
   - If policy still wants `host_path = /srv/data`: try openat2
     of `/srv/data` for new bind → ENOENT (host dir gone).  Bind
     fails; library logs error.  Old mount entry kept (cannot
     unmount because EBUSY by fd from step 2).  Policy author
     should update.
   - If policy now wants `host_path = /srv/data.old`:
     ReplaceHostPath — try umount, EBUSY → shadow with new bind
     of `/srv/data.old` on top.  Old fd from step 2 still sees
     the old (kernel-pinned) inode tree; new opens see the new
     bind.

**Expected**: yes, with the caveat that already-held fds keep
seeing the orphaned inode tree.  Documented as Limitation #8.

## Case 12 — Concurrent reconciles

Same as design.new.md Case 9.  Lock serializes.

## Case 13 — Re-add after umount-EBUSY

Same as design.new.md Case 11.

---

## Open TODOs / future work

- Decide whether to SETFD-replace fds in `fexecve` / `mmap
  PROT_EXEC` (Limitation #10).
- Pidfd-based "graceful revoke" API.
- Better diagnostics on `umount` EBUSY and dirfd upgrade events.
- Telemetry on `fs.mount-max` headroom.
- Mid-getdents detection / warning heuristic.
- Optimization: skip `move_mount` in `ShadowAdd` for children
  being concurrently `Removed`.
