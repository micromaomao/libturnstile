# Sandbox redesign (`ManagedBindMountSandbox` v2)

This document captures the redesign of `ManagedBindMountSandbox` that came
out of the discussion about preserving fd / cwd identity across mount
updates.  The starting point and motivation is the current `design.md`;
this file describes what should *replace* the current reconcile design.

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
reconciles.

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

### 2. Unified mount tree (no dummy/real distinction)

`current_mount_tree: Mutex<FsTree<MountInternal>>` holds every active
bind mount.  There is no special marker distinguishing "explicit policy
mount" from "implicit anchor mount" — both are just entries.  Each
reconcile decides what to do with each entry based on the diff against
the desired tree, and the kernel's `EBUSY` is the source of truth on
whether an entry is still in use.

```rust
struct MountInternal {
    user: ManagedMountPoint,  // host_path + currently-applied attrs
    // No cached mount fd.  All mount-fd-requiring operations (move_mount,
    // mount_setattr, open_tree for parking, etc.) are issued from a
    // forked helper that enters m1 and opens the path on demand.
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
- `split_on_one_side = false`.  This means children common to both
  sides of an `Added`/`Removed` parent are still visited as
  `Updated`/etc.  Required for the `ShadowAdd` path (we need to see the
  common children to enumerate them as preserve-and-move-mount
  targets).

### 5. Cascade rule for `Removed`

Removed walk is bottom-up (`FsTree::diff` guarantees this for the
left-only subtree).  For each `Removed(P)`:

1. Try `umount(P)` non-detach.
2. On success: drop `P` from `current_mt`.
3. On EBUSY:
   - Find all entries in `current_mt` whose path is strictly under `P`
     and which are still alive (i.e. were not successfully removed
     earlier in this pass).  Call them `kept_children`.
   - If `kept_children` is non-empty, this is a `ScrubAndUnmount(P,
     kept_children)`.  Park them in scratch, retry `umount(P)`.
     - If the retry succeeds: recreate placeholder hierarchy as needed
       on the newly-revealed layer; restore children to their original
       paths; drop `P` from `current_mt`; children stay.
     - If the retry still fails (P is held by something other than its
       sub-mounts): restore children to their original paths under `P`;
       `P` stays; emit `SetAttrToCovering(P)` and
       `SetAttrToCovering(child)` for each restored child.
   - If `kept_children` is empty, P is held by itself: `P` stays; emit
     `SetAttrToCovering(P)`.

### 6. `Added` cascade

For `Added(P)`:

1. If any current_mt entry is under `P`, this is a `ShadowAdd`.
   Enumerate the direct sub-mounts of `P` in current_mt (only
   immediate-mount children, not transitively).  The plan op:
   - Create ancestor placeholders for `P` (already handled by phase 1
     of reconcile).
   - Bind-mount host source at `P`.
   - For each enumerated direct sub-mount `C`, `move_mount` `C`
     (acquired as an `O_PATH` fd from m1 by opening `C`'s current
     path) onto `C`'s same path, which now resolves inside the new
     overlay.  The mountpoint dentry inside the overlay must exist
     (because the bind-mounted host fs must already have it, by the
     mount's nature).
2. If no current_mt entry is under `P`, this is a plain `Mount`.

### 7. `Updated` cascade

For `Updated(P)` (host_path matches, attrs may differ): emit
`SetAttr(P, new_attrs, old_attrs)`.  No diff-walk into common children
needed for the operation itself; their `Updated`/`Removed`/`Added`
events drive their own ops.

### 8. No cached fds

Earlier drafts proposed caching a `MountObj` (an `open_tree`/`O_PATH`
fd) per mount in the supervisor to avoid re-opening per reconcile.  We
drop this:

- A cached fd holds a reference to the mount.  Non-`MNT_DETACH`
  `umount2` would always EBUSY because of our own ref.  We'd have to
  drop the fd before each umount attempt and re-open on failure —
  expensive in the common "app is using it" case.
- Lazy open from the m1 helper (one openat2 per operation) is cheap
  enough at interactive rates.

### 9. Symlink mirroring (existing behavior, preserved)

The bin already mirrors host symlinks along ancestor paths into the
sandbox via `mirror_intent_path_symlinks` so that pre-resolution paths
remain meaningful.  This stays.  Path-resolution intermediate symlinks
are not full bind mounts; they live in the placeholder tree.

### 10. Interaction-driven anchor mounts

A new top-level API on `ManagedBindMountSandbox`:

```rust
pub enum InteractionKind {
    /// Read access on a regular file.
    ReadFile,
    /// Write access on a regular file.
    WriteFile,
    /// Exec access on a regular file.
    ExecFile,
    /// `openat(... O_PATH)` on a regular file or `chdir`/`fchdir`/
    /// `O_PATH`-open on a directory.  The fd or cwd persists after
    /// the syscall and is anchored on whatever mount currently
    /// covers the path; without a real bind mount it would be
    /// anchored on a placeholder dentry and never see the host
    /// content even if access is granted later.  Library translates
    /// this into a "needs at least read access" requirement on the
    /// path, but only if the existing covering mount is not already
    /// `rw` (any further exec upgrade is handled at execveat time
    /// by re-resolving the target by absolute path — see §10
    /// "Exec-at-execveat").
    AnchoringOpen,
    /// `readlink`/`readlinkat`/`stat`/`access`/etc. — resolve-only
    /// syscalls whose result is consumed in-syscall and does not
    /// produce a fd or cwd reference.  Mirror the relevant
    /// placeholder (symlink target, stat-derived placeholder, ...)
    /// into the placeholder tmpfs so the kernel's resolution and
    /// readlink yield host-truthful values without granting a real
    /// bind mount.
    PlaceholderMirror,
}

pub fn note_path_interaction(
    &self,
    path: &OsStr,
    kind: InteractionKind,
) -> Result<(), BindMountSandboxError>;
```

Semantics:

- The library maintains, in addition to the user-facing policy desired
  tree, an *interactions tree* of mounts implied by the app's observed
  behavior.  The effective desired tree is the union (with
  user-policy attrs taking precedence on conflict).
- `ReadFile`/`WriteFile`/`ExecFile` add entries with the corresponding
  attrs.  If a user policy entry already covers the path with stronger
  attrs, the interaction is redundant; if not, this is the "auto-mount
  on first access" behavior the existing `--permissive` mode performs,
  now expressed cleanly.
- `AnchoringOpen` requires a real bind mount on the path with at
  least `ro,noexec` attrs.  This is the load-bearing rule for fd/cwd
  identity preservation: any path that the app holds open (as
  `O_PATH` on a file, an `O_RDONLY|O_DIRECTORY` dir fd, or as cwd via
  `chdir`) must be backed by a real bind mount *before* the open
  returns, because path-resolution-via-held-dirfd does not cross
  subsequently-layered mounts.  See limitation #1.

  The library does **not** auto-create the bind mount.  Instead,
  `AnchoringOpen` raises a "needs at least read access" signal on the
  path, which the bin handles like any other read-access request: it
  asks the policy author; if granted, the policy gains a read entry on
  the path and the next reconcile establishes the bind mount, then the
  syscall continues; if denied, the request returns EPERM to the app
  exactly like any other denied access.  The "implicit grant on chdir"
  outcome only happens if the policy author chooses to grant read on
  that path.
- `PlaceholderMirror` only updates the placeholder tree — for a
  symlink path, write the host symlink's target into the tmpfs as a
  `PlaceholderSymlink`; for a non-symlink path, create a matching
  dir/file placeholder.  Subsequent `readlinkat` / `fstatat` etc.
  resolve in the placeholder tmpfs and return the same content the
  host would return, without granting read on the underlying inode.

Additional refinements that reduce the impact of the "any open forces
read" rule:

- **"Full" means `rw` for anchoring purposes; exec is handled
  separately.**  Exec is technically a third upgradable dimension,
  but treating it the same as r/w would force a dummy mount on every
  open under an `rw` (but `noexec`) mount — defeating the win of
  granting `rw` on a large project dir.  We instead take the
  pragmatic stance: `rw` coverage on the ancestor is treated as full
  for anchoring; exec grants are honored at **execveat time** for
  the **abspath form** of exec syscalls by establishing a one-off
  bind mount with `exec` attrs for the specific target file and
  letting `SECCOMP_USER_NOTIF_FLAG_CONTINUE` replay the syscall
  (the kernel re-resolves from `/` and crosses into the new
  mount).  See "Exec-at-execveat (abspath form only)" below.  This
  keeps the common "rw-but-noexec project dir" case fast (no
  per-open dummy mount) while letting `execve("/abs/path")`-style
  exec calls work after a late grant.  Caveat: exec via held fds
  (`execveat(dirfd, "relpath")`, `fexecve`, `mmap(PROT_EXEC)`) is
  not recovered — the kernel checks the fd's mount directly and
  the supervisor cannot rewrite syscall args.  See Limitation #11.
- **No anchoring mount where no future grant could change the picture.**
  An `AnchoringOpen` is only useful if the path's covering mount could
  later have its effective permissions broadened on a sub-path.  If
  the path is already covered by a mount with `rw` (or `rwx`) attrs,
  no future *anchoring-relevant* grant can elevate it further — exec
  is handled at execveat as above.  Skip the interaction entirely.
  Concrete impact: when the policy author has granted
  `/home/mao/turnstile` as `rw` (or `rwx`), an app running
  `cargo build` inside it issues thousands of opens; none of those
  need a dummy mount.
- **"Non-full" coverage triggers anchoring; "full" doesn't.**  In what
  follows, when we say "the anchoring rule applies", read it as: the
  covering mount lacks `r` or `w` on the leaf's effective attrs.
  `ro,noexec` and `ro,exec` are non-full (read-only — write could be
  granted later); `rw,noexec` and `rwx` are full (any future grant is
  either redundant or exec-only and handled at execveat).
- **No anchoring mount where the supervisor itself lacks write access
  on the dir.**  Before adding an `AnchoringOpen` mount, the library
  calls `faccessat(AT_FDCWD, host_path, W_OK, AT_EACCESS)` (from
  outside any namespace).  If the supervisor has no write permission
  on the host path, the policy could never legitimately grant write
  to the sandboxed app either, so the only remaining upgrade
  dimension is exec (handled at execveat).  Emit a
  `PlaceholderMirror` instead.  Eliminates dummy mounts for system
  dirs like `/usr`, `/lib`, `/etc` etc. when the supervisor runs
  unprivileged.

### Exec-at-execveat (abspath form only)

When the app calls `execve(path)` or `execveat(AT_FDCWD, path, ...)`
(or `execveat(dirfd, path, ...)` where `path` is absolute), the
bin's seccomp handler:

1. Resolves the target to an absolute sandbox path from the
   syscall's path argument.
2. Calls `note_path_interaction(path, ExecFile)` — policy author
   confirms; on grant, an `exec` bind mount is established for the
   target file (a leaf mount, not the whole dir).
3. Responds with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.  The kernel
   replays the syscall in the app's context.  Path resolution
   starts from `/` (or `AT_FDCWD`'s mount, which is cwd's mount
   — the abspath case bypasses this) and crosses into the
   newly-installed exec mount at the leaf.  `path_noexec` checks
   the new mount, sees `exec`, succeeds.

This covers the common case: shell-style `execve("/bin/sh", ...)`,
`posix_spawn` with abspath, etc.  The worked example becomes: app
does `execve("/a/b/c", ...)` or `execveat(AT_FDCWD, "/a/b/c",
...)` — library mounts host `/a/b/c` exec, CONTINUE re-resolves
from `/`, succeeds.

**What this does *not* cover**, because the supervisor cannot
rewrite the app's syscall args and cannot execute on the app's
behalf:

- **`execveat(dirfd, "c", ...)`** where `dirfd` was opened under a
  `noexec` mount before the exec grant.  CONTINUE replays with the
  same `dirfd`; the kernel checks `path_noexec(&dirfd_file->f_path)`
  against the dirfd's (still-`noexec`) mount and returns `EACCES`.
  The newly-installed leaf exec mount is irrelevant because the
  resolution starts from the dirfd, not from `/`.
- **`execveat(fd, "", AT_EMPTY_PATH)`** (`fexecve`) where `fd` was
  opened under a `noexec` mount.  Same reason — the kernel checks
  the fd's mount directly.
- **`mmap(PROT_EXEC, fd, ...)`** where `fd` was opened under a
  `noexec` mount.  Same kernel check in `mmap_region`.

All three failure cases are documented under Limitation #11.
They share a common workaround: if the policy author wants exec
through a held fd, they must grant exec on the relevant subtree
**before** the corresponding open, so the fd is anchored on an
exec mount from the start.  Alternatively, the app can re-open
by path after the grant.
- **`openat("/")` and chdir-to-`/` are no-ops.**  The sandbox root is
  always already mounted (the bind of `root_tmpfs` over m1's `/`),
  and you cannot layer another mount over `/` and have it affect
  existing fds/cwds anyway.  Skip the interaction entirely.
- **Only fd-producing resolve-only syscalls require a bind mount.**
  `readlink`/`readlinkat` return a buffer immediately and never
  produce a long-lived reference — `PlaceholderMirror` suffices.
  Same for `stat`/`fstatat`/`statx`/`access`/`faccessat`.  Only
  `openat(... O_PATH)` (which yields a fd) and `chdir`/`fchdir`
  (which set cwd) require the full `AnchoringOpen` mount.

GC of interaction-driven entries happens implicitly: on each reconcile,
they are `Removed` if not covered by user policy and not re-asserted
since the previous reconcile.  Try-umount; on EBUSY they stay and the
next reconcile retries.

TODO: interactions cancellation — currently sticky-until-umount-succeeds.
Future work: explicit handle-based deregistration when the app closes
the fd or chdirs away.  Not blocked on this work.

## 11. Proxying syscalls that the bind-mount layout would otherwise corrupt

Some syscalls behave differently inside m1 (where the sandbox's bind
mounts exist) than they would have on the host:

- **`linkat` / `renameat` / `renameat2`** across two sandbox paths
  that are bind mounts of the same underlying host filesystem return
  `EXDEV` from m1, because the two mountpoints are different
  `struct vfsmount`s.  On the host they'd succeed.
- **`unlinkat` / `rmdir`** of a path that the library has bind-mounted
  (e.g. a dummy `AnchoringOpen` mount or a regular policy mount) return
  `EBUSY` from m1 because the path is a mountpoint.  On the host the
  inode could be unlinked normally.
- Possibly **`rename`** of a path that is itself a mountpoint —
  `EBUSY` in m1, would-be successful on the host.

Performing these in m1 doesn't help: m1 *is* what introduces the
divergence.  The proxy has to run in **m0** (the supervisor's outer
mount namespace, i.e. the host namespace), where the bind mounts the
library installed do not exist.

### Translation

Sandbox paths must be translated to host paths before m0 execution.
For an abspath `/sandbox/path`, walk `current_mt` for the longest
prefix that is a bind mount, take its `host_path`, and append the
remainder of `/sandbox/path` past the prefix.  The translated path
is what the m0 proxy operates on.

Examples:
- `current_mt = { /work: host /tmp/work-a }`; sandbox path
  `/work/sub/file` → host path `/tmp/work-a/sub/file`.
- `current_mt = { /work: host /tmp/work-a, /work/sub: host /tmp/work-b }`;
  sandbox path `/work/sub/file` → host path `/tmp/work-b/file`.
- Sandbox path `/work/notmounted/file` with only `/work` bind-mounted
  → host path `/tmp/work-a/notmounted/file`.

### Bypass risk and opt-in setting

Executing in m0 means the supervisor performs an operation on the
host filesystem *outside* the sandbox's mount layout.  Risks:

1. The supervisor process has its own uid/cap set; if it's privileged
   beyond what the sandbox itself can access, an attacker who
   convinces the supervisor to do a proxied syscall on a path the
   sandboxed app couldn't reach in m1 effectively escalates.
2. Race conditions: between the policy check (sandbox-side) and the
   m0 execution, the host filesystem could change (e.g. symlink swap).
   The sandbox sees one inode; m0 might touch another.
3. The supervisor's m0 view may include paths the sandbox is supposed
   to not see at all (mount points in m0 that don't exist in m1).
   If translation produces such a path due to a current_mt bug, the
   m0 op operates on out-of-sandbox state.

Mitigations:
- Re-validate the translated host path against the supervisor's own
  notion of permitted host paths (the union of all `host_path`s in
  `current_mt`'s bind-mount entries, restricted to the relevant
  subtree).
- Pin the source/target via fd before the policy check.  Resolve the
  abspath via `openat2(O_PATH|RESOLVE_NO_SYMLINKS|RESOLVE_IN_ROOT)`
  in m1 to get a fd, then `pidfd_getfd`-style migrate the fd into m0
  context via `/proc/<helper_pid>/fd/N`, then perform `linkat` /
  `renameat` / `unlinkat` with `AT_EMPTY_PATH` on those fds.  This
  pins the inode identity across the policy/execution boundary.
- Make each proxy **opt-in** at sandbox construction time:

  ```rust
  #[derive(Default)]
  pub struct ProxiedHostOps {
      pub link:   bool,
      pub rename: bool,
      pub unlink: bool,
      // ... more as we find more
  }

  ManagedBindMountSandbox::new(disable_userns, ProxiedHostOps { ... })
  ```

  Default is all-false: spurious EXDEV/EBUSY is propagated to the
  app, which fails closed.  Enabling each requires the policy author
  to take the bypass risk consciously.

### What's still done in m1

Mounts/unmounts/setattr etc. — all the operations that *are*
specifically about the sandbox's namespace — continue to happen in
m1 as before.  Only the path-input proxies above need m0.

## 12. Refreshing the mount tree from `/proc/<pid>/mountinfo`

The host filesystem can change underneath an active sandbox.  In
particular the dentry backing one of our bind mounts can be moved
or unlinked on the host:

- The bind mount itself stays alive (the kernel holds a reference to
  the inode; an unlinked-but-still-mounted inode is a real state).
- Path resolution to it from the host fs may stop working.
- `/proc/<sandbox_pid>/mountinfo` annotates such mounts in the
  fourth field (root-within-fs) with a trailing `//deleted`.

The library has no in-band way to learn about these changes — the
sandboxed app's syscalls don't reveal them.  We rely on
**periodic** *and* **on-demand** refresh by reading mountinfo.

### When to refresh

- Before every reconcile's diff step.  This ensures the diff input
  reflects the current kernel-truthful state.
- When a request looks "not covered" by current_mt but the cause is
  suspected to be a stale entry (heuristic: a request for a path
  whose ancestor exists in current_mt — possibly the ancestor is
  now `//deleted`).
- Optionally on a timer for long-running sandboxes.

### How to refresh

1. Maintain a long-lived helper process inside m1 (forked once at
   sandbox init, persists for the sandbox's lifetime, just sleeps).
   Call it `mountinfo_pid`.  Its `/proc/<pid>/mountinfo` provides
   m1's view.
2. Each `MountInternal` records the kernel `mnt_id` of its bind
   mount, captured at mount-creation time via `statx(STATX_MNT_ID)`.
3. To refresh:
   - Open `/proc/<mountinfo_pid>/mountinfo`, parse each line into
     `(mnt_id, parent_mnt_id, root_from_fs, mountpoint_in_ns,
     options, ...)`.
   - For each parsed entry whose `mnt_id` is present in the *old*
     `current_mt`, copy the `MountInternal` (carrying our metadata)
     into a freshly-allocated `new_current_mt` at the path given by
     `mountpoint_in_ns`.
   - Entries whose `mnt_id` is unknown: ignore (they're not ours
     — could be the scratch tmpfs, root_tmpfs, or unrelated).
   - **Source-unlinked** entries: `mnt_id` is known and present in
     mountinfo, but `root_from_fs` ends in `//deleted`.  The bind
     source on the host was unlinked while the mount itself is
     still alive.  Copy to `new_current_mt` and set
     `dentry_unlinked: true`.  Subsequent reconcile may try to
     umount it (succeeds if nothing references it; EBUSY if held);
     attempting to re-mount with the same `host_path` will ENOENT.
   - **Mount-gone** entries: `mnt_id` is known in old `current_mt`
     but absent from mountinfo entirely.  The mount no longer
     exists in m1.  This is the second disappearance mode.  Possible
     causes:
     - A `ProxiedHostOps`-enabled `unlinkat`/`rmdir` proxied in m0
       removed the mountpoint dentry on the host: mountpoint
       protection only applies within the current or parent mntns,
       so an op issued from m0 (which is neither in m1's chain nor
       its descendant) is free to unlink it.  The kernel then
       auto-detaches the mount.
     - An external host process with the requisite filesystem
       permissions unlinked the mountpoint dentry directly (no
       special mount privilege needed — a plain `unlink` from a
       different mntns suffices).
     - Something `MNT_DETACH`ed the mount (e.g. an earlier
       `forcibly_remove_mount` call).

     Either way, there's no mount left to manipulate; drop from
     tree entirely.  No retry, no reconcile op.
4. Replace `current_mt` with `new_current_mt`.

### Behavior on policy update after a refresh

If a mount is marked `dentry_unlinked` and the policy still wants
that path:
- If the policy specifies the same `host_path`, the entry is
  effectively dead — its bind source is gone.  Treat as Removed in
  the diff (umount the dead mount) and then Add a fresh one (which
  will fail at openat2 of the host source with ENOENT — propagate
  the failure to the caller; the policy author needs to update
  their policy).
- If the policy specifies a new `host_path`, it's a normal
  ReplaceHostPath.

If a mount is marked `dentry_unlinked` and the policy no longer
wants that path: it's just Removed → umount as usual.  Held fds
keep the mount alive but the path is gone from current_mt.

### Concerns

- **`mountinfo` parsing**.  The format is documented but quirky
  (octal-escaped paths, etc.).  Existing crates handle it; or roll
  a small parser since we only need a few fields.
- **Race between refresh and external mount changes**.  Refresh is
  point-in-time.  Between read and next reconcile, more changes
  could happen.  Acceptable — refresh runs again before each
  reconcile.
- **Helper process lifetime**.  Must outlive the sandbox.  If it
  dies (shouldn't, but defensively), refresh fails; the library
  falls back to using its own in-memory state and logs a warning.
  Re-fork the helper.
- **`mountinfo` for shadowed mounts**.  Shadowed mounts (e.g. the
  scratch tmpfs under root_tmpfs) appear in mountinfo too, with
  their `parent_mnt_id` pointing to a now-shadowed parent.  The
  parsing logic should be robust to this.
- **Path of move_mounted entries**.  If a mount was parked in
  scratch at refresh time, mountinfo shows its mountpoint as
  `scratch/<uuid>`.  We need to recognize this and either map it
  back to its intended path (if reconcile is in progress) or treat
  it as a dangling parked entry to be cleaned up.

## Assumptions

1. The sandboxed application is denied mount-related syscalls via
   seccomp (otherwise the whole bind-mount sandbox is bypassable).  In
   particular it cannot peel back the root overlay to access the
   scratch tmpfs.
2. The user namespace owning m1 grants the supervisor (via its forked
   m1 helpers) CAP_SYS_ADMIN over m1.  Required for `mount_setattr`,
   `move_mount`, `umount2`, etc.
3. `fs.mount-max` is large enough for the working set of mounts the
   sandbox accumulates.  The default (100,000) is comfortable for
   interactive use; pathological apps that touch hundreds of thousands
   of paths may need tuning.
4. The kernel is recent enough for `open_tree` / `move_mount` /
   `fsmount` / `mount_setattr` (Linux ≥ 5.12 for the full set, ≥ 5.2
   for the older ones).  The existing code already requires this.
5. Symlink mirroring uses host paths verbatim; the supervisor and the
   sandbox agree on the meaning of those paths because the sandbox's
   m1 root is initially set up to be a faithful overlay of selected
   host paths.

## Limitations

1. **Identity is preserved for mounts, not for fds opened against
   placeholder dentries.**  If the app `chdir`s or `O_PATH`-opens a
   path before a covering mount exists, its fd / cwd is anchored to
   the placeholder dentry, not to a mount.  Therefore, an `O_PATH`
   open or `chdir` is treated by the library as **requiring read
   access** on the path: if the policy author grants read, a bind
   mount is established and the fd / cwd lands on it; if not, the
   syscall is denied with EPERM the same as any other unauthorized
   access.  An "I just want to resolve, not read" intent is not
   expressible at the kernel boundary for these syscalls.  The same
   applies to long-lived O_RDONLY directory fds (the dir must already
   be backed by a real bind mount at open time).  Scope and
   mitigations:
   - **Only triggers under non-full ancestor coverage.**  "Full"
     here means `rw` (read+write) on the leaf's effective attrs.
     If the path is already under a `rw` (or `rwx`) mount, no
     future grant could broaden anchoring-relevant permissions
     further; exec is handled at execveat time by abspath
     re-resolution (see §10 "Exec-at-execveat").  In practice, an
     app running entirely inside a `rw`-granted subtree (e.g.
     `cargo build` under a fully-granted project dir) issues no
     anchoring mounts at all.
   - **Exec is not an anchoring-triggering dimension.**  Treating
     exec as upgradable for anchoring purposes would force a dummy
     mount on every open under a `rw,noexec` ancestor, which would
     ruin the cost model for the common "granted rw, noexec"
     project-dir case.  Instead, exec grants are honored at
     execveat time via a one-off leaf mount and abspath
     re-resolution.  This trades one corner case —
     `mmap(PROT_EXEC, fd, ...)` against a fd opened before the
     exec grant — for the bulk fast path; see Limitation #11.
   - Skip if the supervisor has no write permission on the host path
     (write could never be granted anyway → only a `PlaceholderMirror`
     is offered; if exec is the only remaining upgrade dimension we
     err on the side of `PlaceholderMirror` for now).
   - Skip for the sandbox root `/`.
   - Resolve-only syscalls that do not produce a fd (`readlink`,
     `stat`, `access`, ...) use placeholder mirroring instead — no
     bind mount, no read grant requested.
2. **Tightening attrs is immediately observable to held fds.**
   `mount_setattr` propagates to all access through the mount; an app
   that was writing under an rw mount will start getting `EROFS` on
   the next write the instant the attr changes.  This is correct
   policy enforcement but not graceful.
3. **`ReplaceHostPath` may shadow rather than truly replace.**  If the
   old mount is busy, the new host_path is bind-mounted on top.  Held
   fds still reference the *old* host_path, so this is not a true
   revocation.  For security-sensitive revocation, the policy author
   must kill the sandboxed process.  The library exposes
   `forcibly_remove_mount` (uses `MNT_DETACH`) as a separate, scary
   API for that case.
4. **Scratch parking briefly breaks `..` from inside a parked mount.**
   A cwd whose mount has just been parked to `scratch/<uuid>` will see
   `..` lead into the scratch root rather than to its old parent.  The
   library should not respond to seccomp-notify requests during the
   parking window (the existing reconcile path is already serialized;
   this naturally holds).
5. **`getcwd()` race during parking.**  An app that calls `getcwd()`
   while its cwd's mount is parked will get a scratch-relative path
   ("(unreachable)..." or similar).  Mitigated by the same serialization
   point.
6. **`fs.mount-max` is an upper bound on accumulated interactions.**
   No explicit GC thread; we rely on each reconcile's try-umount pass
   to free unused mounts.  An app that holds many distinct paths open
   simultaneously can in principle exhaust the limit.  Detectable;
   not currently mitigated beyond the implicit reclamation.
7. **`open_tree`-less plain `open(O_PATH)` is what the library uses
   to acquire mount handles inside m1.**  Holding such a handle pins
   the mount, but it cannot be used as the source of `move_mount` if
   the mount happens to be detached / in an anon namespace — only
   `OPEN_TREE_CLONE` produces anon-namespace clones for that purpose.
   We never need anon-namespace clones in the current design; if a
   future feature requires it (e.g. cross-sandbox mount migration),
   it must reach for `OPEN_TREE_CLONE` deliberately.
8. **Interactions are sticky.**  See the TODO above.  Practical
   workaround: trust the implicit per-reconcile try-umount GC.
9. **Bind sources can vanish on the host.**  If a host dentry that a
   bind mount references gets unlinked or moved externally, the
   mount keeps the inode alive but path-walks to its bind source
   fail.  Detected on next refresh (§12), reported as
   `dentry_unlinked: true`.  Policy updates can then act on it.
   Apps holding fds to inodes inside the now-orphaned mount keep
   working until they release the fds.
10. **m0 proxies bypass the m1 mount layout.**  When `ProxiedHostOps`
    flags are enabled, the supervisor performs the relevant syscall
    in m0.  Risks: see §11.  The setting is off by default and the
    policy author has to opt in.
11. **Exec through pre-grant fds fails.**  The exec dimension is
    intentionally not treated as anchoring-triggering (see §10
    "Exec-at-execveat (abspath form only)") to keep the cost model
    for `rw,noexec` ancestors bearable.  Consequently, any syscall
    whose exec check the kernel performs against a held fd's
    vfsmount fails if that fd was acquired before the exec grant:
    - **`mmap(PROT_EXEC, fd, ...)`**: `mmap_region` calls
      `path_noexec(&file->f_path)`; on `noexec`, `VM_MAYEXEC` is
      stripped and `PROT_EXEC` returns `EPERM`.  No subsequent
      `mprotect` can recover.
    - **`execveat(dirfd, "relpath", ...)`** with relative path:
      kernel resolves from `dirfd`'s `struct path`; `path_noexec`
      against `dirfd`'s mount fails with `EACCES`.  The supervisor
      cannot rewrite the syscall args, and the abspath exec mount
      is unreachable from the dirfd's resolution root.
    - **`execveat(fd, "", AT_EMPTY_PATH)`** (`fexecve` /
      `execveat`-on-fd): same check against `fd`'s mount.

    Scope and workarounds:
    - Dynamic linkers (glibc ld.so, musl) re-open the .so by
      abspath, so library loading is unaffected.
    - Shell-style `execve("/abs/path", ...)` and
      `execveat(AT_FDCWD, "/abs/path", ...)` are handled by
      `Exec-at-execveat` and do work.
    - `execveat(dirfd, path)` with an abspath also works (kernel
      ignores dirfd when path is absolute).
    - Apps that need exec through pre-grant fds must either
      re-open by abspath after the grant, or the policy author
      grants exec on the relevant subtree **before** the original
      open so the fd is anchored on an exec mount.

## Changes needed (relative to current code)

### `BindMountSandbox`

- `new(...)`: insert the scratch-tmpfs step between namespace creation
  and the existing `root_tmpfs` overlay.  Store `m1_scratch_fd: ForeignFd`.
- New low-level primitive `park_to_scratch(path, uuid) -> Result<()>`
  and `restore_from_scratch(uuid, dest_path) -> Result<()>`.  Both
  fork into m1, open the path via openat2 (RESOLVE_NO_SYMLINKS |
  RESOLVE_IN_ROOT) for the source, and `move_mount` to/from
  `scratch_fd/uuid`.
- `unmount(path)`: stop using `MNT_DETACH` by default.  Add a
  `forcibly: bool` parameter.
- `mount_host_into_sandbox_impl`: unchanged in spirit but should
  expose enough hooks that the planner can drive it without going
  through the placeholder-creation path (already true via
  `create_placeholders: bool`).
- `set_mount_attr(path, new, old)`: unchanged, but the planner is now
  the only caller for the managed layer.

### `ManagedBindMountSandbox`

- `current_mount_tree` value type → `MountInternal` (currently just
  `ManagedMountPoint`).  No behavioral change yet but lets us add
  internal state later (e.g. "parked_at" for crash recovery).
- Owns or wraps `TurnstileTracer`.  Exposes `yield_request` directly
  (callers continue to drive the request loop).  Internally, when
  `allow()` is called on a `linkat`/`renameat`/`renameat2` request,
  the library performs the syscall in m1 via abspaths and returns
  the result through `seccomp_notif_resp` (no CONTINUE).  All other
  allowed requests just CONTINUE.
- New `interactions_tree: Mutex<FsTree<InteractionEntry>>`.  Merged
  with the user policy tree at reconcile time to form the effective
  desired tree.
- New public method `note_path_interaction`.  The library decides
  internally whether to add a bind mount, mirror a placeholder, or
  no-op (e.g. `/` or supervisor-cannot-write).
- `reconcile`: rewritten as plan-then-execute.  The plan stage walks
  the diff and emits `HighLevelOp`s.  The execute stage runs them
  with full context (including ability to enumerate sub-mounts under
  a parent for `ShadowAdd` and `ScrubAndUnmount`).
- New helper on `FsTree`:
  ```rust
  pub fn walk_subtree_top_down<F>(&self, root: &OsStr, f: F);
  pub fn first_data_descendants<F>(&self, root: &OsStr, f: F);
  ```
  for enumerating "all data entries under a subtree" and "direct-most
  data entries under a subtree" respectively.

### `turnstile-sandbox` bin

- Replace direct `add_or_update_mount` calls in the request loop with
  `note_path_interaction` calls.  The library decides which mounts to
  create.  The bin decides what category each request maps to:
  - `FsOpen` with `O_PATH` flag → `AnchoringOpen`.
  - `FsOpen` with `O_RDONLY|O_DIRECTORY` (non-`O_PATH` dir open) →
    `AnchoringOpen` (the dirfd will outlive the syscall and be used
    in further `*at` calls).
  - `FsOpen` with read → `ReadFile`; write → `WriteFile`; exec →
    `ExecFile`.
  - `FsChdir` → `AnchoringOpen` on the target.
  - `FsStat` / `FsAccess` / `FsReadlink` → `PlaceholderMirror`.
  - Other operations (`FsCreate`, `FsUnlink`, `FsLink`, `FsRename`)
    → only register access kind (no anchor needed; they don't
    produce long-lived references).
- `--permissive` mode becomes: `note_path_interaction` for every
  observed access, regardless of whether the user has explicitly
  granted it.  In strict mode, only observed accesses that match an
  explicit grant trigger interactions.

### `design.md`

Update to reflect the new model.  This file becomes the basis.

## Additional problems / open questions

A. **What if the host fs doesn't contain the dentry we want to
   anchor on?**  The kernel requires the mountpoint dentry to exist.
   For "we want to bind /foo/bar at /foo/bar in the sandbox", the
   host's bind source must contain `bar`.  This is the normal case.
   For chdir into a path that doesn't exist on host: the sandboxed
   app would already have got `ENOENT` from the kernel, so we never
   see the interaction.  Not a problem.

B. **What if the policy user changes the placeholder for a path
   simultaneously with an interaction-driven anchor mount at that
   path?**  The interaction tree only contains mount entries (not
   placeholders).  Conflict resolution: policy wins on placeholders
   (placeholders are policy-only), interactions can add a mount on
   top, both apply.

C. **What if the app upgrades a fd's attrs (open + write) and we
   set_mount_attr-rw, then the policy revokes write?**  Tightening
   ro → write attempts EROFS.  Documented above; no workaround.

D. **What if a `ShadowAdd` enumerates sub-mounts that aren't directly
   reachable through the new parent's host fs?**  Example: parent
   host fs is `/var/empty` (no children), but current_mt has a sub-mount
   at `parent/foo`.  The new parent's overlay doesn't contain a `foo`
   dentry → `move_mount` fails.  Detectable; the planner should
   either skip such children (leaving them under the old shadowed
   parent, which works but leaks identity) or refuse the `Added`
   entirely.  Probably warn and skip; child stays beneath the
   shadowed old parent mount, which still anchors it.

E. **Concurrency.**  The lock pattern is unchanged: take both trees'
   lock, plan, execute, release.  Multiple seccomp-notify worker
   threads can call `check_covered` in parallel under reader locks;
   `note_path_interaction` and `update_*` take writer locks.

F. **Crash recovery.**  If the supervisor crashes mid-reconcile (e.g.
   during a `ScrubAndUnmount` where children are in scratch and the
   parent is umounted but children not yet restored), the namespaces
   die with the supervisor process and the whole sandbox is gone.
   No external state to recover.  The sandbox is single-process
   stateful, not persistent.

G. **Mount propagation.**  `fsmount` produces private mounts.  We
   never set `MS_SHARED` anywhere; host changes do not propagate
   into the sandbox.  Confirmed.

H. **`m1_scratch_fd` lifecycle.**  Lives for the sandbox's lifetime.
   Holding it is fine — scratch is meant to stay alive.  On sandbox
   drop, namespaces tear down and the scratch is released
   automatically.

---

# Scenario walk-throughs

These exercise the design.  For each, we describe initial state,
incoming event, planned operations, and expected outcome.

Notation:
- `policy` = user's explicit desired tree.
- `interactions` = library-maintained interaction tree.
- `current_mt` = active mounts at start of step.

## Case 1 — Add a parent over an existing child (with cwd inside child)

**Initial state**
- `policy = { /a/b/c: rw }`
- `current_mt = { /a/b/c: rw }`
- Sandbox cwd = `/a/b/c`

**Event**: app opens `/a/b` absolute path.

**Library behavior**:
1. Bin calls `note_path_interaction("/a/b", ResolveOnlyFile)` (or
   `ChdirOrOpathDir` depending on what the app actually requested;
   say it's an open of a dir).  Library upgrades to a `ro,noexec`
   mount at `/a/b`.
2. Library asks the policy author to confirm via the existing prompt
   path.  Author allows `/a` rw.
3. `policy = { /a: rw, /a/b/c: rw }`.
4. Reconcile:
   - Diff vs current_mt: `Added(/a, rw)`, `Updated(/a/b/c, rw, rw)`.
   - Planner sees `Added(/a)` with sub-mount `/a/b/c` already in
     current_mt → `ShadowAdd("/a", host=/a, rw, children=["/a/b/c"])`.
   - `Updated(/a/b/c, rw, rw)` → noop (attrs unchanged).
5. Execute `ShadowAdd`:
   - Create ancestor placeholders for `/a` (already done in phase 1).
   - Bind-mount host `/a` at `/a` rw.  This shadows the existing
     `/a/b/c` mount in the namespace tree.
   - Acquire `fd1 = openat2("/a/b/c", O_PATH)` from m1.  This opens
     the still-existing-but-shadowed `/a/b/c` mount because path
     resolution from m1's root walks through the old `/a` mount
     first... wait.

   ⚠️  **Subtle point**: after the new `/a` bind shadows the old
   layout, path resolution to `/a/b/c` from a fresh openat in m1 now
   goes through the **new** `/a` overlay, not the old `/a/b/c`
   mount.  The old `/a/b/c` mount is still alive but anchored
   beneath the new `/a` overlay's dentry tree.  We can't get a fd to
   the old `/a/b/c` mount via path lookup anymore.

   **Resolution**: acquire `fd1` *before* the `ShadowAdd`-internal
   bind-mount of the new parent.  Plan order:
   1. `fd1 = openat2("/a/b/c", O_PATH)` (still resolves to the
      child mount because the new parent isn't mounted yet).
   2. Bind-mount host `/a` at `/a`.
   3. `move_mount(fd1, "", AT_FDCWD, "/a/b/c", MOVE_MOUNT_F_EMPTY_PATH)`.
      Target `/a/b/c` resolves in the new overlay; the child mount
      relocates on top.
   4. `close(fd1)`.

   The planner for `ShadowAdd` must enforce this ordering: open
   children first, then mount parent, then move children.

6. Outcome:
   - `/a` rw mount in place.
   - `/a/b/c` is the same `struct mount` as before, anchored on the
     new `/a` overlay's `b/c` dentry.
   - App's cwd's struct path is `(child_mount, root_dentry_of_child)`;
     unchanged; `..` from cwd now leads to the new `/a/b` (inside
     new `/a` mount) which is what the app expected.
   - Open of `/a/b` succeeds; sees host `/a/b` contents.

**Expected**: yes.

**Variant — same starting state, policy becomes just `{ /a: rw }`
(no `/a/b/c`)**:

1. Diff: `Added(/a, rw)`, `Removed(/a/b/c)`.
2. Planner: `Added(/a)` with sub-mount `/a/b/c` → `ShadowAdd("/a",
   children=["/a/b/c"])`.  Even though `/a/b/c` is also being
   removed, the `ShadowAdd` still moves it (because we don't know
   yet whether the umount will succeed).
3. Then `Removed(/a/b/c)` → try `umount("/a/b/c")`.  EBUSY (cwd
   holds it).  `SetAttrToCovering("/a/b/c")` finds `/a` rw in
   desired and applies rw → noop since it was already rw.  Entry
   stays in `current_mt` with attrs rw.
4. Outcome:
   - `/a` rw.
   - `/a/b/c` rw (kept due to cwd).
   - Next reconcile, if cwd has moved away, the still-Removed
     `/a/b/c` is umounted.

**Optimization note**: when `Removed(C)` immediately follows
`ShadowAdd(P, children including C)`, we could skip the move_mount
of C in the ShadowAdd (since we'll try to drop C anyway), then drop
C straight from under the shadowed-old-P, then umount old P entirely.
The cwd-EBUSY case still needs the move, so the cheap path is to
always move and rely on the subsequent Removed try-umount.  Add a
TODO for the optimization.

## Case 2 — Add a parent ro, with rw child (cwd inside child, .. across mount)

**Initial state**
- `policy = { /a/b/c: rw }`
- `current_mt = { /a/b/c: rw }`
- Sandbox cwd = `/a/b/c`

**Event**: app opens `../d` (= `/a/b/d`).

**Library behavior**:
1. `note_path_interaction("/a/b/d", ReadFile)`.  Interaction adds
   `{ /a/b/d: ro,noexec }`.  Reconcile required.
2. Policy author is prompted; allows `/a/b ro`.
3. `policy = { /a/b: ro, /a/b/c: rw }`, `interactions = { /a/b/d:
   ro,noexec }`.  Effective desired = `{ /a/b: ro, /a/b/c: rw, /a/b/d:
   ro,noexec }`.
4. Diff vs `current_mt`: `Added(/a/b, ro)`, `Updated(/a/b/c)`,
   `Added(/a/b/d)`.
5. Planner:
   - `Added(/a/b)` with sub-mount `/a/b/c` → `ShadowAdd("/a/b",
     host=/a/b, ro, children=["/a/b/c"])`.
   - `Updated(/a/b/c, rw, rw)` → noop.
   - `Added(/a/b/d)` → plain `Mount(/a/b/d, host=/a/b/d, ro,noexec)`.
6. Execute:
   - Pre-open `fd1 = openat2("/a/b/c", O_PATH)`.
   - Bind-mount host `/a/b` at `/a/b` ro.
   - `move_mount(fd1, "", AT_FDCWD, "/a/b/c", MOVE_MOUNT_F_EMPTY_PATH)`.
   - Bind-mount host `/a/b/d` at `/a/b/d` ro,noexec.
7. Outcome:
   - `/a/b` ro mount, with `/a/b/c` (same struct mount as before) on
     top at `b/c`, and `/a/b/d` ro mount on top at `b/d`.
   - App's cwd is still on the same `struct mount`.
   - `..` from cwd → reaches the new `/a/b` mount's `b` dentry.
     This is the host's `/a/b` rendered through the new ro mount.
   - `openat(cwd_dirfd, "../d")` walks `..` (crosses to new /a/b
     mount) then `d` (crosses into new /a/b/d mount) → succeeds with
     ro access.

**Expected**: yes.

## Case 3 — Remove a parent, with held child

**Initial state**
- `policy = { /a: ro, /a/b/c: rw }`
- `current_mt = { /a: ro, /a/b/c: rw }`
- App has an O_PATH fd on `/a/b/c/file`.

**Event**: policy author removes `/a` from policy.  New `policy = {
/a/b/c: rw }`.

**Library behavior**:
1. Diff: `Removed(/a)`, `Updated(/a/b/c, rw, rw)`.
2. Planner:
   - Removed walk is bottom-up.  No mounts strictly under `/a` are
     being removed (only `/a/b/c`, but it's in desired); so the
     enumeration of `Removed` items under `/a` is empty.  `Removed(/a)`
     → try `umount("/a")` non-detach.
   - But: `current_mt` has `/a/b/c` strictly under `/a`, which is
     *kept* (it's in desired).  So the planner sees `kept_children =
     [/a/b/c]` and emits `ScrubAndUnmount("/a", keep_children=[
     "/a/b/c"])`.
3. Execute:
   - `fd1 = openat2("/a/b/c", O_PATH)` (still in the namespace).
   - `move_mount(fd1, "", m1_scratch_fd, "<uuid>", MOVE_MOUNT_F_EMPTY_PATH)`.
     `/a/b/c` is now parked.
   - `umount("/a")` succeeds (no sub-mounts left under it).
   - Recreate placeholder hierarchy: `/a` was a mount, now it's
     gone; the underlying tmpfs at `/a` needs `mkdir /a/b/c` as
     placeholder so the restore target exists.  The library creates
     `/a` placeholder dir and `/a/b/c` placeholder dir on root_tmpfs
     (or whatever is now the underlying layer).
   - `move_mount(fd1, "", AT_FDCWD, "/a/b/c", MOVE_MOUNT_F_EMPTY_PATH)`.
4. Outcome:
   - `/a` is no longer a mount (root_tmpfs's `/a` placeholder dir
     visible).
   - `/a/b/c` is the same `struct mount` as before, now mounted on
     the root_tmpfs `/a/b/c` placeholder dentry.
   - App's fd to `/a/b/c/file` still works; its `struct path` has
     vfsmount = the (same) child mount; reads succeed.
   - `..` from inside that fd's mount reaches root_tmpfs `/a/b`
     (placeholder), not host `/a/b`.  App sees an empty
     placeholder dir.  This is the trade-off of removing `/a`.

**Expected**: yes — the policy author revoked `/a`, so seeing
placeholder rather than host content is correct.

## Case 4 — Remove a parent, with EBUSY on both parent and held child

**Initial state**
- `policy = { /a: ro, /a/b: rw }`
- `current_mt = { /a: ro, /a/b: rw }`
- App has cwd on `/a/b` and a held fd on `/a` itself (`O_PATH` on
  the dir).

**Event**: `policy = { /a/b: rw }` (drop /a).

**Library behavior**:
1. Diff: `Removed(/a)`, `Updated(/a/b)`.
2. Planner: `Removed(/a)` with kept_child `/a/b` → `ScrubAndUnmount`.
3. Execute:
   - `fd_child = openat2("/a/b", O_PATH)`.
   - `move_mount(fd_child → scratch/<uuid>)`.
   - `umount("/a")` → EBUSY (the app's held O_PATH on `/a`).
   - Restore: `move_mount(fd_child → "/a/b")`.  The target `/a/b`
     resolves through the still-alive `/a` mount, into its `b`
     dentry → the child re-attaches on top.
   - Emit `SetAttrToCovering(/a)`: no desired entry covers `/a`,
     default `ro,noexec` → already ro,noexec, noop.
   - `current_mt` keeps both `/a` and `/a/b`.
4. Next reconcile, if app has dropped its `/a` fd, the still-Removed
   `/a` succeeds in umount.

**Expected**: yes — best effort, eventual consistency.

## Case 5 — `chdir` into a placeholder dir before mounting

**Initial state**
- `policy = {}`
- `current_mt = {}` (just root_tmpfs)
- Bin starts the sandboxed process with cwd `/home/mao/turnstile`
  (because that's the supervisor's cwd).

**Event**: bin's `run_command` does `create_placeholder_hierarchy("
/home/mao/turnstile", true)` then chdir.  Then the app starts.

**Library behavior** (under the new design):
1. `BindMountSandbox::run_command` calls
   `note_path_interaction(cwd, ChdirOrOpathDir)` *before* the
   pre_exec chdir.  The library reconciles.
2. Reconcile: `interactions = { /home/mao/turnstile: ro,noexec }`.
3. Plan: `Added(/home/mao/turnstile)` → plain Mount (no children).
4. Execute: bind-mount host `/home/mao/turnstile` at the same path
   ro,noexec.
5. Then pre_exec chdirs.  The cwd's `struct path` is `(new_mount,
   mount_root_dentry)`.

**Expected**: yes.  If we'd skipped the interaction call and merely
created the placeholder, the chdir would land the cwd on
root_tmpfs's placeholder dentry and the app would forever read an
empty dir.

## Case 6 — Resolve-only on a regular file

**Initial state**
- `policy = { /lib: rx }`
- `current_mt = { /lib: rx }` (rx = readonly, executable)

**Event**: app does `openat(O_PATH | O_NOFOLLOW, "/etc/passwd")`.

**Library behavior**:
1. Bin's `as_rwx_permissions` reports `rwxp = { read=false,
   write=false, exec=false }` (resolve-only).
2. New rule: resolve-only on a regular file is upgraded to read.
   Bin calls `note_path_interaction("/etc/passwd", ResolveOnlyFile)`.
3. Library upgrades internally to `ReadFile` → adds
   `{ /etc/passwd: ro,noexec }` to `interactions`.
4. Reconcile → `Added(/etc/passwd)` → plain Mount.
5. App's `O_PATH` fd ends up on the new mount.

**Expected**: yes.  Future read via `/proc/self/fd/N` re-open will
work (the fd is anchored on the right mount).

## Case 7 — host_path change (ReplaceHostPath)

**Initial state**
- `policy = { /work: rw → host /tmp/work-a }`
- `current_mt = { /work: rw → host /tmp/work-a }`

**Event**: policy updated to `/work: rw → host /tmp/work-b`.

**Library behavior**:
1. Diff: `split_on(host_path mismatch)` fires → `Removed(/work →
   host /tmp/work-a)` then `Added(/work → host /tmp/work-b)`.
2. Planner pair-matches these into `ReplaceHostPath("/work",
   new_host=/tmp/work-b, new_attrs=rw)`.
3. Execute:
   - Try `umount("/work")`.
   - If Ok: `Mount("/work", /tmp/work-b, rw)`.  Clean replacement.
   - If EBUSY (app has fds open in /work):
     - Bind-mount /tmp/work-b on top of the existing /work.
     - The app's held fds still reference the old (now-shadowed)
       /work → /tmp/work-a mount.
     - The library records that current_mt's `/work` host is
       /tmp/work-b (top-of-stack); the old /tmp/work-a layer is
       not separately tracked (we accept identity loss for files
       per the host_path-change decision).

**Expected**: yes, with the documented identity-loss caveat.

## Case 8 — Interactions exceed mount-max

**Initial state**: deep dir tree, app chdirs through many paths
during a build (`cd a; cd b; cd c; ...`).

**Behavior**: each chdir adds an interaction → next reconcile mounts
the new path.  Each subsequent chdir-away triggers `Removed`
attempts on previous chdir dirs.

- If the app *only* held the cwd (no leftover fds), `umount` succeeds
  → the mount is reclaimed.  Mount count stays small.
- If the app holds fds on intermediate paths, those mounts stick
  around until the fds close.

If somehow the app pathologically holds 100k distinct fds open, the
sandbox hits `fs.mount-max` → `bind` syscall fails.  The library
should propagate the error (currently `MountFailed`) and the bin
should refuse further interactions.  Not a graceful degradation but
a hard limit; documented.

**Expected**: yes, with a known cap.

## Case 9 — Concurrent reconciles

**Initial state**: two seccomp-notify worker threads.

**Event**: worker A calls `note_path_interaction(/foo, ReadFile)`;
worker B calls `note_path_interaction(/bar, ReadFile)` concurrently.

**Behavior**: each `note_path_interaction` takes the trees lock,
mutates the interactions tree, runs reconcile, releases.  The two
calls serialize.  Worker B sees worker A's `/foo` mount as part of
`current_mt` when it builds its own reconcile.  No interleaving.

**Expected**: yes.

## Case 10 — App writes to a file under a ro mount, then policy upgrades

**Initial state**
- `policy = { /home/x: ro }`
- App holds `fd = openat("/home/x/file", O_RDONLY)`.

**Event 1**: app calls `write(fd, ...)`.  Kernel returns `EBADF`
(fd wasn't opened for writing) — no seccomp involvement.

**Event 2**: app calls `openat(AT_FDCWD, "/home/x/file", O_WRONLY)`.
Bin calls `note_path_interaction("/home/x/file", WriteFile)`.

**Library behavior**:
1. Interactions tree adds `{ /home/x/file: rw,noexec }`.
2. Library asks policy author; granted.  `policy = { /home/x: ro,
   /home/x/file: rw }`.
3. Reconcile: `Added(/home/x/file: rw)`, ShadowAdd? No — `Added`
   only triggers ShadowAdd if existing sub-mounts are under it;
   `/home/x/file` is a leaf with no sub-mounts.  Plain Mount.
4. The new bind mount sits on top of `(/home/x mount,
   file_dentry)`.  Future opens of `/home/x/file` cross into it.
5. The app's existing `O_RDONLY` fd's struct path is `(/home/x
   mount, file_dentry)` — *not* on the new mount.  Reads still go
   through the ro mount (still works for reading).  Writes through
   the new path resolution work via the new rw mount.

**Expected**: yes.  An app holding a *write* fd predating the
upgrade isn't possible (couldn't open for write while the mount was
ro), so the only fds that survive the upgrade are read-only ones,
and they keep working through the ro layer.

## Case 11 — Re-add a previously-removed path with same host_path

**Initial state**: `policy = { /var: rw }`, then policy author
removes `/var`, then re-adds `/var: rw` later.

**Behavior**:
1. After first removal: `Removed(/var)` → try umount.
   - If app didn't hold it: umount succeeds, `current_mt = {}`.
   - If held: EBUSY, `current_mt` keeps `/var` with default attrs.
2. Re-add: diff vs `current_mt`:
   - If `/var` was removed: `Added(/var, rw)` → plain Mount.  Fresh
     `struct mount`.  Any old held fds (if there were any to
     placeholder dentries) don't migrate.
   - If `/var` was EBUSY-kept: `Updated(/var, rw, default)` →
     SetAttr.  Same `struct mount` throughout; held fds keep
     working with rw attrs.

**Expected**: yes.  Identity is preserved across remove/re-add when
something held the mount; it's not preserved when the mount was
actually torn down.  Reasonable trade-off.

---

## Open TODOs / future work

- Interaction-handle-based deregistration (no longer sticky).
- Optimization: skip move_mount in `ShadowAdd` for children that
  are being `Removed` in the same plan.
- Optional "panic mode": kill the sandboxed process if a reconcile
  failure would leave attrs more permissive than policy requires.
- Better diagnostics: emit a structured event when a `umount`
  EBUSY's so policy authors can debug "why is this mount sticking
  around".
- Telemetry on `fs.mount-max` headroom.
- A "graceful revoke" API that combines policy removal with
  pidfd-based SIGTERM/SIGKILL of any process still referencing the
  about-to-be-removed mount, for true revocation.
