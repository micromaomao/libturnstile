## BindMountSandbox

`BindMountSandbox` is a low-level sandbox built on top of Linux mount and
user namespaces.  It owns:

- A set of managed namespaces (`m0` outer mount ns, `m1` inner mount ns,
  user ns, pid ns) via `ManagedNamespaces`.
- An anonymous, detached `tmpfs` (`root_tmpfs`) that acts as the
  sandbox's root filesystem.  Everything visible inside the sandbox is
  either this tmpfs or a bind mount layered onto it.
- A `host_root_fd` (`O_PATH` to `/` opened from inside `m0`) used to
  resolve caller-provided host paths so that resulting fds carry m0's
  mount namespace, which `open_tree()` needs.

It exposes thin, imperative primitives:

- `create_placeholder_hierarchy(path, leaf_is_dir)` walks the tmpfs and
  creates any missing intermediate directories with default modes, and
  ensures the leaf exists as the requested type.  Returns an `O_PATH`
  fd to the leaf.
- `create_placeholder_symlink(linkpath, target)` is the symlink
  equivalent.
- `remove_placeholder(path)` recursively removes a path from the tmpfs;
  ENOENT anywhere on the way is silently treated as success.
- `mount_host_into_sandbox(host, ns_path).attributes(...).mount()` bind-
  mounts a host path into the sandbox.  Internally this opens the host
  source under `host_root_fd`, optionally creates the placeholder
  hierarchy in the tmpfs (`create_placeholders` flag on
  `mount_host_into_sandbox_impl`), forks a helper that enters `m0` to
  call `open_tree()` on the source and then enters `m1` to mount it at
  `ns_path`.
- `unmount(ns_path)` and `set_mount_attr(ns_path, new, old)` adjust
  existing mounts from inside `m1`.
- `stat_host(host_path)` and `open_sandbox_parent(sandbox_path)` are
  helpers used by the managed layer.
- `restrict_self()` / `run_command()` join the current thread (or a
  freshly forked child via `pre_exec`) into the sandbox's namespaces.

Path resolution is hardened: host fds are opened with
`RESOLVE_NO_SYMLINKS` unless the caller explicitly opts in, and sandbox
paths use `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`.  Mount and unmount
operations always happen inside a fork to avoid disturbing the parent
process's namespace membership.

`BindMountSandbox` does not track what it has mounted or created — each
call is independent.  Tracking is the job of `ManagedBindMountSandbox`.

## ManagedBindMountSandbox

`ManagedBindMountSandbox` wraps `BindMountSandbox` and turns it into a
declarative, idempotent state manager keyed on a desired tree of
entries.  An entry (`ManagedTreeEntry`) is either:

- `Placeholder(ManagedPlaceholder)` — a user-controlled file, directory
  or symlink that lives in the backing tmpfs (with caller-supplied
  mode, timestamps, and, for symlinks, target), or
- `BindMount(ManagedMountPoint)` — a bind mount from a host path with
  given `MountAttributes`.

The internal state is split into two `FsTree`s guarded by separate
mutexes (locked together in a fixed order):

- `current_placeholder_tree: FsTree<ManagedPlaceholder>` — every
  placeholder we actively own in the tmpfs, including synthesized
  ancestor directories for mounts.
- `current_mount_tree: FsTree<ManagedMountPoint>` — every bind mount
  currently active.

The split is what makes cleanup tractable: mounts and the placeholders
they sit on top of are tracked independently, so removing a mount does
not implicitly drop user-specified placeholders that share a prefix,
and removing a placeholder does not interact with mount lifecycles.

### Reconcile algorithm

`update_from_tree(desired_entries)` (and all the convenience wrappers,
including the back-compat `update_mounts_from_*`) goes through these
phases:

1. **Build desired placeholder tree and desired mount tree** from
   `desired_entries` via a top-down walk:
   - A `Placeholder` entry is inserted as-is into the placeholder tree.
   - A `BindMount` entry is inserted into the mount tree.  If no
     placeholder for this path is already in the desired placeholder
     tree, we `stat_host()` the source to decide whether to synthesize
     a default-dir or default-file placeholder.
   - For every entry, every ancestor path also gets a default-dir
     placeholder in the desired placeholder tree, so creation order
     naturally flows parent-before-child.
   - The path `/` is special: it never gets a placeholder (it is the
     tmpfs root) but it can be a mount target.

2. **Create / update placeholders** by diffing
   `current_placeholder_tree → desired_placeholder_tree`.  `Added` and
   `Updated` invoke `create_or_update_placeholder` on the parent dirfd
   (which the previous diff step has already created); `Removed` is
   ignored in this phase.

3. **Apply mount changes** by diffing
   `current_mount_tree → desired_mount_tree`:
   - `Removed` → `unmount`.
   - `Added` → `mount_host_into_sandbox_impl(..., create_placeholders =
     false)`: the placeholder was already created in phase 2.
   - `Updated` → `set_mount_attr` for an attribute change.  A change in
     `host_path` is signalled to `diff` via the `split_on` predicate so
     it becomes a `Removed` + `Added` pair instead of an in-place
     update.

4. **Remove unused placeholders** by diffing
   `current_placeholder_tree → desired_placeholder_tree` again, acting
   only on `Removed`.  Bottom-up order is provided by `FsTree::diff`'s
   one-sided walk, so child entries are unlinked before their
   ancestors.

If any phase fails, the partial progress is still committed to the
internal trees so the next reconcile picks up where the previous one
left off.

### Convenience APIs

- `add_or_update_entry(path, entry)`, `add_or_update_mount(path, mp)`,
  `add_or_update_placeholder(path, ph)`, `remove_entry(path)`,
  `remove_mount(path)` — point updates that internally rebuild the
  desired tree from the current state, apply the single mutation, and
  reconcile.
- `update_from_list`, `update_mounts_from_list`,
  `update_mounts_from_tree` — bulk variants.
- `check_covered(path, need_write, need_exec)` — read-only query
  against `current_mount_tree`.
- `restrict_self`, `run_command`, `root_in_sandbox` — pass-throughs to
  the underlying `BindMountSandbox`.
