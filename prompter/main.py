#!/usr/bin/env python3

"""Interactive GUI prompter for turnstile-sandbox.

Reads a single ``PrompterRequest`` JSON object on stdin and writes a
single ``PrompterResponse`` JSON object on stdout (see
``src/bin/prompter.rs`` for the protocol).

The window shows the sandbox launch command, the access the sandboxed
process is asking for, and an editable filesystem tree of r/w/x
checkboxes.  The user can grant access at the requested paths or widen it
to parent directories, then *Continue* (grant + let the syscall proceed)
or *Cancel and deny* (reject with ``EPERM``).

Simplifications (left as TODO for now):
  * Resolve-only requests (no r/w/x needed, just path resolution) are
    always allowed by emitting ``match_host`` placeholders; they are not
    shown in the tree.

When "Persist these rules in the config" is checked, the granted mounts
are written into the YAML config file named in the request (parsed,
modified, written to a sibling temp file, then atomically moved onto the
config path) and ``reload_config`` is set instead of emitting
``add_mounts``.
"""

import json
import os
import sys
import tempfile

from PySide6 import QtCore, QtGui, QtWidgets


EPERM = 1

# Pixels of indentation per filesystem-tree depth level.
INDENT_PX = 22

# Window-scale (Ctrl+scroll zoom) bounds and step.
MIN_SCALE = 0.5
MAX_SCALE = 4.0
SCALE_STEP = 0.1


def config_path():
    """Path to the prompter's persisted settings file."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(base, "turnstile-prompter", "settings.json")


def load_scale():
    """Load the persisted window scale factor (defaults to 1.0)."""
    try:
        with open(config_path()) as f:
            return float(json.load(f).get("scale", 1.0))
    except (OSError, ValueError, json.JSONDecodeError):
        return 1.0


def save_scale(scale):
    """Persist the window scale factor, best-effort."""
    path = config_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"scale": scale}, f)
    except OSError:
        pass


class ScaleManager:
    """Live, persisted UI scaling driven by the application font size.

    Most Qt widgets size themselves from the font, so scaling the font
    scales the whole dialog.  The chosen factor is remembered in the
    config file so the next prompt opens at the same size.
    """

    def __init__(self, app):
        self.app = app
        self.base_font = app.font()
        self.base_pt = self.base_font.pointSizeF()
        if self.base_pt <= 0:
            self.base_pt = 10.0
        self.scale = max(MIN_SCALE, min(MAX_SCALE, load_scale()))

    def apply(self, root=None):
        """Apply the current scale to the app and an optional widget tree."""
        font = QtGui.QFont(self.base_font)
        font.setPointSizeF(self.base_pt * self.scale)
        self.app.setFont(font)
        if root is not None:
            root.setFont(font)
            for child in root.findChildren(QtWidgets.QWidget):
                child.setFont(font)

    def zoom(self, steps):
        """Adjust the scale by ``steps`` (each ``SCALE_STEP``) and persist."""
        new = max(MIN_SCALE, min(MAX_SCALE, self.scale + steps * SCALE_STEP))
        if new == self.scale:
            return False
        self.scale = new
        save_scale(self.scale)
        return True


def perm_string(attrs):
    """Build a config permission string ("r"/"rw"/"rx"/"rwx") from attrs."""
    s = "r"
    if not attrs.get("readonly", True):
        s += "w"
    if not attrs.get("noexec", True):
        s += "x"
    return s


def escape_config_path(path):
    """Escape a literal path for the config's ``$``-expansion syntax.

    turnstile-sandbox expands ``$$`` to ``$`` and ``$VAR`` to an
    environment variable when loading rule keys/targets, so a literal
    ``$`` in a host path must be doubled to round-trip unchanged.
    """
    return path.replace("$", "$$")


def persist_to_config(config_path, mounts, ignores=()):
    """Write ``mounts`` and ``ignores`` into the YAML config.

    The file is parsed, the ``rules`` mapping is updated with one entry
    per mount (a plain permission string when the host path matches the
    sandbox path, otherwise a ``target``/``permissions`` mapping) and one
    ``ignore: true`` entry per ignored path, then serialized to a sibling
    temp file and atomically moved onto the config path so a concurrent
    reader never sees a partial file.
    """
    import yaml

    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        cfg = {}
    rules = cfg.get("rules")
    if not isinstance(rules, dict):
        rules = {}
        cfg["rules"] = rules

    for mount in mounts:
        sandbox_path = mount["mount_point"]
        host_path = mount["host_path"]
        perms = perm_string(mount.get("attrs", {}))
        key = escape_config_path(sandbox_path)
        if host_path == sandbox_path:
            rules[key] = perms
        else:
            rules[key] = {
                "target": escape_config_path(host_path),
                "permissions": perms,
            }

    for path in ignores:
        rules[escape_config_path(path)] = {"ignore": True}

    directory = os.path.dirname(config_path) or "."
    fd, tmp = tempfile.mkstemp(
        prefix=".turnstile-config-", suffix=".yaml", dir=directory
    )
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
        os.replace(tmp, config_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def needed_perms(perm):
    """Return (need_read, need_write, need_exec) for a rwx_permission."""
    need_read = bool(perm.get("read")) or bool(perm.get("chdir"))
    need_write = bool(perm.get("write"))
    need_exec = bool(perm.get("exec"))
    return need_read, need_write, need_exec


def rwx_string(need_read, need_write, need_exec):
    return (
        ("r" if need_read else "-")
        + ("w" if need_write else "-")
        + ("x" if need_exec else "-")
    )


def target_path(perm):
    """The displayed/host path of a rwx_permission, normalised.

    rwx_permission targets are already symlink-free due to realpath,
    so collapsing ``.`` / ``..`` and redundant slashes lexically yields
    the real path.
    """
    return os.path.normpath(perm["target"]["path"])


def grant_path_for(perm, create_like=False):
    """Host path the permission is really required on.

    For directory operations (create / unlink / rename / ...) the
    permission is normally required on the *parent* directory of the
    target, so we grant there.

    Exception: for create-like operations (open ``O_CREAT``, mkdir,
    symlink, mknod) whose target *already exists* on the host, no entry
    will actually be created in the parent - continuing the syscall will
    instead open the existing entry or fail with ``EEXIST``.  In that case
    we can grant on the target itself rather than exposing write on the
    whole parent directory.  (The parent is still offered as a widen-able
    node in the tree if the user wants it.)
    """
    path = target_path(perm)
    if perm.get("is_dir_op"):
        if create_like and os.path.lexists(path):
            return path
        path = os.path.dirname(path.rstrip("/")) or "/"
    return path


def operation_name(access_request):
    """Best-effort human name of the operation, e.g. ``FsRename``."""
    op = access_request.get("operation")
    # op looks like {"FsOperation": {"FsRename": {...}}}
    if isinstance(op, dict):
        for _outer, inner in op.items():
            if isinstance(inner, dict):
                for variant in inner:
                    return variant
            return _outer
    return "operation"


class FsNode:
    """A node in the editable filesystem-permission tree."""

    def __init__(self, name, path, depth, parent):
        self.name = name
        self.path = path
        self.depth = depth
        self.parent = parent
        self.children = {}

        # The user's *direct* selection on this node (as opposed to
        # permissions inherited from an ancestor).
        self.own_r = False
        self.own_w = False
        self.own_x = False

        # Effective state after inheritance, filled in by TreeWidget.refresh.
        self.eff_r = False
        self.eff_w = False
        self.eff_x = False

        # Checkboxes, created lazily by TreeWidget.
        self.cb_r = None
        self.cb_w = None
        self.cb_x = None

        # Redirect state: when set, this node is mounted from a
        # user-specified host path (with full rwx) instead of its own path.
        self.redirect = None
        # own_r/w/x captured before a redirect forced them all on, so they
        # can be restored when the redirect is cleared.
        self.saved_own = None

        # Block state: when true, this node (and everything under it) is
        # emitted as an ``ignore: true`` config rule instead of a mount.
        self.block = False

        # Row widgets, created by TreeWidget.
        self.label = None
        self.redirect_btn = None
        self.block_btn = None
        # Every widget making up this node's row, so it can be shown/hidden.
        self.row_widgets = []

    def child(self, name):
        node = self.children.get(name)
        if node is None:
            if self.path == "/":
                path = "/" + name
            else:
                path = self.path + "/" + name
            node = FsNode(name, path, self.depth + 1, self)
            self.children[name] = node
        return node


class TreeWidget(QtWidgets.QWidget):
    """Editable filesystem-permission tree with r/w/x checkboxes per row.

    Rules implemented:
      * Checking ``w`` or ``x`` on a line also checks ``r`` on it, and
        deselecting ``r`` clears ``w`` and ``x``, since a mount always
        implies read.
      * Selecting a permission on a parent forces the same box checked and
        disabled on every descendant (inheritance).
    """

    # Emitted (with whether any row is currently blocked) whenever a
    # block toggle changes, so the dialog can force "persist to config".
    blocks_changed = QtCore.Signal(bool)

    def __init__(self, grants, allow_block=True, parent=None):
        super().__init__(parent)
        self.allow_block = allow_block
        self.root = FsNode("/", "/", 0, None)
        self._build(grants)

        self.nodes_preorder = []
        self._flatten(self.root)

        # Icons shown (only while a row is hovered) by the per-row redirect
        # button: an arrow to set a redirect, an "x" to clear one.
        style = self.style()
        self._arrow_icon = style.standardIcon(QtWidgets.QStyle.SP_ArrowRight)
        self._clear_icon = style.standardIcon(QtWidgets.QStyle.SP_LineEditClearButton)
        # The block ("prohibited") glyph shown by the per-row block toggle.
        self._block_glyph = "\U0001f6c7"

        # Hover bookkeeping for the redirect/block buttons.
        self._hovered = None
        self._node_of_widget = {}

        grid = QtWidgets.QGridLayout(self)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setHorizontalSpacing(6)
        grid.setVerticalSpacing(2)

        for row, node in enumerate(self.nodes_preorder):
            label = QtWidgets.QLabel(self._row_label_text(node))
            label.setContentsMargins(node.depth * INDENT_PX, 0, 0, 0)
            node.label = label

            # Mounts on "/" are unsupported, so the root gets no rwx
            # controls and no redirect - only its descendants are grantable.
            if node.depth == 0:
                grid.addWidget(label, row, 0)
                node.row_widgets = [label]
                continue

            # Redirect button: always present (so the column never reflows)
            # but only shows its icon while the row is hovered.
            btn = QtWidgets.QToolButton()
            btn.setAutoRaise(True)
            btn.setToolTip("Redirect this path to another host location")
            btn.clicked.connect(
                lambda _checked, n=node: self._on_redirect_clicked(n)
            )
            node.redirect_btn = btn

            # Block toggle: a push-down button that marks this path (and
            # everything under it) as ignored.  It shows its glyph while the
            # row is hovered or whenever it is checked.
            block_btn = QtWidgets.QToolButton()
            block_btn.setAutoRaise(True)
            block_btn.setCheckable(True)
            block_btn.setText(self._block_glyph)
            block_btn.setEnabled(self.allow_block)
            block_btn.setToolTip(
                "Block all further requests for or under this path"
            )
            block_btn.toggled.connect(
                lambda checked, n=node: self._on_block_toggled(n, checked)
            )
            node.block_btn = block_btn

            name_box = QtWidgets.QWidget()
            name_layout = QtWidgets.QHBoxLayout(name_box)
            name_layout.setContentsMargins(0, 0, 0, 0)
            name_layout.setSpacing(6)
            name_layout.addWidget(label)
            name_layout.addWidget(btn)
            name_layout.addWidget(block_btn)
            name_layout.addStretch(1)
            grid.addWidget(name_box, row, 0)

            node.cb_r = self._make_box(node, "r")
            node.cb_w = self._make_box(node, "w")
            node.cb_x = self._make_box(node, "x")
            grid.addWidget(node.cb_r, row, 1)
            grid.addWidget(node.cb_w, row, 2)
            grid.addWidget(node.cb_x, row, 3)

            # Track hover over every interactive widget in the row so the
            # redirect / block buttons reveal themselves.
            for w in (name_box, label, btn, block_btn, node.cb_r, node.cb_w, node.cb_x):
                self._node_of_widget[w] = node
                w.installEventFilter(self)

            node.row_widgets = [name_box, node.cb_r, node.cb_w, node.cb_x]

        grid.setColumnStretch(0, 1)
        # Absorb extra vertical space below the rows so they stay compact
        # at the top instead of spreading out when the window is tall.
        grid.setRowStretch(len(self.nodes_preorder), 1)
        self.refresh()
        self._update_visibility()

    def _update_visibility(self):
        """Hide rows whose ancestor is redirected/blocked (covered by it)."""
        for node in self.nodes_preorder:
            hidden = self._has_covering_ancestor(node)
            for w in node.row_widgets:
                w.setVisible(not hidden)

    def _has_covering_ancestor(self, node):
        """Whether any ancestor of ``node`` is redirected or blocked.

        Either makes ``node`` redundant: a redirected ancestor mounts the
        whole subtree, and a blocked ancestor ignores it entirely.
        """
        anc = node.parent
        while anc is not None:
            if anc.redirect is not None or anc.block:
                return True
            anc = anc.parent
        return False

    def _make_box(self, node, perm):
        box = QtWidgets.QCheckBox(perm)
        box.toggled.connect(
            lambda checked, n=node, p=perm: self._on_toggle(n, p, checked)
        )
        return box

    def _build(self, grants):
        """Insert every grant path into the trie and seed required perms."""
        for path, need_write, need_exec in grants:
            node = self.root
            for comp in path.strip("/").split("/"):
                if comp:
                    node = node.child(comp)
            # Mark this node as a requested grant target.  A mount always
            # grants read, so own_r is always set for a target.
            node.own_r = True
            node.own_w = node.own_w or need_write
            node.own_x = node.own_x or need_exec

    def _flatten(self, node):
        self.nodes_preorder.append(node)
        for _name, child in sorted(node.children.items()):
            self._flatten(child)

    def _row_label_text(self, node):
        """Display text for a node's row, including any redirect target."""
        if node.depth == 0 or node.children:
            text = node.name if node.depth == 0 else node.name + "/"
        else:
            text = node.name
        if node.redirect is not None:
            text += "  \u2192  " + node.redirect
        return text

    def _update_row_label(self, node):
        if node.label is not None:
            node.label.setText(self._row_label_text(node))

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.Enter:
            node = self._node_of_widget.get(obj)
            if node is not None:
                self._set_hovered(node)
        return super().eventFilter(obj, event)

    def leaveEvent(self, event):
        self._set_hovered(None)
        super().leaveEvent(event)

    def _set_hovered(self, node):
        """Reveal the redirect button on ``node``'s row, hide it elsewhere."""
        # When the whole tree is disabled (the request isn't being
        # granted), don't reveal any redirect button.
        if not self.isEnabled():
            node = None
        if node is self._hovered:
            return
        if self._hovered is not None and self._hovered.redirect_btn is not None:
            self._hovered.redirect_btn.setIcon(QtGui.QIcon())
        self._hovered = node
        if node is not None and node.redirect_btn is not None:
            self._update_redirect_button(node)

    def _update_redirect_button(self, node):
        """Set the redirect button's icon and tooltip for its current state."""
        btn = node.redirect_btn
        if btn is None:
            return
        if node.redirect is not None:
            btn.setIcon(self._clear_icon)
            btn.setToolTip("Clear redirection")
        else:
            btn.setIcon(self._arrow_icon)
            btn.setToolTip("Redirect this path to another host location")

    def _on_redirect_clicked(self, node):
        if node.redirect is not None:
            self._clear_redirect(node)
        else:
            self._set_redirect(node)

    def _node_is_dir(self, node):
        """Whether ``node`` denotes a directory (so we pick a dir chooser).

        Nodes with children are directories by construction; otherwise we
        fall back to inspecting the host path.
        """
        if node.children:
            return True
        try:
            return os.path.isdir(node.path)
        except OSError:
            return False

    def _set_redirect(self, node):
        """Ask for a host path and redirect ``node``'s mount there."""
        start = node.redirect or node.path
        if self._node_is_dir(node):
            path = QtWidgets.QFileDialog.getExistingDirectory(
                self, "Redirect %s to host directory" % node.path, start
            )
        else:
            path, _filter = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Redirect %s to host file" % node.path,
                os.path.dirname(start) or "/",
            )
        if not path:
            return
        path = path.strip()
        if not path:
            return
        # A redirect grants full rwx; remember the prior selection so it can
        # be restored if the redirect is later cleared.
        node.saved_own = (node.own_r, node.own_w, node.own_x)
        node.redirect = path
        node.own_r = node.own_w = node.own_x = True
        self._update_row_label(node)
        if node.redirect_btn is not None:
            self._update_redirect_button(node)
        self.refresh()
        self._update_visibility()

    def _clear_redirect(self, node):
        """Remove ``node``'s redirect and restore its original access."""
        node.redirect = None
        if node.saved_own is not None:
            node.own_r, node.own_w, node.own_x = node.saved_own
            node.saved_own = None
        self._update_row_label(node)
        if node.redirect_btn is not None:
            self._update_redirect_button(node)
        self.refresh()
        self._update_visibility()

    def _on_toggle(self, node, perm, checked):
        if perm == "r":
            node.own_r = checked
            if not checked:
                node.own_w = False
                node.own_x = False
        elif perm == "w":
            node.own_w = checked
            if checked:
                node.own_r = True
        else:
            node.own_x = checked
            if checked:
                node.own_r = True
        self.refresh()

    def _on_block_toggled(self, node, checked):
        """Mark/unmark ``node`` as blocked (passed through via ignore)."""
        node.block = checked
        # Blocking supersedes a redirect on the same row; drop it and
        # restore the grant the redirect had overridden.
        if checked and node.redirect is not None:
            node.redirect = None
            if node.saved_own is not None:
                node.own_r, node.own_w, node.own_x = node.saved_own
                node.saved_own = None
            self._update_row_label(node)
            if node.redirect_btn is not None:
                self._update_redirect_button(node)
        self.refresh()
        self._update_visibility()
        self.blocks_changed.emit(self.has_blocks())

    def refresh(self):
        """Recompute effective state and update every checkbox."""
        for node in self.nodes_preorder:  # parents before children
            pr = node.parent.eff_r if node.parent else False
            pw = node.parent.eff_w if node.parent else False
            px = node.parent.eff_x if node.parent else False

            node.eff_r = node.own_r or pr
            node.eff_w = node.own_w or pw
            node.eff_x = node.own_x or px

            if node.cb_r is None:
                # Root row (no rwx controls); nothing to update.
                continue

            # A blocked node grants nothing via a mount: its boxes are
            # cleared and disabled, and its redirect button is disabled.
            if node.block:
                for box in (node.cb_r, node.cb_w, node.cb_x):
                    box.blockSignals(True)
                    box.setChecked(False)
                    box.setEnabled(False)
                    box.blockSignals(False)
                if node.redirect_btn is not None:
                    node.redirect_btn.setEnabled(False)
                continue
            if node.redirect_btn is not None:
                node.redirect_btn.setEnabled(True)

            # A redirected node is locked at full rwx until the redirect is
            # cleared, so its boxes are checked and disabled.
            locked = node.redirect is not None
            for box, checked, enabled in (
                (node.cb_r, node.eff_r, not pr and not locked),
                (node.cb_w, node.eff_w, not pw and not locked),
                (node.cb_x, node.eff_x, not px and not locked),
            ):
                box.blockSignals(True)
                box.setChecked(checked)
                box.setEnabled(enabled)
                box.blockSignals(False)

    def mounts(self):
        """Build the ``add_mounts`` list from the current selection.

        A node gets its own mount only when it introduces a permission its
        parent does not already grant, which keeps the mount set minimal
        while still covering descendants that need *more* than the parent.
        """
        result = []
        seen = set()
        for node in self.nodes_preorder:
            # Anything under a redirected or blocked ancestor is already
            # handled by that ancestor (its mount, or its ignore rule), so
            # never emit a mount for it.
            if self._has_covering_ancestor(node):
                continue

            # A blocked node is passed through via an ignore rule, not a
            # mount.
            if node.block:
                continue

            # A redirected node is always mounted, from its user-specified
            # host path, with full rwx.
            if node.redirect is not None:
                if node.path not in seen:
                    seen.add(node.path)
                    result.append(
                        {
                            "mount_point": node.path,
                            "host_path": node.redirect,
                            "attrs": {"readonly": False, "noexec": False},
                        }
                    )
                continue

            pr = node.parent.eff_r if node.parent else False
            pw = node.parent.eff_w if node.parent else False
            px = node.parent.eff_x if node.parent else False
            introduces = (
                (node.eff_r and not pr)
                or (node.eff_w and not pw)
                or (node.eff_x and not px)
            )
            if not (node.eff_r and introduces):
                continue
            if node.path in seen:
                continue
            seen.add(node.path)
            result.append(
                {
                    "mount_point": node.path,
                    "host_path": node.path,
                    "attrs": {
                        "readonly": not node.eff_w,
                        "noexec": not node.eff_x,
                    },
                }
            )
        return result

    def ignored_paths(self):
        """Paths to persist as ``ignore: true`` rules (blocked rows).

        A blocked node under another blocked/redirected ancestor is
        redundant and omitted, mirroring :meth:`mounts`.
        """
        result = []
        seen = set()
        for node in self.nodes_preorder:
            if node.depth == 0 or not node.block:
                continue
            if self._has_covering_ancestor(node):
                continue
            if node.path in seen:
                continue
            seen.add(node.path)
            result.append(node.path)
        return result

    def has_blocks(self):
        """Whether any row is currently blocked."""
        return any(node.block for node in self.nodes_preorder)


class PrompterDialog(QtWidgets.QDialog):
    def __init__(self, request, grants, placeholders):
        super().__init__()
        self.placeholders = placeholders
        self.config_path = request.get("config_path")
        self.response = deny_response()  # default if the window is closed
        self.scale_mgr = None  # set by main() before exec()

        access_request = request.get("access_request", {})
        op = operation_name(access_request)
        comm = request.get("request_comm", "?")
        pid = request.get("request_pid", "?")
        cmd = " ".join(request.get("sandbox_cmd", [])) or "(unknown)"

        self.setWindowTitle("Turnstile-sandbox access request")
        # Mark the window as a dialog so tiling window managers (i3, sway,
        # ...) float it instead of tiling/maximizing it.
        self.setWindowFlag(QtCore.Qt.Dialog, True)
        self.setWindowModality(QtCore.Qt.ApplicationModal)

        layout = QtWidgets.QVBoxLayout(self)

        layout.addWidget(QtWidgets.QLabel("The sandbox"))
        cmd_field = QtWidgets.QLineEdit(cmd)
        cmd_field.setReadOnly(True)
        cmd_field.setCursorPosition(0)
        layout.addWidget(cmd_field)

        layout.addWidget(
            QtWidgets.QLabel(
                f"is requesting the following access to execute a "
                f"<b>{op}</b> from <b>{comm}[{pid}]</b>:"
            )
        )

        layout.addWidget(self._build_request_table(request))
        layout.addWidget(self._build_show_request(access_request))

        self.allow_box = QtWidgets.QCheckBox(
            "Allow this request by granting the following access:"
        )
        self.allow_box.setChecked(True)
        self.allow_box.toggled.connect(self._on_allow_toggled)
        layout.addWidget(self.allow_box)

        self.tree = TreeWidget(grants, allow_block=bool(self.config_path))
        self.tree.blocks_changed.connect(self._on_blocks_changed)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidget(self.tree)
        scroll.setWidgetResizable(True)
        scroll.setMinimumHeight(160)
        layout.addWidget(scroll)

        self.persist_box = QtWidgets.QCheckBox("Persist these rules in the config")
        self.persist_box.setChecked(True)
        self.persist_box.setEnabled(bool(self.config_path))
        layout.addWidget(self.persist_box)

        buttons = QtWidgets.QHBoxLayout()
        style = self.style()
        cancel = QtWidgets.QPushButton(
            style.standardIcon(QtWidgets.QStyle.SP_DialogCancelButton),
            "Cancel and deny",
        )
        cancel.clicked.connect(self._on_cancel)
        cont = QtWidgets.QPushButton(
            style.standardIcon(QtWidgets.QStyle.SP_DialogOkButton),
            "Continue",
        )
        cont.setDefault(True)
        cont.clicked.connect(self._on_continue)
        buttons.addWidget(cancel)
        buttons.addStretch(1)
        buttons.addWidget(cont)
        layout.addLayout(buttons)

    def _build_request_table(self, request):
        perms = request.get("rwx_permissions", [])
        table = QtWidgets.QTableWidget(len(perms), 2)
        table.setHorizontalHeaderLabels(["access", "path"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        for row, perm in enumerate(perms):
            need_read, need_write, need_exec = needed_perms(perm)
            table.setItem(
                row, 0, QtWidgets.QTableWidgetItem(rwx_string(need_read, need_write, need_exec))
            )
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(target_path(perm)))
        self.table = table
        self._fit_table()
        return table

    def _fit_table(self):
        """Resize the access table's columns and height to its content.

        Called on build and after every scale change so zooming widens the
        columns and grows the height instead of clipping the content.
        """
        table = self.table
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)
        table.setMaximumHeight(
            table.horizontalHeader().height()
            + sum(table.rowHeight(r) for r in range(table.rowCount()))
            + 2
        )

    def _build_show_request(self, access_request):
        container = QtWidgets.QWidget()
        box = QtWidgets.QVBoxLayout(container)
        box.setContentsMargins(0, 0, 0, 0)

        toggle = QtWidgets.QToolButton()
        toggle.setText("Show request")
        toggle.setCheckable(True)
        toggle.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        toggle.setArrowType(QtCore.Qt.RightArrow)
        box.addWidget(toggle)

        text = QtWidgets.QPlainTextEdit(json.dumps(access_request, indent=2))
        text.setReadOnly(True)
        text.setVisible(False)
        box.addWidget(text)

        def on_toggle(checked):
            toggle.setArrowType(QtCore.Qt.DownArrow if checked else QtCore.Qt.RightArrow)
            text.setVisible(checked)

        toggle.toggled.connect(on_toggle)
        return container

    def _on_allow_toggled(self, checked):
        self.tree.setEnabled(checked)

    def _on_blocks_changed(self, has_blocks):
        """Force "persist to config" on while any path is blocked.

        A block is only expressible as a persisted ``ignore: true`` rule
        (there is no transient form), so persisting is mandatory then.
        """
        if has_blocks:
            self.persist_box.setChecked(True)
            self.persist_box.setEnabled(False)
            self.persist_box.setToolTip(
                "Blocking a path requires writing the config"
            )
        else:
            self.persist_box.setEnabled(bool(self.config_path))
            self.persist_box.setToolTip("")

    def _apply_scale(self):
        """Apply the current scale and re-fit scale-dependent widgets."""
        if self.scale_mgr is not None:
            self.scale_mgr.apply(self)
        self._fit_table()
        self.adjustSize()

    def eventFilter(self, obj, event):
        # Ctrl+scroll anywhere in the window zooms the whole UI up/down.
        if (
            self.scale_mgr is not None
            and event.type() == QtCore.QEvent.Wheel
            and (event.modifiers() & QtCore.Qt.ControlModifier)
        ):
            dy = event.angleDelta().y()
            if dy and self.scale_mgr.zoom(1 if dy > 0 else -1):
                self._apply_scale()
            return True
        return super().eventFilter(obj, event)

    def _on_cancel(self):
        self.response = deny_response()
        self.reject()

    def _on_continue(self):
        if self.allow_box.isChecked():
            mounts = self.tree.mounts()
            ignores = self.tree.ignored_paths()
            self.response = {
                "action": {"continue": True},
                "add_placeholders": self.placeholders,
                "auto_add_symlinks": True,
                "auto_widen_descendant_permissions": True,
            }
            # When persisting, write the mounts/ignores into the config and
            # ask turnstile-sandbox to reload it instead of applying
            # transient mounts; the reload reproduces exactly these rules.
            # Blocked paths can only be expressed as persisted ignore rules,
            # so a block forces persistence.  Fall back to transient mounts
            # if writing the config fails.
            if self.persist_box.isChecked() and self.config_path:
                try:
                    persist_to_config(self.config_path, mounts, ignores)
                    self.response["reload_config"] = True
                except Exception as exc:
                    QtWidgets.QMessageBox.warning(
                        self,
                        "Could not persist to config",
                        "Failed to write the config file:\n%s\n\n"
                        "Granting for this session only." % exc,
                    )
                    self.response["add_mounts"] = mounts
            else:
                self.response["add_mounts"] = mounts
        else:
            # Don't grant anything, but still let the syscall proceed
            # against the current sandbox view rather than forcing EPERM.
            # It may fail naturally (EEXIST / ENOENT / EROFS / ...), and
            # the user can arrange things manually (e.g. create the
            # missing dir) without exposing the whole parent.  Resolve-only
            # placeholders are still applied.
            self.response = {
                "action": {"continue": True},
                "add_placeholders": self.placeholders,
                "auto_add_symlinks": True,
            }
        self.accept()


def deny_response():
    return {"action": {"send_error": EPERM}}


def main():
    request = json.load(sys.stdin)
    perms = request.get("rwx_permissions", [])

    # Create-like operations (open O_CREAT, mkdir, symlink, mknod) can be
    # granted on an already-existing target instead of its parent; see
    # grant_path_for.  Operations that genuinely mutate the parent
    # (unlink, rename, link) must not, so gate on the operation type.
    op_name = operation_name(request.get("access_request", {}))
    create_like = op_name in ("FsOpen", "FsCreate")

    # Resolve-only requests (no r/w/x) are always allowed via match_host
    # placeholders and never shown in the UI.  Everything else becomes an
    # editable grant in the tree.
    placeholders = []
    seen_placeholders = set()
    grants = {}
    for perm in perms:
        need_read, need_write, need_exec = needed_perms(perm)
        if not (need_read or need_write or need_exec):
            path = target_path(perm)
            if path not in seen_placeholders:
                seen_placeholders.add(path)
                placeholders.append({"path": path, "match_host": True})
            continue
        path = grant_path_for(perm, create_like)
        cur_w, cur_x = grants.get(path, (False, False))
        grants[path] = (cur_w or need_write, cur_x or need_exec)

    grant_list = [(path, w, x) for path, (w, x) in grants.items()]

    if not grant_list:
        # Nothing to decide interactively: just allow the resolve-only
        # placeholders and continue without showing a window.
        response = {
            "action": {"continue": True},
            "add_placeholders": placeholders,
            "auto_add_symlinks": True,
            "auto_widen_descendant_permissions": True,
        }
        json.dump(response, sys.stdout)
        sys.stdout.write("\n")
        return

    # Silence the harmless "Could not register app ID" portal warning that
    # Qt emits when no matching .desktop file exists for our app id.
    QtCore.QLoggingCategory.setFilterRules("qt.qpa.services.warning=false")
    app = QtWidgets.QApplication([])
    # Give the window a specific app-id / WM_CLASS (instead of the generic
    # "python3") so window-manager rules can target it.  On Wayland the
    # app-id is taken from the desktop file name.
    app.setApplicationName("turnstile-example-prompter")
    app.setDesktopFileName("turnstile-example-prompter")
    scale_mgr = ScaleManager(app)
    dialog = PrompterDialog(request, grant_list, placeholders)
    dialog.scale_mgr = scale_mgr
    # Receive every wheel event so Ctrl+scroll zooms regardless of which
    # widget is under the cursor.
    app.installEventFilter(dialog)
    dialog._apply_scale()
    dialog.exec()
    app  # keep a reference until here

    json.dump(dialog.response, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
