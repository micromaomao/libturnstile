use std::{
	collections::{HashMap, hash_map},
	ffi::{OsStr, OsString},
	fmt::Display,
	iter::FusedIterator,
	os::unix::ffi::OsStrExt,
};

struct PathToComponentsIter<'a> {
	path_bytes: &'a [u8],
	next_start: usize,
}

struct PathComponent<'a> {
	pub name: &'a OsStr,
	pub path_from_root: &'a OsStr,
	pub parent_path_from_root: &'a OsStr,
	pub remaining: &'a OsStr,
}

impl<'a> PathComponent<'a> {
	pub fn is_last(&self) -> bool {
		self.remaining.as_encoded_bytes().iter().all(|&b| b == b'/')
	}
}

impl<'a> Iterator for PathToComponentsIter<'a> {
	type Item = PathComponent<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.next_start >= self.path_bytes.len() {
			return None;
		}
		let parent_abs = if self.next_start == 0 {
			OsStr::new("")
		} else {
			OsStr::from_bytes(&self.path_bytes[..self.next_start - 1])
		};
		loop {
			if self.next_start >= self.path_bytes.len() {
				return None;
			}
			let next_slash = self.path_bytes[self.next_start..]
				.iter()
				.copied()
				.position(|b| b == b'/');
			let curr_start = self.next_start;
			let end;
			if let Some(next_slash) = next_slash {
				self.next_start += next_slash + 1;
				end = self.next_start - 1;
			} else {
				self.next_start = self.path_bytes.len();
				end = self.path_bytes.len();
			}
			let current = &self.path_bytes[curr_start..end];
			let current_abs = &self.path_bytes[..end];
			let remaining = &self.path_bytes[self.next_start..];
			if current.is_empty() {
				continue;
			}
			if current == b"." || current == b".." {
				panic!(
					"Unable to walk path {:?}: dots are not allowed",
					OsStr::from_bytes(self.path_bytes)
				);
			}
			return Some(PathComponent {
				name: OsStr::from_bytes(current),
				path_from_root: OsStr::from_bytes(current_abs),
				parent_path_from_root: parent_abs,
				remaining: OsStr::from_bytes(remaining),
			});
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		if self.next_start >= self.path_bytes.len() {
			return (0, Some(0));
		}
		let remaining = &self.path_bytes[self.next_start..];
		let len = remaining
			.split(|&b| b == b'/')
			.filter(|s| !s.is_empty())
			.count();
		(len, Some(len))
	}
}

impl<'a> FusedIterator for PathToComponentsIter<'a> {}
impl<'a> ExactSizeIterator for PathToComponentsIter<'a> {}

fn path_to_components<'a>(path: &'a OsStr) -> PathToComponentsIter<'a> {
	PathToComponentsIter {
		path_bytes: path.as_encoded_bytes(),
		next_start: 0,
	}
}

#[test]
fn test_path_to_components() {
	fn test_case(paths: &[&str], expected: &[&str], expected_path_from_root: &[&str]) {
		for &test_path in paths {
			let components_iter = path_to_components(OsStr::new(test_path));
			let sz_hint = components_iter.size_hint();
			assert_eq!(sz_hint.0, expected.len());
			assert_eq!(sz_hint.1, Some(expected.len()));
			let components = components_iter.collect::<Vec<_>>();
			assert_eq!(components.len(), expected.len());
			for (i, (component, &expected_component)) in components.iter().zip(expected).enumerate()
			{
				assert_eq!(component.name, OsStr::new(expected_component));
				assert_eq!(
					component.path_from_root,
					OsStr::new(expected_path_from_root[i])
				);
				if i > 0 {
					assert_eq!(
						component.parent_path_from_root,
						OsStr::new(expected_path_from_root[i - 1])
					);
				} else {
					assert_eq!(component.parent_path_from_root, OsStr::new(""));
				}
				let expected_is_last = i == expected.len() - 1;
				assert_eq!(component.is_last(), expected_is_last);
				if !expected_is_last {
					assert_eq!(
						component.remaining,
						OsStr::new(&test_path[component.path_from_root.len() + 1..])
					);
				} else {
					assert!(
						component
							.remaining
							.as_encoded_bytes()
							.iter()
							.all(|&b| b == b'/')
					);
				}
			}
		}
	}

	test_case(&["", "/", "//", "///", "////"], &[], &[]);
	test_case(&["foo", "foo/", "foo//"], &["foo"], &["foo"]);
	test_case(&["/foo"], &["foo"], &["/foo"]);
	test_case(&["//foo/", "//foo//"], &["foo"], &["//foo"]);
	test_case(
		&["foo/bar", "foo/bar/"],
		&["foo", "bar"],
		&["foo", "foo/bar"],
	);
	test_case(
		&["/foo/bar", "/foo/bar/", "/foo/bar//"],
		&["foo", "bar"],
		&["/foo", "/foo/bar"],
	);
	test_case(
		&["/foo//bar", "/foo//bar//"],
		&["foo", "bar"],
		&["/foo", "/foo//bar"],
	);
}

#[derive(Debug, Clone)]
struct FsTreeNode<T> {
	data: Option<T>,
	children: HashMap<OsString, FsTreeNode<T>>,
}

/// A in-memory representation of a map of paths to custom data.
///
/// All paths passed to this struct are interpreted as absolute paths.
/// Because .. resolution depends on the actual filesystem, "." and ".."
/// are not allowed as components of paths when used with this struct.
/// The caller should resolve any user-provided paths before using them
/// with this struct.
#[derive(Debug, Clone)]
pub struct FsTree<T> {
	root: FsTreeNode<T>,
	nb_entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffTree<T1, T2> {
	Updated(T1, T2),
	Added(T2),
	Removed(T1),
}

impl<'a, 'b, T1: Clone, T2: Clone> DiffTree<&'a T1, &'b T2> {
	pub fn cloned(&self) -> DiffTree<T1, T2> {
		match self {
			&DiffTree::Updated(t1, t2) => DiffTree::Updated(t1.clone(), t2.clone()),
			&DiffTree::Added(t2) => DiffTree::Added(t2.clone()),
			&DiffTree::Removed(t1) => DiffTree::Removed(t1.clone()),
		}
	}
}

impl<T> FsTree<T> {
	/// Create a new empty FsTree
	pub fn new() -> Self {
		FsTree {
			root: FsTreeNode {
				data: None,
				children: HashMap::new(),
			},
			nb_entries: 0,
		}
	}

	/// Returns the data at the exact path, or None if the path is not in
	/// the tree.
	pub fn get(&self, path: &OsStr) -> Option<&T> {
		let mut current = &self.root;
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get(comp.name) {
				current = v;
			} else {
				return None;
			}
		}
		current.data.as_ref()
	}

	/// Returns a mutable reference to the data at the exact path, or None
	/// if the path is not in the tree.
	pub fn get_mut(&mut self, path: &OsStr) -> Option<&mut T> {
		let mut current = &mut self.root;
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get_mut(comp.name) {
				current = v;
			} else {
				return None;
			}
		}
		current.data.as_mut()
	}

	/// Returns a mutable reference to the data at the exact path.  If the
	/// path does not exist in the tree, `default_constructor` is called
	/// and the return value is inserted then returned.
	pub fn get_mut_or_insert<F: FnOnce() -> T>(
		&mut self,
		path: &OsStr,
		default_constructor: F,
	) -> &mut T {
		let mut current = &mut self.root;
		for comp in path_to_components(path) {
			// the lifetime on HashMap::get_mut is too restrictive, so we
			// have to use .entry() here.
			let entry = current.children.entry(comp.name.to_owned());
			match entry {
				hash_map::Entry::Occupied(e) => {
					current = e.into_mut();
				}
				hash_map::Entry::Vacant(e) => {
					current = e.insert(FsTreeNode {
						data: None,
						children: HashMap::new(),
					});
				}
			}
		}
		if current.data.is_none() {
			current.data = Some(default_constructor());
			self.nb_entries += 1;
		}
		current.data.as_mut().unwrap()
	}

	pub fn is_empty(&self) -> bool {
		self.nb_entries == 0
	}

	pub fn len(&self) -> usize {
		self.nb_entries
	}

	/// Attempt to walk from root to the given path, evaluating the
	/// predicate on each level with data (including the root).  Return
	/// the last level for which the predicate returned true, or None if
	/// the predicate returns false for all levels of the path.
	///
	/// For each level, the predicate is given a prefix extracted from the
	/// `path` argument, and a reference to the data stored for the path
	/// corresponding to the current level.
	///
	/// If the path given starts with a slash, the path given to the
	/// predicate and the return value will both have a leading slash,
	/// otherwise, neither will have a leading slash.
	pub fn find<'a, P: FnMut(&'a OsStr, &T) -> bool>(
		&self,
		path: &'a OsStr,
		mut predicate: P,
	) -> Option<(&'a OsStr, &T)> {
		let mut current = &self.root;
		let mut last_matching: Option<(&'a OsStr, &T)> = None;
		let root = if path.as_encoded_bytes().get(0).copied() == Some(b'/') {
			OsStr::new("/")
		} else {
			OsStr::new("")
		};
		if let Some(root_data) = &current.data
			&& predicate(root, root_data)
		{
			last_matching = Some((root, root_data));
		}
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get(comp.name) {
				current = v;
				if let Some(data) = &current.data
					&& predicate(comp.path_from_root, data)
				{
					last_matching = Some((comp.path_from_root, data));
				}
			} else {
				return last_matching;
			}
		}
		last_matching
	}

	/// Insert the given path into this FsTree, replacing any existing
	/// data at the path, and return the existing data, if any.
	pub fn insert<'a>(&mut self, path: &'a OsStr, target: T) -> Option<T> {
		let mut current: &mut FsTreeNode<T> = &mut self.root;
		for comp in path_to_components(path) {
			// the lifetime on HashMap::get_mut is too restrictive, so we
			// have to use .entry() here.
			let entry = current.children.entry(comp.name.to_owned());
			match entry {
				hash_map::Entry::Occupied(e) => {
					current = e.into_mut();
				}
				hash_map::Entry::Vacant(e) => {
					current = e.insert(FsTreeNode {
						data: None,
						children: HashMap::new(),
					});
				}
			}
		}
		let ret = current.data.replace(target);
		if ret.is_none() {
			self.nb_entries += 1;
		}
		ret
	}

	/// Remove the path from the tree, returning the existing data, if
	/// any.  Any paths under the removed path are not removed.
	///
	/// After removing the data, if the target node has no children, it
	/// is removed from its parent's children map, and this cleanup is
	/// repeated up the chain for any ancestor that ends up with no data
	/// and no children.  This preserves the "no useless subtree"
	/// invariant: a non-root node exists in the tree only if it (or
	/// something under it) carries data.
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::FsTree;
	/// use std::ffi::OsStr;
	/// let mut tree = FsTree::new();
	/// tree.insert(OsStr::new("/foo/bar/baz"), 1);
	/// tree.insert(OsStr::new("/foo/qux"), 2);
	/// assert_eq!(tree.len(), 2);
	///
	/// assert_eq!(tree.remove(OsStr::new("/foo/bar/baz")), Some(1));
	/// let mut paths = Vec::new();
	/// tree.walk_top_down(|p, _| paths.push(p.to_str().unwrap().to_string()));
	/// assert_eq!(paths, &["/foo/qux"]);
	///
	/// // Removing the last entry leaves the tree empty.
	/// assert_eq!(tree.remove(OsStr::new("/foo/qux")), Some(2));
	/// assert!(tree.is_empty());
	///
	/// // Removing a non-existent path returns None.
	/// assert_eq!(tree.remove(OsStr::new("/nope")), None);
	/// ```
	pub fn remove(&mut self, path: &OsStr) -> Option<T> {
		let names: Vec<&OsStr> = path_to_components(path).map(|c| c.name).collect();
		let (ret, _) = Self::remove_impl(&mut self.root, &names);
		if ret.is_some() {
			self.nb_entries -= 1;
		}
		ret
	}

	/// Recursive helper for [`Self::remove`].  Descends into `node`
	/// following `names`, takes the data at the leaf on the way down,
	/// and on the way back up tells each caller whether the child entry
	/// it owns should be dropped (because its subtree is now useless).
	///
	/// Returns `(removed_data, prune_self)` where `prune_self` is true
	/// iff `node` has no data and no children after the recursion and
	/// should therefore be removed from its parent's children map.
	/// `prune_self` is meaningful only when the caller is a parent; the
	/// top-level call (on `self.root`) ignores it.
	///
	/// Proof sketch (induction on the tree state before the call,
	/// assuming the invariant holds): the node we delete from is a leaf
	/// of the path lookup.  If it still has children, by the invariant
	/// at least one descendant carries data, so the subtree is not
	/// useless and no cleanup is needed.  If it has no children, we
	/// prune it; its parent may then satisfy the same condition (no
	/// data, no children), and we repeat.  At every step we either stop
	/// at a node that still has data or children (invariant preserved)
	/// or we prune a node that just became useless, so we never leave a
	/// useless subtree behind.
	fn remove_impl(node: &mut FsTreeNode<T>, names: &[&OsStr]) -> (Option<T>, bool) {
		if let Some((first, rest)) = names.split_first() {
			let entry = match node.children.get_mut(*first) {
				Some(child) => child,
				None => return (None, false),
			};
			let (ret, prune_child) = Self::remove_impl(entry, rest);
			if prune_child {
				node.children.remove(*first);
			}
			let prune_self = ret.is_some() && node.data.is_none() && node.children.is_empty();
			(ret, prune_self)
		} else {
			let ret = node.data.take();
			let prune_self = ret.is_some() && node.children.is_empty();
			(ret, prune_self)
		}
	}

	/// Walks the tree in top-down order, e.g. /, /foo, /foo/bar, /baz,
	/// calling the given function for any paths that exists in the tree.
	/// Iteration order for entries of the same directory is arbitrary.
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::FsTree;
	/// use std::ffi::{OsStr, OsString};
	/// let mut tree = FsTree::new();
	/// tree.insert(OsStr::new("/foo"), 1);
	/// tree.insert(OsStr::new("/foo/bar"), 2);
	/// tree.insert(OsStr::new("/dev/baz"), 3);
	/// let mut result = Vec::new();
	/// tree.walk_top_down(|path, data| result.push(path.to_str().unwrap().to_string()));
	/// if result[0] == "/foo" {
	///     assert_eq!(result, &[
	///         "/foo",
	///         "/foo/bar",
	///         "/dev/baz",
	///     ]);
	/// } else {
	///     assert_eq!(result, &[
	///         "/dev/baz",
	///         "/foo",
	///         "/foo/bar",
	///     ]);
	/// }
	/// ```
	pub fn walk_top_down<F: FnMut(&OsStr, &T)>(&self, mut f: F) {
		self.walk_impl(&mut f, true, &mut vec![b'/'], &self.root);
	}

	/// Fill in any "incomplete parent" nodes - that is, any internal
	/// node that exists in the tree (because some descendant has data)
	/// but does not itself have data.  For each such node,
	/// `constructor` is called with the absolute path of that node and
	/// the returned value is stored as the node's data.
	///
	/// Because we maintain the "no useless subtree" invariant (see
	/// [`Self::remove`]), every data-less non-root node is by
	/// definition an incomplete parent: it would not exist otherwise.
	/// This therefore runs in O(N) where N is the number of nodes in
	/// the tree.
	///
	/// The root is also filled if it currently has no data and the
	/// tree is non-empty.
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::FsTree;
	/// use std::ffi::OsStr;
	/// let mut tree: FsTree<String> = FsTree::new();
	/// tree.insert(OsStr::new("/a/b/c"), "c".to_string());
	/// tree.insert(OsStr::new("/a/d"), "d".to_string());
	/// tree.fill_incomplete_parent(|path| format!("filled:{}", path.to_str().unwrap()));
	/// assert_eq!(tree.get(OsStr::new("/")).map(String::as_str), Some("filled:/"));
	/// assert_eq!(tree.get(OsStr::new("/a")).map(String::as_str), Some("filled:/a"));
	/// assert_eq!(tree.get(OsStr::new("/a/b")).map(String::as_str), Some("filled:/a/b"));
	/// assert_eq!(tree.get(OsStr::new("/a/b/c")).map(String::as_str), Some("c"));
	/// assert_eq!(tree.get(OsStr::new("/a/d")).map(String::as_str), Some("d"));
	/// ```
	pub fn fill_incomplete_parent<F: FnMut(&OsStr) -> T>(&mut self, mut constructor: F) {
		Self::fill_impl(
			&mut self.root,
			&mut vec![b'/'],
			&mut constructor,
			true,
			&mut self.nb_entries,
		);
	}

	fn fill_impl<F: FnMut(&OsStr) -> T>(
		node: &mut FsTreeNode<T>,
		path: &mut Vec<u8>,
		constructor: &mut F,
		is_root: bool,
		nb_entries: &mut usize,
	) {
		// Skip filling an empty root (i.e. an empty tree).  Otherwise
		// any node we visit must, by the no-useless-subtree invariant,
		// be either the root, carry data, or have descendants with
		// data; in the latter two cases we fill if data is missing.
		if node.data.is_none() && !(is_root && node.children.is_empty()) {
			node.data = Some(constructor(OsStr::from_bytes(path)));
			*nb_entries += 1;
		}
		for (name, child) in node.children.iter_mut() {
			let orig_len = path.len();
			if path.last().copied() != Some(b'/') {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			Self::fill_impl(child, path, constructor, false, nb_entries);
			path.truncate(orig_len);
		}
	}

	/// Reports if the tree has any "incomplete parent" - any entries for
	/// which one or more of its parent does not exist as another entry
	/// with data in this tree.
	///
	/// In other words, this return whether
	/// [`Self::fill_incomplete_parent`] would make any changes if it is
	/// called on this tree.
	pub fn has_incomplete_parents(&self) -> bool {
		self.has_incomplete_parents_impl(&self.root)
	}

	fn has_incomplete_parents_impl(&self, node: &FsTreeNode<T>) -> bool {
		// The root is allowed to both be present (it has to) and have no
		// data or children, so this node.children.is_empty() check is
		// necessary.
		if node.data.is_none() && !node.children.is_empty() {
			return true;
		}
		for child in node.children.values() {
			if self.has_incomplete_parents_impl(child) {
				return true;
			}
		}
		false
	}

	/// Walks the tree in bottom-up order, e.g. /foo/bar, /foo, /baz, /,
	/// calling the given function for any paths that exists in the tree.
	/// Iteration order for entries of the same directory is arbitrary.
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::FsTree;
	/// use std::ffi::OsStr;
	/// let mut tree = FsTree::new();
	/// tree.insert(OsStr::new("/foo"), 1);
	/// tree.insert(OsStr::new("/foo/bar"), 2);
	/// tree.insert(OsStr::new("/dev/baz"), 3);
	/// let mut result = Vec::new();
	/// tree.walk_bottom_up(|path, data| result.push(path.to_str().unwrap().to_string()));
	/// if result[0] == "/foo/bar" {
	///     assert_eq!(result, &[
	///         "/foo/bar",
	///         "/foo",
	///         "/dev/baz",
	///     ]);
	/// } else {
	///     assert_eq!(result, &[
	///         "/dev/baz",
	///         "/foo/bar",
	///         "/foo",
	///     ]);
	/// }
	pub fn walk_bottom_up<F: FnMut(&OsStr, &T)>(&self, mut f: F) {
		self.walk_impl(&mut f, false, &mut vec![b'/'], &self.root);
	}

	/// Walk the data entries under (but not including) `root` in top-down
	/// order, calling `f(path, data)` for each.
	///
	/// If `topmost_only` is true, only the "topmost" children of `root` are
	/// visited.  For example, for a tree containing /a, /a/b/c, /a/b/c/d, the
	/// only topmost child of /a is /a/b/c.
	///
	/// If no path in the tree starts with `root`, `f` is not called.
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::FsTree;
	/// use std::ffi::OsStr;
	/// let mut tree = FsTree::new();
	/// tree.insert(OsStr::new("/a"), 0);
	/// tree.insert(OsStr::new("/a/b"), 1);
	/// tree.insert(OsStr::new("/a/b/c/d"), 2);
	/// tree.insert(OsStr::new("/a/e"), 3);
	///
	/// let mut topmost = Vec::new();
	/// tree.walk_subtree_top_down(OsStr::new("/a"), true, |p, _| {
	///     topmost.push(p.to_str().unwrap().to_string());
	/// });
	/// topmost.sort();
	/// assert_eq!(topmost, &["/a/b", "/a/e"]);
	///
	/// let mut all = Vec::new();
	/// tree.walk_subtree_top_down(OsStr::new("/a"), false, |p, _| {
	///     all.push(p.to_str().unwrap().to_string());
	/// });
	/// all.sort();
	/// assert_eq!(all, &["/a/b", "/a/b/c/d", "/a/e"]);
	/// ```
	pub fn walk_subtree_top_down<F: FnMut(&OsStr, &T)>(
		&self,
		root: &OsStr,
		topmost_only: bool,
		mut f: F,
	) {
		let mut current = &self.root;
		for comp in path_to_components(root) {
			match current.children.get(comp.name) {
				Some(v) => current = v,
				None => return,
			}
		}

		let mut path: Vec<u8> = root.as_encoded_bytes().to_vec();
		// Strip any trailing slash so descendants can uniformly append
		// "/child".  Path will be empty if root is "/".
		while !path.is_empty() && path.last().copied() == Some(b'/') {
			path.pop();
		}
		// Walk the children of `root`, but not `root` itself.
		Self::walk_subtree_impl(&mut f, topmost_only, &mut path, current);
	}

	fn walk_subtree_impl<F: FnMut(&OsStr, &T)>(
		f: &mut F,
		topmost_only: bool,
		path: &mut Vec<u8>,
		node: &FsTreeNode<T>,
	) {
		for (name, child) in node.children.iter() {
			let orig_len = path.len();
			path.push(b'/');
			path.extend_from_slice(name.as_bytes());
			if let Some(data) = &child.data {
				f(OsStr::from_bytes(path), data);
			}
			// When topmost_only, stop descending once we've found a child
			// with data - it is the topmost entry of this branch.
			if !topmost_only || child.data.is_none() {
				Self::walk_subtree_impl(f, topmost_only, path, child);
			}
			path.truncate(orig_len);
		}
	}

	/// path is a scratch buffer that this function can change, but must
	/// restore to the original data on return.
	fn walk_impl<F: FnMut(&OsStr, &T)>(
		&self,
		f: &mut F,
		top_down: bool,
		path: &mut Vec<u8>,
		node: &FsTreeNode<T>,
	) {
		if top_down && let Some(data) = &node.data {
			f(OsStr::from_bytes(path), data);
		}

		let iter = node.children.iter();
		for (comp, child) in iter {
			let orig_path_len = path.len();
			if path.last().copied() != Some(b'/') {
				path.push(b'/');
			}
			path.extend_from_slice(comp.as_bytes());
			self.walk_impl(f, top_down, path, child);
			path.truncate(orig_path_len);
		}
		if !top_down && let Some(data) = &node.data {
			f(OsStr::from_bytes(path), data);
		}
	}

	/// Produce the difference between two trees.  self is considered the
	/// "old" tree and other is considered the "new" tree.  For entries
	/// that are in both trees, if split_on returns true, they are
	/// traversed separately (resulting in a [`DiffTree::Removed`] for
	/// everything in the old tree and a [`DiffTree::Added`] for
	/// everything in the new tree).  If split_on returns false, a
	/// [`DiffTree::Updated`] is produced for both side, and the children
	/// are traversed together.
	///
	/// For trees removed, the iteration order is bottom-up, e.g.
	/// /foo/bar, /foo, /baz, /.  For trees added or updated, the
	/// iteration order is top-down, e.g. /, /foo, /foo/bar.
	///
	/// `split_on_one_side` controls what happens when two trees have a
	/// path in common, but the parent of the path only exists on one
	/// side.  If `split_on_one_side` is false, a [`DiffTree::Added`] or
	/// [`DiffTree::Removed`] is produced for the parent, but the common
	/// children are still traversed together and may produce
	/// [`DiffTree::Updated`] entries.  If `split_on_one_side` is true,
	/// the two sides are treated as completely separate paths and no
	/// [`DiffTree::Updated`] entries are produced for any children of the
	/// parent in question,
	///
	/// ## Example
	///
	/// ```
	/// use libturnstile::fstree::{DiffTree, FsTree};
	/// use std::collections::HashSet;
	/// use std::ffi::OsStr;
	/// let mut tree1 = FsTree::new();
	/// tree1.insert(OsStr::new("/foo"), 1);
	/// tree1.insert(OsStr::new("/foo/bar"), 2);
	/// tree1.insert(OsStr::new("/dev/baz"), 3);
	/// let mut tree2 = FsTree::new();
	/// tree2.insert(OsStr::new("/foo"), 1);
	/// tree2.insert(OsStr::new("/dev/null"), 4);
	///
	/// let mut added = HashSet::new();
	/// let mut removed = HashSet::new();
	/// let mut updated = HashSet::new();
	/// tree1.diff(&tree2, |path, diff| {
	///   let p = path.to_str().unwrap().to_string();
	///   match diff {
	///     DiffTree::Added(_) => { added.insert(p); },
	///     DiffTree::Removed(_) => { removed.insert(p); },
	///     DiffTree::Updated(_, _) => { updated.insert(p); },
	///   }
	/// }, |_, _, _| false, false);
	/// assert_eq!(added, HashSet::from(["/dev/null".to_string()]));
	/// assert_eq!(removed, HashSet::from(["/foo/bar".to_string(), "/dev/baz".to_string()]));
	/// assert_eq!(updated, HashSet::from(["/foo".to_string()]));
	/// ```
	pub fn diff<T2, F: FnMut(&OsStr, DiffTree<&T, &T2>), S: FnMut(&OsStr, &T, &T2) -> bool>(
		&self,
		other: &FsTree<T2>,
		mut f: F,
		mut split_on: S,
		split_on_one_side: bool,
	) {
		self.diff_impl(
			other,
			&mut |path, t1, t2| {
				let diff = match (t1, t2) {
					(Some(t1), Some(t2)) => DiffTree::Updated(t1, t2),
					(Some(t1), None) => DiffTree::Removed(t1),
					(None, Some(t2)) => DiffTree::Added(t2),
					(None, None) => return,
				};
				f(path, diff);
			},
			&mut |path, t1, t2| {
				if let Some(t1) = t1
					&& let Some(t2) = t2
				{
					split_on(path, t1, t2)
				} else if t1.is_none() && t2.is_none() {
					false
				} else {
					split_on_one_side
				}
			},
			&mut vec![b'/'],
			&self.root,
			&other.root,
		);
	}

	/// path is a scratch buffer that this function can change, but must
	/// restore to the original data on return.
	fn diff_impl<
		T2,
		F: FnMut(&OsStr, Option<&T>, Option<&T2>),
		S: FnMut(&OsStr, Option<&T>, Option<&T2>) -> bool,
	>(
		&self,
		other: &FsTree<T2>,
		f: &mut F,
		split_on: &mut S,
		path: &mut Vec<u8>,
		node_left: &FsTreeNode<T>,
		node_right: &FsTreeNode<T2>,
	) {
		let should_split = split_on(
			OsStr::from_bytes(path),
			node_left.data.as_ref(),
			node_right.data.as_ref(),
		);
		if should_split {
			self.walk_impl(
				&mut |path, left| f(path, Some(left), None),
				false,
				path,
				node_left,
			);
			other.walk_impl(
				&mut |path, right| f(path, None, Some(right)),
				true,
				path,
				node_right,
			);
			return;
		}
		f(
			OsStr::from_bytes(path),
			node_left.data.as_ref(),
			node_right.data.as_ref(),
		);
		let left_names = node_left
			.children
			.keys()
			.map(|x| x.as_os_str())
			.collect::<std::collections::HashSet<_>>();
		let right_names = node_right
			.children
			.keys()
			.map(|x| x.as_os_str())
			.collect::<std::collections::HashSet<_>>();
		let left_only = left_names.difference(&right_names);
		let common = left_names.intersection(&right_names);
		let right_only = right_names.difference(&left_names);
		for &name in left_only {
			// These names only exist on the left, and so there is no
			// common paths under them, therefore we use walk_impl to do a
			// one-sided walk.
			let orig_path_len = path.len();
			if path.last().copied() != Some(b'/') {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			self.walk_impl(
				&mut |path, left| f(path, Some(left), None),
				false,
				path,
				&node_left.children[name],
			);
			path.truncate(orig_path_len);
		}
		for &name in common {
			let orig_path_len = path.len();
			if path.last().copied() != Some(b'/') {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			self.diff_impl(
				other,
				f,
				split_on,
				path,
				&node_left.children[name],
				&node_right.children[name],
			);
			path.truncate(orig_path_len);
		}
		for &name in right_only {
			// These names only exist on the right, and so there is no
			// common paths under them, therefore we use walk_impl to do a
			// one-sided walk.
			let orig_path_len = path.len();
			if path.last().copied() != Some(b'/') {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			other.walk_impl(
				&mut |path, right| f(path, None, Some(right)),
				true,
				path,
				&node_right.children[name],
			);
			path.truncate(orig_path_len);
		}
	}
}

impl<T: Display> Display for FsTree<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut result = Ok(());
		self.walk_top_down(|path, target| {
			if result.is_ok() {
				result = writeln!(f, "{:?}: {}", path, target);
			}
		});
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Recursively count nodes (excluding root) so we can detect any
	/// "useless" empty branches left behind.
	fn count_nodes<T>(node: &FsTreeNode<T>) -> usize {
		let mut n = node.children.len();
		for child in node.children.values() {
			n += count_nodes(child);
		}
		n
	}

	#[test]
	fn remove_prunes_useless_branches() {
		let mut tree: FsTree<i32> = FsTree::new();
		tree.insert(OsStr::new("/a/b/c"), 1);
		tree.insert(OsStr::new("/a/b/d"), 2);
		tree.insert(OsStr::new("/a/e"), 3);
		tree.insert(OsStr::new("/x/y/z"), 4);

		// 4 entries, and the internal node count covers every path
		// component: a, b, c, d, e, x, y, z = 8 nodes.
		assert_eq!(tree.len(), 4);
		assert_eq!(count_nodes(&tree.root), 8);

		// Removing /a/b/c: /a/b still has child d, so only the c node
		// is dropped.
		assert_eq!(tree.remove(OsStr::new("/a/b/c")), Some(1));
		assert_eq!(tree.len(), 3);
		assert_eq!(count_nodes(&tree.root), 7);
		assert!(
			tree.root.children[OsStr::new("a")].children[OsStr::new("b")]
				.children
				.contains_key(OsStr::new("d"))
		);
		assert!(
			!tree.root.children[OsStr::new("a")].children[OsStr::new("b")]
				.children
				.contains_key(OsStr::new("c"))
		);

		// Removing /a/b/d: now /a/b is empty and has no data, so b
		// should be pruned. /a still has /a/e so /a remains.
		assert_eq!(tree.remove(OsStr::new("/a/b/d")), Some(2));
		assert_eq!(tree.len(), 2);
		assert!(
			!tree.root.children[OsStr::new("a")]
				.children
				.contains_key(OsStr::new("b"))
		);
		assert!(
			tree.root.children[OsStr::new("a")]
				.children
				.contains_key(OsStr::new("e"))
		);
		// remaining nodes: a, e, x, y, z
		assert_eq!(count_nodes(&tree.root), 5);

		// Removing /a/e: /a has no data and no children -> /a is also
		// pruned all the way to the root.
		assert_eq!(tree.remove(OsStr::new("/a/e")), Some(3));
		assert_eq!(tree.len(), 1);
		assert!(!tree.root.children.contains_key(OsStr::new("a")));
		assert_eq!(count_nodes(&tree.root), 3); // x, y, z

		// Removing /x/y/z: the whole /x/y/z chain should collapse.
		assert_eq!(tree.remove(OsStr::new("/x/y/z")), Some(4));
		assert_eq!(tree.len(), 0);
		assert!(tree.is_empty());
		assert!(tree.root.children.is_empty());
		assert!(tree.root.data.is_none());
	}

	#[test]
	fn remove_keeps_intermediate_node_with_data() {
		// /a has its own data and a child /a/b; removing /a/b must not
		// drop the /a node since /a still carries data.
		let mut tree: FsTree<i32> = FsTree::new();
		tree.insert(OsStr::new("/a"), 10);
		tree.insert(OsStr::new("/a/b"), 20);
		assert_eq!(tree.len(), 2);

		assert_eq!(tree.remove(OsStr::new("/a/b")), Some(20));
		assert_eq!(tree.len(), 1);
		assert!(tree.root.children.contains_key(OsStr::new("a")));
		assert!(tree.root.children[OsStr::new("a")].children.is_empty());
		assert_eq!(tree.root.children[OsStr::new("a")].data, Some(10));
	}

	#[test]
	fn remove_missing_path_is_noop() {
		let mut tree: FsTree<i32> = FsTree::new();
		tree.insert(OsStr::new("/a/b"), 1);
		let nodes_before = count_nodes(&tree.root);

		assert_eq!(tree.remove(OsStr::new("/a/c")), None);
		assert_eq!(tree.remove(OsStr::new("/a/b/c")), None);
		assert_eq!(tree.remove(OsStr::new("/nope")), None);
		// /a has no data of its own; make sure we did not accidentally
		// touch the data or prune anything when probing a missing key.
		assert_eq!(tree.len(), 1);
		assert_eq!(count_nodes(&tree.root), nodes_before);
		assert!(
			tree.root.children[OsStr::new("a")]
				.children
				.contains_key(OsStr::new("b"))
		);

		// Path present in the tree as an intermediate node but with no
		// data of its own: remove should return None and leave
		// everything intact.
		assert_eq!(tree.remove(OsStr::new("/a")), None);
		assert_eq!(tree.len(), 1);
		assert_eq!(count_nodes(&tree.root), nodes_before);
	}

	fn collect_subtree(tree: &FsTree<i32>, root: &str, topmost_only: bool) -> Vec<String> {
		let mut out = Vec::new();
		tree.walk_subtree_top_down(OsStr::new(root), topmost_only, |p, _| {
			out.push(p.to_str().unwrap().to_string());
		});
		out.sort();
		out
	}

	#[test]
	fn walk_subtree_topmost_and_all() {
		let mut tree: FsTree<i32> = FsTree::new();
		tree.insert(OsStr::new("/a"), 0);
		tree.insert(OsStr::new("/a/b"), 1);
		tree.insert(OsStr::new("/a/b/c/d"), 2);
		tree.insert(OsStr::new("/a/b/c/d/e/f"), 3);
		tree.insert(OsStr::new("/a/g"), 4);

		// topmost direct sub-entries of /a: /a/b and /a/g (not /a itself,
		// and nothing buried beneath /a/b).
		assert_eq!(collect_subtree(&tree, "/a", true), &["/a/b", "/a/g"]);
		// everything strictly under /a.
		assert_eq!(
			collect_subtree(&tree, "/a", false),
			&["/a/b", "/a/b/c/d", "/a/b/c/d/e/f", "/a/g"]
		);
		// topmost under /a/b skips /a/b itself and stops at /a/b/c/d.
		assert_eq!(collect_subtree(&tree, "/a/b", true), &["/a/b/c/d"]);
	}

	#[test]
	fn walk_subtree_root_and_missing() {
		let mut tree: FsTree<i32> = FsTree::new();
		tree.insert(OsStr::new("/x"), 1);
		tree.insert(OsStr::new("/y/z"), 2);

		// From the tree root: topmost are /x and /y/z (/y has no data of
		// its own so descent continues into it).
		assert_eq!(collect_subtree(&tree, "/", true), &["/x", "/y/z"]);

		// A root not present in the tree visits nothing.
		assert_eq!(collect_subtree(&tree, "/nope", true), Vec::<String>::new());
		// A data leaf with no children visits nothing.
		assert_eq!(collect_subtree(&tree, "/x", false), Vec::<String>::new());
	}
}
