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
	pub fn remove(&mut self, path: &OsStr) -> Option<T> {
		let mut current = &mut self.root;
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get_mut(comp.name) {
				current = v;
			} else {
				// not found
				return None;
			}
		}
		let ret = current.data.take();
		if ret.is_some() {
			self.nb_entries -= 1;
		}
		ret
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
