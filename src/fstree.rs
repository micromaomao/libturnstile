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
		self.remaining.is_empty()
	}
}

impl<'a> Iterator for PathToComponentsIter<'a> {
	type Item = PathComponent<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			if self.next_start >= self.path_bytes.len() {
				return None;
			}
			let parent_abs = if self.next_start == 0 {
				OsStr::new("")
			} else {
				OsStr::from_bytes(&self.path_bytes[..self.next_start - 1])
			};
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

#[derive(Debug, Clone)]
struct FsTreeNode<T> {
	target: T,
	children: HashMap<OsString, FsTreeNode<T>>,
}

/// A in-memory representation of a filesystem tree with custom data.
#[derive(Debug, Clone)]
pub struct FsTree<T> {
	root: FsTreeNode<T>,
}

pub enum DiffTree<'a, T1, T2> {
	Updated(&'a T1, &'a T2),
	Added(&'a T2),
	Removed(&'a T1),
}

impl<T> FsTree<T> {
	pub fn new(root: T) -> Self {
		FsTree {
			root: FsTreeNode {
				target: root,
				children: HashMap::new(),
			},
		}
	}

	/// Returns the target at the exact path
	pub fn get(&self, path: &OsStr) -> Option<&T> {
		let mut current = &self.root;
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get(comp.name) {
				current = v;
			} else {
				return None;
			}
		}
		Some(&current.target)
	}

	/// Returns a mutable reference to the target at the exact path
	pub fn get_mut(&mut self, path: &OsStr) -> Option<&mut T> {
		let mut current = &mut self.root;
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get_mut(comp.name) {
				current = v;
			} else {
				return None;
			}
		}
		Some(&mut current.target)
	}

	/// Return either the path's tree node itself if it matches some
	/// predicate, or the closest parent matching the predicate (called on
	/// all components).
	pub fn find<'a, P: FnMut(&'a OsStr, &T) -> bool>(
		&mut self,
		path: &'a OsStr,
		mut predicate: P,
	) -> Option<(&'a OsStr, &T)> {
		let mut current = &self.root;
		let mut last_matching: Option<(&'a OsStr, &T)> = None;
		if predicate(OsStr::new(""), &self.root.target) {
			last_matching = Some((OsStr::new(""), &self.root.target));
		}
		for comp in path_to_components(path) {
			if let Some(v) = current.children.get(comp.name) {
				current = v;
				if predicate(comp.path_from_root, &current.target) {
					last_matching = Some((comp.path_from_root, &current.target));
				}
			} else {
				return last_matching;
			}
		}
		last_matching
	}

	/// Insert path, and all necessary parents, into this FsTree, using
	/// the constructor to create new nodes.
	pub fn insert<'a, F: FnMut(&'a OsStr) -> T>(
		&mut self,
		path: &'a OsStr,
		mut constructor: F,
	) -> &mut T {
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
					let new_node = constructor(comp.parent_path_from_root);
					current = e.insert(FsTreeNode {
						target: new_node,
						children: HashMap::new(),
					});
				}
			}
		}
		&mut current.target
	}

	/// Remove the path and everything under it from the tree.
	pub fn remove(&mut self, path: &OsStr) {
		let mut current = &mut self.root;
		for comp in path_to_components(path) {
			if comp.is_last() {
				current.children.remove(comp.name);
				return;
			}
			if let Some(v) = current.children.get_mut(comp.name) {
				current = v;
			} else {
				// not found
				return;
			}
		}
		// root
		current.children.clear();
	}

	fn walk_impl<F: FnMut(&OsStr, &T)>(
		&self,
		mut f: F,
		top_down: bool,
		path: &mut Vec<u8>,
		node: &FsTreeNode<T>,
	) {
		if top_down {
			f(OsStr::from_bytes(path), &node.target);
		}
		#[cfg(debug_assertions)]
		let mut sorted_vec = node.children.iter().collect::<Vec<_>>();
		#[cfg(debug_assertions)]
		sorted_vec.sort_unstable_by_key(|(k, _)| *k);
		#[cfg(debug_assertions)]
		let iter = sorted_vec.iter();
		#[cfg(not(debug_assertions))]
		let iter = node.children.iter();
		for (comp, child) in iter {
			let orig_path_len = path.len();
			if !path.is_empty() {
				path.push(b'/');
			}
			path.extend_from_slice(comp.as_bytes());
			self.walk_impl(&mut f, top_down, path, child);
			path.truncate(orig_path_len);
		}
		if !top_down {
			f(OsStr::from_bytes(path), &node.target);
		}
	}

	/// Walks the tree in top-down order, e.g. /, /foo, /foo/bar, /baz.
	/// Iteration order for entries of the same directory is arbitrary.
	pub fn walk_top_down<F: FnMut(&OsStr, &T)>(&self, f: F) {
		self.walk_impl(f, true, &mut Vec::new(), &self.root);
	}

	/// Walks the tree in bottom-up order, e.g. /foo/bar, /foo, /baz, /.
	/// Iteration order for entries of the same directory is arbitrary.
	pub fn walk_bottom_up<F: FnMut(&OsStr, &T)>(&self, f: F) {
		self.walk_impl(f, false, &mut Vec::new(), &self.root);
	}

	fn diff_impl<
		T2,
		F: FnMut(&OsStr, Option<&T>, Option<&T2>),
		S: FnMut(&OsStr, &T, &T2) -> bool,
	>(
		&self,
		other: &FsTree<T2>,
		mut f: F,
		mut split_on: S,
		path: &mut Vec<u8>,
		node_left: &FsTreeNode<T>,
		node_right: &FsTreeNode<T2>,
	) {
		let should_split = split_on(
			OsStr::from_bytes(path),
			&node_left.target,
			&node_right.target,
		);
		if should_split {
			self.walk_impl(
				|path, left| f(path, Some(left), None),
				false,
				path,
				node_left,
			);
			other.walk_impl(
				|path, right| f(path, None, Some(right)),
				true,
				path,
				node_right,
			);
			return;
		}
		f(
			OsStr::from_bytes(path),
			Some(&node_left.target),
			Some(&node_right.target),
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
			let orig_path_len = path.len();
			if !path.is_empty() {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			self.walk_impl(
				|path, left| f(path, Some(left), None),
				false,
				path,
				&node_left.children[name],
			);
			path.truncate(orig_path_len);
		}
		for &name in common {
			let orig_path_len = path.len();
			if !path.is_empty() {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			self.diff_impl(
				other,
				&mut f,
				&mut split_on,
				path,
				&node_left.children[name],
				&node_right.children[name],
			);
			path.truncate(orig_path_len);
		}
		for &name in right_only {
			let orig_path_len = path.len();
			if !path.is_empty() {
				path.push(b'/');
			}
			path.extend_from_slice(name.as_bytes());
			other.walk_impl(
				|path, right| f(path, None, Some(right)),
				true,
				path,
				&node_right.children[name],
			);
			path.truncate(orig_path_len);
		}
	}

	/// Produce the difference between two trees.  self is considered the
	/// "old" tree and other is considered the "new" tree.  For entries
	/// that are in both trees, if split_on returns true, they are
	/// traversed separately (resulting in a [`DiffTree::Removed`] for
	/// everything in the old tree and a [`DiffTree::Added`] for
	/// everything in the new tree).
	///
	/// For trees removed, the iteration order is bottom-up, e.g.
	/// /foo/bar, /foo, /baz, /.  For trees added or updated, the
	/// iteration order is top-down, e.g. /, /foo, /foo/bar.
	pub fn diff<T2, F: FnMut(&OsStr, DiffTree<T, T2>), S: FnMut(&OsStr, &T, &T2) -> bool>(
		&self,
		other: &FsTree<T2>,
		mut f: F,
		mut split_on: S,
	) {
		self.diff_impl(
			other,
			|path, t1, t2| {
				let diff = match (t1, t2) {
					(Some(t1), Some(t2)) => DiffTree::Updated(t1, t2),
					(Some(t1), None) => DiffTree::Removed(t1),
					(None, Some(t2)) => DiffTree::Added(t2),
					(None, None) => return,
				};
				f(path, diff);
			},
			&mut split_on,
			&mut Vec::new(),
			&self.root,
			&other.root,
		);
	}
}

impl<T: Display> Display for FsTree<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.walk_top_down(|path, target| {
			let _ = writeln!(f, "{:?}: {}", path, target);
		});
		Ok(())
	}
}
