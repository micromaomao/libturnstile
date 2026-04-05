use std::{
	collections::{HashMap, hash_map},
	ffi::{OsStr, OsString},
	fmt::Display,
	os::unix::ffi::OsStrExt,
};

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

enum EntryState<'a, T> {
	Exist(&'a mut FsTreeNode<T>),
	PlaceIn {
		entry: hash_map::Entry<'a, OsString, FsTreeNode<T>>,
	},
	ParentMissing {
		first_child_entry: hash_map::Entry<'a, OsString, FsTreeNode<T>>,
		missing_path_afterwards: OsString,
	},
}

pub struct Entry<'a, T> {
	state: EntryState<'a, T>,
	path: OsString,
}

impl<'a, T> Entry<'a, T> {
	pub fn get_mut(&mut self) -> Option<&mut T> {
		match &mut self.state {
			EntryState::Exist(node) => Some(&mut node.target),
			_ => None,
		}
	}

	/// Get a mutable reference to the target of this entry, creating it
	/// and any missing parents if necessary.
	///
	/// create_node and create_missing_parent are called with the full
	/// path of the node to create (but without leading slash).
	pub fn get_mut_or_insert_with<F1: FnOnce(&OsStr) -> T, F2: FnMut(&OsStr) -> T>(
		self,
		create_node: F1,
		mut create_missing_parent: F2,
	) -> &'a mut T {
		debug_assert!(!self.path.as_bytes().starts_with(b"/"));
		let mut create_node = Some(create_node);
		match self.state {
			EntryState::Exist(node) => &mut node.target,
			EntryState::PlaceIn { entry } => {
				let node = entry.or_insert_with(|| FsTreeNode {
					target: create_node.take().unwrap()(&self.path),
					children: HashMap::new(),
				});
				&mut node.target
			}
			EntryState::ParentMissing {
				first_child_entry,
				missing_path_afterwards,
			} => {
				let mut built_up_prefix = self.path;
				let mut current = first_child_entry.or_insert_with_key(|k| {
					if !built_up_prefix.is_empty() {
						built_up_prefix.push(OsStr::new("/"));
					}
					built_up_prefix.push(k);
					FsTreeNode {
						target: create_missing_parent(&built_up_prefix),
						children: HashMap::new(),
					}
				});
				let mut iter = missing_path_afterwards
					.as_bytes()
					.split(|&b| b == b'/')
					.filter(|s| !s.is_empty())
					.peekable();
				loop {
					match iter.next() {
						Some(comp) => {
							let comp_os = OsStr::from_bytes(comp);
							built_up_prefix.push(OsStr::new("/"));
							built_up_prefix.push(comp_os);
							current =
								current
									.children
									.entry(comp_os.to_owned())
									.or_insert_with(|| {
										let target = if iter.peek().is_some() {
											create_missing_parent(&built_up_prefix)
										} else {
											create_node.take().unwrap()(&built_up_prefix)
										};
										FsTreeNode {
											target,
											children: HashMap::new(),
										}
									});
						}
						None => break,
					}
				}
				&mut current.target
			}
		}
	}
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

	pub fn get(&self, path: &OsStr) -> Option<&T> {
		let pathb = path.as_bytes();
		let mut current = &self.root;
		for comp in pathb.split(|&b| b == b'/').filter(|comp| !comp.is_empty()) {
			let comp_os = OsStr::from_bytes(comp);
			if let Some(v) = current.children.get(comp_os) {
				current = v;
			} else {
				return None;
			}
		}
		Some(&current.target)
	}

	pub fn get_mut(&mut self, path: &OsStr) -> Option<&mut T> {
		let pathb = path.as_bytes();
		let mut current = &mut self.root;
		for comp in pathb.split(|&b| b == b'/').filter(|comp| !comp.is_empty()) {
			let comp_os = OsStr::from_bytes(comp);
			if let Some(v) = current.children.get_mut(comp_os) {
				current = v;
			} else {
				return None;
			}
		}
		Some(&mut current.target)
	}

	pub fn entry(&mut self, path: &OsStr) -> Entry<'_, T> {
		let pathb = path.as_bytes();
		let mut current = Some(&mut self.root);
		let components = pathb.split(|&b| b == b'/').filter(|comp| !comp.is_empty());
		let mut iter = components.into_iter();
		let mut built_up_prefix = OsString::new();
		loop {
			let comp = iter.next();
			match comp {
				None => {
					return Entry {
						state: EntryState::Exist(current.unwrap()),
						path: built_up_prefix,
					};
				}
				Some(comp) => {
					let comp_os = OsStr::from_bytes(comp);
					built_up_prefix.push(comp_os);
					if let Some(_) = current.as_mut().unwrap().children.get_mut(comp_os) {
						current = Some(current.take().unwrap().children.get_mut(comp_os).unwrap());
					} else {
						let entry = current.take().unwrap().children.entry(comp_os.to_owned());
						let mut remaining_path = OsString::new();
						while let Some(next) = iter.next() {
							if !remaining_path.is_empty() {
								remaining_path.push(OsStr::new("/"));
							}
							remaining_path.push(OsStr::from_bytes(next));
						}
						if remaining_path.is_empty() {
							return Entry {
								state: EntryState::PlaceIn { entry },
								path: built_up_prefix,
							};
						} else {
							return Entry {
								state: EntryState::ParentMissing {
									first_child_entry: entry,
									missing_path_afterwards: remaining_path,
								},
								path: built_up_prefix,
							};
						}
					}
				}
			}
		}
	}

	/// Remove entries in the subtree rooted at path for which drain
	/// returns true, including the path itself, except any parents of any
	/// entries for which drain returns false are kept (and drain won't be
	/// called).
	///
	/// If this is called on "/", the root itself is not drained, but its
	/// children are.
	pub fn drain_subtree_bottom_up<F: FnMut(&OsStr, &mut T) -> bool>(
		&mut self,
		path: &OsStr,
		mut drain: F,
	) {
		let pathb = path.as_bytes();
		let mut current = &mut self.root;
		let mut iter = pathb
			.split(|&b| b == b'/')
			.filter(|comp| !comp.is_empty())
			.peekable();
		fn helper<T, F: FnMut(&OsStr, &mut T) -> bool>(
			current: &mut FsTreeNode<T>,
			pathbuf: &mut Vec<u8>,
			drain: &mut F,
		) -> bool {
			current.children.retain(|k, v| {
				let orig_len = pathbuf.len();
				if !pathbuf.is_empty() {
					pathbuf.push(b'/');
				}
				pathbuf.extend_from_slice(k.as_bytes());
				let res = helper(v, pathbuf, drain);
				pathbuf.truncate(orig_len);
				!res
			});
			let should_remove = drain(OsStr::from_bytes(pathbuf), &mut current.target);
			should_remove
		}
		loop {
			let comp = iter.next();
			match comp {
				None => {
					// root
					helper(current, &mut Vec::new(), &mut drain);
					return;
				}
				Some(comp) => {
					let comp_os = OsStr::from_bytes(comp);
					if let Some(_) = current.children.get(comp_os) {
						if iter.peek().is_none() {
							// remove children of current/comp
							let mut pathbuf = pathb.to_vec();
							let mut comp_entry = current.children.remove_entry(comp_os).unwrap();
							if helper(&mut comp_entry.1, &mut pathbuf, &mut drain) {
								// remove current/comp itself
								let should_remove =
									drain(OsStr::from_bytes(pathb), &mut comp_entry.1.target);
								if !should_remove {
									current.children.insert(comp_entry.0, comp_entry.1);
								}
								return;
							}
						} else {
							current = current.children.get_mut(comp_os).unwrap();
						}
					} else {
						// path doesn't exist, so nothing to drain
						return;
					}
				}
			}
		}
	}

	/// Given a subtree, if it is empty, call drain to decide if it should
	/// be removed, and if yes, remove it and repeat this process on its
	/// parent.  If the given subtree is not empty, this does nothing.
	/// Returns whether any entry was removed.  Does nothing if given "/".
	pub fn drain_parents<F: FnMut(&OsStr, &mut T) -> bool>(
		&mut self,
		path: &OsStr,
		mut drain: F,
	) -> bool {
		let pathb = path.as_bytes();
		let components: Vec<&[u8]> = pathb
			.split(|&b| b == b'/')
			.filter(|comp| !comp.is_empty())
			.collect();

		if components.is_empty() {
			return false;
		}

		let mut any_removed = false;

		fn helper<T, F: FnMut(&OsStr, &mut T) -> bool>(
			node: &mut FsTreeNode<T>,
			components: &[&[u8]],
			depth: usize,
			path_buf: &mut Vec<u8>,
			drain: &mut F,
			any_removed: &mut bool,
		) -> bool {
			if depth == components.len() {
				return node.children.is_empty();
			}

			let comp = components[depth];
			let comp_os = OsStr::from_bytes(comp);

			if !node.children.contains_key(comp_os) {
				return false;
			}

			let orig_len = path_buf.len();
			if !path_buf.is_empty() {
				path_buf.push(b'/');
			}
			path_buf.extend_from_slice(comp);

			let child = node.children.get_mut(comp_os).unwrap();
			let should_remove = helper(child, components, depth + 1, path_buf, drain, any_removed);

			if should_remove {
				let child_key = comp_os.to_owned();
				let mut child_node = node.children.remove(&child_key).unwrap();
				if drain(OsStr::from_bytes(path_buf), &mut child_node.target) {
					*any_removed = true;
					path_buf.truncate(orig_len);
					return node.children.is_empty();
				} else {
					node.children.insert(child_key, child_node);
					path_buf.truncate(orig_len);
					return false;
				}
			}

			path_buf.truncate(orig_len);
			false
		}

		helper(
			&mut self.root,
			&components,
			0,
			&mut Vec::new(),
			&mut drain,
			&mut any_removed,
		);
		any_removed
	}

	pub fn remove_assert_no_subtree(&mut self, path: &OsStr) {
		self.drain_subtree_bottom_up(path, |p, _| {
			if p != path {
				panic!(
					"FsTree: expected no subtree at {:?}, but reached {:?}",
					path, p
				);
			}
			true
		});
	}

	pub fn remove_subtree(&mut self, path: &OsStr) {
		self.drain_subtree_bottom_up(path, |_, _| true);
	}

	fn walk_impl<F: FnMut(&OsStr, &T)>(&self, mut f: F, top_down: bool) {
		fn helper<T, F: FnMut(&OsStr, &T)>(
			node: &FsTreeNode<T>,
			path: &mut Vec<u8>,
			f: &mut F,
			top_down: bool,
		) {
			if top_down {
				f(OsStr::from_bytes(path), &node.target);
			}
			let mut sorted_vec = node.children.iter().collect::<Vec<_>>();
			sorted_vec.sort_unstable_by_key(|(k, _)| *k);
			for (comp, child) in sorted_vec.into_iter() {
				let orig_path_len = path.len();
				if !path.is_empty() {
					path.push(b'/');
				}
				path.extend_from_slice(comp.as_bytes());
				helper(child, path, f, top_down);
				path.truncate(orig_path_len);
			}
			if !top_down {
				f(OsStr::from_bytes(path), &node.target);
			}
		}
		let mut path = Vec::new();
		helper(&self.root, &mut path, &mut f, top_down);
	}

	/// Walks the tree in top-down order, e.g. /, /foo, /foo/bar, /baz
	pub fn walk_top_down<F: FnMut(&OsStr, &T)>(&self, f: F) {
		self.walk_impl(f, true);
	}

	/// Walks the tree in bottom-up order, e.g. /foo/bar, /foo, /baz, /
	pub fn walk_bottom_up<F: FnMut(&OsStr, &T)>(&self, f: F) {
		self.walk_impl(f, false);
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
	) {
		unimplemented!()
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
	pub fn diff_bottom_up_filtered<
		T2,
		F: FnMut(&OsStr, DiffTree<T, T2>),
		S: FnMut(&OsStr, &T, &T2) -> bool,
	>(
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
