//! Configuration file parsing for `turnstile-sandbox`.
//!
//! See the top-level documentation of [`Config`] for the on-disk format.

use std::{
	collections::BTreeMap,
	ffi::{CString, OsString},
	fs,
	os::unix::ffi::{OsStrExt, OsStringExt},
	path::Path,
};

use libturnstile::{ManagedMountPoint, MountAttributes};
use serde::Deserialize;

/// Top-level configuration document.
///
/// ```yaml
/// rules:
///     /home/mao/code: rx
///     /etc: r
///     $PWD: rwx
///     $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY: rw
///     $XDG_RUNTIME_DIR:
///         target: $XDG_RUNTIME_DIR/my-app
///         permissions: rw
///     /proc:
///         ignore: true
///     /home/mao:
///         permissions: r
///         ignore: true
/// ```
///
/// An `ignore: true` rule marks a path (and everything under it) as one
/// turnstile-sandbox passes through unmediated instead of prompting for
/// or denying.  On its own it leaves the path entirely alone; combined
/// with `permissions` it grants that access and only passes through what
/// the grant does not already cover (e.g. `permissions: r` + `ignore:
/// true` serves reads from the mount but lets writes/execs through).
#[derive(Debug, Deserialize)]
pub struct Config {
	#[serde(default)]
	pub rules: BTreeMap<String, Rule>,
}

/// A single rule value, which is either a permission string or a mapping.
///
/// The mapping form carries an optional `target` (host path), optional
/// `permissions`, and an optional `ignore` flag.  `ignore: true` may
/// stand alone (leave the path entirely alone) or accompany
/// `permissions` (grant that access, but pass through anything it does
/// not cover instead of prompting/denying).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Rule {
	Simple(String),
	Detailed {
		/// Host path that should be mounted.  Path expansion (`$$` and
		/// `$ENV_VAR`) applies here as well.  Defaults to the rule's key
		/// (the sandbox path) when not specified.
		#[serde(default)]
		target: Option<String>,
		/// Access to grant, e.g. `rx`.  An empty string is a resolve-only
		/// placeholder.  Absent means no mount/placeholder (only valid
		/// together with `ignore: true`).
		#[serde(default)]
		permissions: Option<String>,
		/// Pass requests this rule does not otherwise grant through
		/// unmediated, without mounting, prompting, or denying.
		#[serde(default)]
		ignore: bool,
	},
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	#[error("error reading config file {path:?}: {source}")]
	Io {
		path: std::path::PathBuf,
		#[source]
		source: std::io::Error,
	},
	#[error("error parsing config file {path:?}: {source}")]
	Parse {
		path: std::path::PathBuf,
		#[source]
		source: serde_yaml_ng::Error,
	},
	#[error("invalid permission string {0:?}: must only contain 'r', 'w', and 'x'")]
	InvalidPermission(String),
	#[error("invalid permission string {0:?}: must contain 'r'")]
	MissingReadPermission(String),
	#[error("invalid path {0:?}: {1}")]
	InvalidPath(String, &'static str),
	#[error("environment variable {0:?} referenced in path {1:?} is not set")]
	MissingEnvVar(String, String),
	#[error("path {0:?} resolved to an empty string after expansion")]
	EmptyPath(String),
	#[error("path {0:?} contains a NUL byte after expansion")]
	NulInPath(String),
	#[error("rule {0:?} must specify 'permissions' and/or 'ignore: true'")]
	EmptyRule(String),
}

/// Parse a permission string like `"r"`, `"rx"`, `"rw"`, `"rwx"` into
/// [`MountAttributes`].
///
/// Each character must be one of `r`, `w`, `x`.  Presence of `w` clears
/// `readonly`; presence of `x` clears `noexec`, and `r` is required.
/// Different orderings or duplicate letters are allowed.
pub fn parse_permissions(s: &str) -> Result<MountAttributes, ConfigError> {
	let mut readonly = true;
	let mut noexec = true;
	let mut has_read = false;
	for c in s.chars() {
		match c {
			'r' => has_read = true,
			'w' => readonly = false,
			'x' => noexec = false,
			_ => return Err(ConfigError::InvalidPermission(s.to_string())),
		}
	}
	if !has_read {
		return Err(ConfigError::MissingReadPermission(s.to_string()));
	}
	Ok(MountAttributes { readonly, noexec })
}

/// Expand `$$` and `$VAR` references in `input`, returning the resulting bytes.
///
/// - `$$` becomes a literal `$`.
/// - `$NAME` (where `NAME` matches `[A-Za-z0-9_]+`) is substituted with the
///   value of the environment variable `NAME`.  If the variable is not set,
///   [`ConfigError::MissingEnvVar`] is returned.
/// - A `$` not followed by `$` or `[A-Za-z0-9_]` is an error.
///
/// Operates on bytes so that environment variables containing arbitrary
/// non-UTF-8 bytes are preserved verbatim.
pub fn expand_path(input: &str) -> Result<Vec<u8>, ConfigError> {
	let bytes = input.as_bytes();
	let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		let b = bytes[i];
		if b != b'$' {
			out.push(b);
			i += 1;
			continue;
		}
		// b == '$'
		if i + 1 >= bytes.len() {
			return Err(ConfigError::InvalidPath(
				input.to_string(),
				"trailing '$' must be followed by '$' or an environment variable name",
			));
		}
		let next = bytes[i + 1];
		if next == b'$' {
			out.push(b'$');
			i += 2;
			continue;
		}
		if !is_var_char(next) {
			return Err(ConfigError::InvalidPath(
				input.to_string(),
				"'$' must be followed by '$' or [A-Za-z0-9_]",
			));
		}
		let mut j = i + 1;
		while j < bytes.len() && is_var_char(bytes[j]) {
			j += 1;
		}
		let name = std::str::from_utf8(&bytes[i + 1..j]).expect("ascii slice");
		match std::env::var_os(name) {
			Some(val) => out.extend_from_slice(val.as_bytes()),
			None => {
				return Err(ConfigError::MissingEnvVar(
					name.to_string(),
					input.to_string(),
				));
			}
		}
		i = j;
	}
	Ok(out)
}

fn is_var_char(b: u8) -> bool {
	b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether any `/`-separated component of `path` is `.` or `..`.  Such
/// paths are not canonical and cannot be represented by the sandbox
/// mount tree, which walks components and forbids dots.
fn path_has_dot_component(path: &[u8]) -> bool {
	path.split(|&b| b == b'/')
		.any(|comp| comp == b"." || comp == b"..")
}

/// A single parsed config entry, ready to be passed to
/// [`libturnstile::ManagedBindMountSandbox::update_from_list`].
pub struct ConfigEntry {
	/// Path inside the sandbox.
	pub sandbox_path: OsString,
	/// Mount point describing the host source and attributes.  If None,
	/// this is a placeholder-only (resolve-only) entry, or carries no
	/// mount at all (an ignore-only rule).
	pub mount: Option<ManagedMountPoint>,
	/// If self.mount is None, this is the host path that should be used
	/// to create a placeholder.  None for ignore-only entries.
	pub placeholder_host_path: Option<CString>,
	/// Whether this rule passes through requests it does not otherwise
	/// grant (`ignore: true`).  May be set together with a mount.
	pub ignore: bool,
}

impl Config {
	/// Read and parse a configuration file.
	pub fn load(path: &Path) -> Result<Self, ConfigError> {
		let content = fs::read_to_string(path).map_err(|e| ConfigError::Io {
			path: path.to_path_buf(),
			source: e,
		})?;
		let cfg: Config = serde_yaml_ng::from_str(&content).map_err(|e| ConfigError::Parse {
			path: path.to_path_buf(),
			source: e,
		})?;
		Ok(cfg)
	}

	/// Parse all rules into a list of entries.  Performs path expansion
	/// (`$$` / `$VAR`) and permission parsing, returning errors produced
	/// along the way.
	pub fn parse_entries(&self) -> Result<Vec<ConfigEntry>, ConfigError> {
		let mut out = Vec::with_capacity(self.rules.len());
		for (sandbox_path_raw, rule) in &self.rules {
			let sandbox_bytes = expand_path(sandbox_path_raw)?;
			if sandbox_bytes.is_empty() {
				return Err(ConfigError::EmptyPath(sandbox_path_raw.clone()));
			}
			if sandbox_bytes.contains(&0) {
				return Err(ConfigError::NulInPath(sandbox_path_raw.clone()));
			}
			// The sandbox mount tree walks path components and rejects "."
			// / ".." (it would otherwise panic), so reject such paths here
			// with a clean error instead of crashing on insertion.
			if path_has_dot_component(&sandbox_bytes) {
				return Err(ConfigError::InvalidPath(
					sandbox_path_raw.clone(),
					"'.' and '..' path components are not allowed in sandbox paths",
				));
			}

			let (target, permissions, ignore) = match rule {
				Rule::Simple(p) => (None, Some(p.as_str()), false),
				Rule::Detailed {
					target,
					permissions,
					ignore,
				} => (target.as_deref(), permissions.as_deref(), *ignore),
			};

			// Build the mount or placeholder from the permissions, if any.
			// A non-empty permission string is a mount, an empty string is
			// a resolve-only placeholder, and an absent one means neither
			// (only valid alongside `ignore: true`).
			let (mount, placeholder_host_path) = match permissions {
				Some(perms) => {
					let host_path_raw = target.unwrap_or(sandbox_path_raw.as_str());
					let host_bytes = expand_path(host_path_raw)?;
					if host_bytes.is_empty() {
						return Err(ConfigError::EmptyPath(host_path_raw.to_string()));
					}
					let host_path = CString::new(host_bytes)
						.map_err(|_| ConfigError::NulInPath(host_path_raw.to_string()))?;
					if perms.is_empty() {
						(None, Some(host_path))
					} else {
						(
							Some(ManagedMountPoint {
								host_path,
								attrs: parse_permissions(perms)?,
							}),
							None,
						)
					}
				}
				None => (None, None),
			};

			if mount.is_none() && placeholder_host_path.is_none() && !ignore {
				return Err(ConfigError::EmptyRule(sandbox_path_raw.clone()));
			}

			out.push(ConfigEntry {
				sandbox_path: OsString::from_vec(sandbox_bytes),
				mount,
				placeholder_host_path,
				ignore,
			});
		}
		Ok(out)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn permissions_basic() {
		assert_eq!(
			parse_permissions("r").unwrap(),
			MountAttributes {
				readonly: true,
				noexec: true
			}
		);
		assert_eq!(
			parse_permissions("rx").unwrap(),
			MountAttributes {
				readonly: true,
				noexec: false
			}
		);
		assert_eq!(
			parse_permissions("rw").unwrap(),
			MountAttributes {
				readonly: false,
				noexec: true
			}
		);
		assert_eq!(
			parse_permissions("rwx").unwrap(),
			MountAttributes {
				readonly: false,
				noexec: false
			}
		);
		assert!(parse_permissions("rz").is_err());
	}

	#[test]
	fn expand_no_dollar() {
		assert_eq!(expand_path("/etc").unwrap(), b"/etc");
	}

	#[test]
	fn expand_double_dollar() {
		assert_eq!(expand_path("/foo/$$bar").unwrap(), b"/foo/$bar");
	}

	#[test]
	fn expand_env_var() {
		// SAFETY: this test sets an env var; std::env::set_var is unsafe in
		// recent Rust because it is not thread-safe, but the test is
		// single-threaded and uses a unique variable name.
		unsafe {
			std::env::set_var("TURNSTILE_TEST_VAR", "/tmp/xyz");
		}
		assert_eq!(
			expand_path("$TURNSTILE_TEST_VAR/file").unwrap(),
			b"/tmp/xyz/file"
		);
	}

	#[test]
	fn expand_missing_env_var() {
		unsafe {
			std::env::remove_var("TURNSTILE_NOT_SET_VAR");
		}
		assert!(matches!(
			expand_path("$TURNSTILE_NOT_SET_VAR"),
			Err(ConfigError::MissingEnvVar(_, _))
		));
	}

	#[test]
	fn expand_bare_dollar_fails() {
		assert!(expand_path("/foo/$/bar").is_err());
		assert!(expand_path("/foo/$").is_err());
	}

	#[test]
	fn parse_full_config() {
		unsafe {
			std::env::set_var("TURNSTILE_HOME", "/home/mao");
			std::env::set_var("TURNSTILE_RT", "/run/user/1000");
		}
		let yaml = r#"
rules:
    /etc: r
    $TURNSTILE_HOME/code: rx
    $TURNSTILE_RT:
        target: $TURNSTILE_RT/my-app
        permissions: rw
"#;
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let mounts = cfg.parse_entries().unwrap();
		assert_eq!(mounts.len(), 3);
		// rules are kept in BTreeMap order (sorted by sandbox path string).
		let by_path: std::collections::HashMap<_, _> = mounts
			.iter()
			.map(|m| (m.sandbox_path.as_bytes().to_vec(), m))
			.collect();
		let etc = by_path.get(&b"/etc"[..]).unwrap();
		let etc_mount = etc.mount.as_ref().unwrap();
		assert_eq!(etc_mount.host_path.to_bytes(), b"/etc");
		assert_eq!(etc_mount.attrs.readonly, true);
		assert_eq!(etc_mount.attrs.noexec, true);

		let code = by_path.get(&b"/home/mao/code"[..]).unwrap();
		let code_mount = code.mount.as_ref().unwrap();
		assert_eq!(code_mount.host_path.to_bytes(), b"/home/mao/code");
		assert_eq!(code_mount.attrs.readonly, true);
		assert_eq!(code_mount.attrs.noexec, false);

		let rt = by_path.get(&b"/run/user/1000"[..]).unwrap();
		let rt_mount = rt.mount.as_ref().unwrap();
		assert_eq!(rt_mount.host_path.to_bytes(), b"/run/user/1000/my-app");
		assert_eq!(rt_mount.attrs.readonly, false);
		assert_eq!(rt_mount.attrs.noexec, true);
	}

	#[test]
	fn parse_ignore_rule() {
		let yaml = r#"
rules:
    /etc: r
    /proc:
        ignore: true
"#;
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let entries = cfg.parse_entries().unwrap();
		assert_eq!(entries.len(), 2);
		let by_path: std::collections::HashMap<_, _> = entries
			.iter()
			.map(|e| (e.sandbox_path.as_bytes().to_vec(), e))
			.collect();
		let etc = by_path.get(&b"/etc"[..]).unwrap();
		assert!(!etc.ignore);
		assert!(etc.mount.is_some());
		let proc = by_path.get(&b"/proc"[..]).unwrap();
		assert!(proc.ignore);
		assert!(proc.mount.is_none());
		assert!(proc.placeholder_host_path.is_none());
	}

	#[test]
	fn parse_grant_plus_ignore() {
		let yaml = r#"
rules:
    /home/mao:
        permissions: r
        ignore: true
"#;
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let entries = cfg.parse_entries().unwrap();
		assert_eq!(entries.len(), 1);
		let e = &entries[0];
		assert!(e.ignore);
		let mount = e.mount.as_ref().unwrap();
		assert_eq!(mount.host_path.to_bytes(), b"/home/mao");
		assert_eq!(mount.attrs.readonly, true);
		assert_eq!(mount.attrs.noexec, true);
	}

	#[test]
	fn reject_empty_rule() {
		let yaml = "rules:\n    /foo: {}\n";
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		assert!(matches!(
			cfg.parse_entries(),
			Err(ConfigError::EmptyRule(_))
		));
	}

	#[test]
	fn reject_dot_components() {
		for p in ["/a/..", "/a/../b", "/a/.", "/./a", ".."] {
			let yaml = format!("rules:\n    \"{p}\": r\n");
			let cfg: Config = serde_yaml_ng::from_str(&yaml).unwrap();
			assert!(
				matches!(cfg.parse_entries(), Err(ConfigError::InvalidPath(_, _))),
				"expected {p:?} to be rejected"
			);
		}
	}

	#[test]
	fn parse_binary_path() {
		// YAML escape \x12\x34 produces U+0012 and U+0034, both ASCII-range
		// so they encode to single bytes in UTF-8 and round-trip as path
		// bytes.
		let yaml = "rules:\n    \"\\x12\\x34\": r\n";
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let mounts = cfg.parse_entries().unwrap();
		assert_eq!(mounts.len(), 1);
		assert_eq!(mounts[0].sandbox_path.as_bytes(), &[0x12, 0x34]);
		assert_eq!(
			mounts[0].mount.as_ref().unwrap().host_path.to_bytes(),
			&[0x12, 0x34]
		);
	}

	#[test]
	fn dollar_dollar_in_full_config() {
		let yaml = "rules:\n    /a/$$b: r\n";
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let mounts = cfg.parse_entries().unwrap();
		assert_eq!(mounts[0].sandbox_path.as_bytes(), b"/a/$b");
	}
}
