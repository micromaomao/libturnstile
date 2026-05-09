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
/// ```
#[derive(Debug, Deserialize)]
pub struct Config {
	#[serde(default)]
	pub rules: BTreeMap<String, Rule>,
}

/// A single rule value, which is either a permission string or a mapping with
/// `target` (host path) and `permissions`.
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
		permissions: String,
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
	#[error("invalid path {0:?}: {1}")]
	InvalidPath(String, &'static str),
	#[error("environment variable {0:?} referenced in path {1:?} is not set")]
	MissingEnvVar(String, String),
	#[error("path {0:?} resolved to an empty string after expansion")]
	EmptyPath(String),
	#[error("path {0:?} contains a NUL byte after expansion")]
	NulInPath(String),
}

/// Parse a permission string like `"r"`, `"rx"`, `"rw"`, `"rwx"` into
/// [`MountAttributes`].
///
/// Each character must be one of `r`, `w`, `x`.  Presence of `w` clears
/// `readonly`; presence of `x` clears `noexec`.  `r` is required to make a
/// mount point useful, but extra `r`s or different orderings are allowed.
pub fn parse_permissions(s: &str) -> Result<MountAttributes, ConfigError> {
	let mut readonly = true;
	let mut noexec = true;
	for c in s.chars() {
		match c {
			'r' => {}
			'w' => readonly = false,
			'x' => noexec = false,
			_ => return Err(ConfigError::InvalidPermission(s.to_string())),
		}
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
		// SAFETY: var name chars are all ASCII, so this slice is valid UTF-8.
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

/// A single resolved mount entry, ready to be passed to
/// [`libturnstile::ManagedBindMountSandbox::update_mounts_from_list`].
pub struct ResolvedMount {
	/// Path inside the sandbox.
	pub sandbox_path: OsString,
	/// Mount point describing the host source and attributes.
	pub mount: ManagedMountPoint,
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

	/// Resolve all rules into a list of mount entries.  Performs path
	/// expansion (`$$` / `$VAR`) and permission parsing, returning errors
	/// produced along the way.
	pub fn resolve_mounts(&self) -> Result<Vec<ResolvedMount>, ConfigError> {
		let mut out = Vec::with_capacity(self.rules.len());
		for (sandbox_path_raw, rule) in &self.rules {
			let (host_path_raw, permissions) = match rule {
				Rule::Simple(p) => (sandbox_path_raw.as_str(), p.as_str()),
				Rule::Detailed {
					target,
					permissions,
				} => (
					target.as_deref().unwrap_or(sandbox_path_raw.as_str()),
					permissions.as_str(),
				),
			};
			let sandbox_bytes = expand_path(sandbox_path_raw)?;
			if sandbox_bytes.is_empty() {
				return Err(ConfigError::EmptyPath(sandbox_path_raw.clone()));
			}
			if sandbox_bytes.contains(&0) {
				return Err(ConfigError::NulInPath(sandbox_path_raw.clone()));
			}
			let host_bytes = expand_path(host_path_raw)?;
			if host_bytes.is_empty() {
				return Err(ConfigError::EmptyPath(host_path_raw.to_string()));
			}
			let host_path = CString::new(host_bytes)
				.map_err(|_| ConfigError::NulInPath(host_path_raw.to_string()))?;
			let attrs = parse_permissions(permissions)?;
			out.push(ResolvedMount {
				sandbox_path: OsString::from_vec(sandbox_bytes),
				mount: ManagedMountPoint {
					host_path,
					attrs,
				},
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
		let mounts = cfg.resolve_mounts().unwrap();
		assert_eq!(mounts.len(), 3);
		// rules are kept in BTreeMap order (sorted by sandbox path string).
		let by_path: std::collections::HashMap<_, _> = mounts
			.iter()
			.map(|m| (m.sandbox_path.as_bytes().to_vec(), m))
			.collect();
		let etc = by_path.get(&b"/etc"[..]).unwrap();
		assert_eq!(etc.mount.host_path.to_bytes(), b"/etc");
		assert_eq!(etc.mount.attrs.readonly, true);
		assert_eq!(etc.mount.attrs.noexec, true);

		let code = by_path.get(&b"/home/mao/code"[..]).unwrap();
		assert_eq!(code.mount.host_path.to_bytes(), b"/home/mao/code");
		assert_eq!(code.mount.attrs.readonly, true);
		assert_eq!(code.mount.attrs.noexec, false);

		let rt = by_path.get(&b"/run/user/1000"[..]).unwrap();
		assert_eq!(rt.mount.host_path.to_bytes(), b"/run/user/1000/my-app");
		assert_eq!(rt.mount.attrs.readonly, false);
		assert_eq!(rt.mount.attrs.noexec, true);
	}

	#[test]
	fn parse_binary_path() {
		// YAML escape \x12\x34 produces U+0012 and U+0034, both ASCII-range
		// so they encode to single bytes in UTF-8 and round-trip as path
		// bytes.
		let yaml = "rules:\n    \"\\x12\\x34\": r\n";
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let mounts = cfg.resolve_mounts().unwrap();
		assert_eq!(mounts.len(), 1);
		assert_eq!(mounts[0].sandbox_path.as_bytes(), &[0x12, 0x34]);
		assert_eq!(mounts[0].mount.host_path.to_bytes(), &[0x12, 0x34]);
	}

	#[test]
	fn dollar_dollar_in_full_config() {
		let yaml = "rules:\n    /a/$$b: r\n";
		let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
		let mounts = cfg.resolve_mounts().unwrap();
		assert_eq!(mounts[0].sandbox_path.as_bytes(), b"/a/$b");
	}
}
