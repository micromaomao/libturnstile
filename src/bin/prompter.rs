use std::{
	io::{self, Write},
	os::fd::{AsRawFd, BorrowedFd},
	os::unix::process::CommandExt,
	process::{Command, Stdio},
};

use libturnstile::{
	ManagedMountPoint, ManagedPlaceholder,
	access::{AccessRequest, fs::RwxPermission},
};
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct PrompterRequest {
	/// Randomly generated ID for this instance of the turnstile-sandbox.
	/// This will be the same value for all requests coming from this
	/// sandbox.
	pub sandbox_id: u64,
	/// The original command line used to launch this sandbox.
	pub sandbox_cmd: Vec<String>,
	/// The PID of the process that caused this access request.
	pub request_pid: u32,
	/// The /proc/.../comm of the process that caused this access request
	/// (with space trimmed).
	pub request_comm: String,
	/// The access request data.
	pub access_request: AccessRequest,
	/// An opened fd number (passed to the prompter) for the /proc/<pid>
	/// directory of the requesting process, or null if opening this fd
	/// failed.
	pub pidfd: Option<u32>,
	/// For filesystem operations, this is the request represented in a
	/// "r/w/x <file>" format.
	pub rwx_permissions: Vec<RwxPermission>,
	/// Path to the config file
	pub config_path: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Action {
	Continue(#[serde(deserialize_with = "deserialize_true")] bool),
	/// The positive errno
	SendError(i32),
}

/// Deserialize a `bool` that is required to be `true`, used so that e.g.
/// `{"continue": true}` is accepted but `{"continue": false}` is
/// rejected.
fn deserialize_true<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let value = bool::deserialize(deserializer)?;
	if !value {
		return Err(serde::de::Error::custom("must be true"));
	}
	Ok(value)
}

#[derive(Deserialize, Debug, Clone)]
pub struct MountsToAdd {
	/// The path to mount on.
	pub mount_point: String,
	#[serde(flatten)]
	pub mount: ManagedMountPoint,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PlaceholderToAdd {
	/// The path to create the placeholder at.
	pub path: String,
	/// If set, turnstile-sandbox stats the host path at `path` (no
	/// symlink following) and mirrors its type/metadata as the
	/// placeholder.  See `build_resolve_placeholder`.  Mutually exclusive
	/// with any `placeholder` fields.
	#[serde(default)]
	pub match_host: bool,
	#[serde(flatten)]
	pub placeholder: Option<ManagedPlaceholder>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PrompterResponse {
	/// What to do with this syscall, after applying the changes requested
	/// by the prompter in the following fields.
	pub action: Action,
	/// Signal that the config has been modified by the prompter and
	/// should be reloaded and changes applied before continuing.
	#[serde(default)]
	pub reload_config: bool,
	/// Mounts to add to this sandbox.  This does not persist it to the
	/// config, and changes made this way will be reverted when the config
	/// is reloaded.
	#[serde(default)]
	pub add_mounts: Vec<MountsToAdd>,
	/// Placeholders to add to this sandbox.  This does not persist it to
	/// the config, and changes made this way will be reverted when the
	/// config is reloaded.
	#[serde(default)]
	pub add_placeholders: Vec<PlaceholderToAdd>,
	/// If set, turnstile-sandbox will automatically create placeholders
	/// for symlinks that are necessary to resolve the requested path (see
	/// create_symlinks_for_user_path).  It is also possible for the
	/// prompter to manually implement this by adding placeholders.
	#[serde(default)]
	pub auto_add_symlinks: bool,
	/// If set, after applying the added mounts turnstile-sandbox widens
	/// every existing descendant mount so it is at least as permissive as
	/// the newly granted access (see `inherit_attrs_to_descendants`).
	/// For example, granting rwx on a parent will lift a more restrictive
	/// ro child mount to rwx as well.  Does not persist to the config.
	#[serde(default)]
	pub auto_widen_descendant_permissions: bool,
}

/// Launch the prompter `program`, send it `request` as a single JSON
/// object on stdin, and parse the JSON object it writes to stdout as a
/// [`PrompterResponse`].
///
/// When `pass_fd` is `Some`, the file descriptor is made inheritable
/// (its `CLOEXEC` flag is cleared in the forked child before exec) so
/// that the prompter can use it.  Its raw fd number is what the caller
/// should have placed in [`PrompterRequest::pidfd`].
///
/// All traffic to and from the prompter is logged at `debug` level.
pub fn run_prompter(
	program: &str,
	request: &PrompterRequest,
	pass_fd: Option<BorrowedFd>,
) -> io::Result<PrompterResponse> {
	let request_json = serde_json::to_string(request)
		.map_err(|e| io::Error::other(format!("serializing prompter request: {e}")))?;
	debug!("prompter <- request to {:?}: {}", program, request_json);

	let mut cmd = Command::new(program);
	cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
	if let Some(fd) = pass_fd {
		let raw = fd.as_raw_fd();
		// Clear CLOEXEC in the child so the descriptor survives exec and
		// the prompter can open paths relative to it.
		unsafe {
			cmd.pre_exec(move || {
				let flags = libc::fcntl(raw, libc::F_GETFD);
				if flags < 0 {
					return Err(io::Error::last_os_error());
				}
				if libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
					return Err(io::Error::last_os_error());
				}
				Ok(())
			});
		}
	}

	let mut child = cmd.spawn()?;
	{
		// Take and drop stdin after writing so the prompter sees EOF.
		let mut stdin = child.stdin.take().expect("stdin was piped");
		stdin.write_all(request_json.as_bytes())?;
		stdin.write_all(b"\n")?;
	}
	let output = child.wait_with_output()?;
	if !output.status.success() {
		return Err(io::Error::other(format!(
			"prompter {program:?} exited with {}",
			output.status
		)));
	}
	let stdout = String::from_utf8_lossy(&output.stdout);
	debug!("prompter -> response from {:?}: {}", program, stdout.trim());
	let response: PrompterResponse = serde_json::from_str(stdout.trim())
		.map_err(|e| io::Error::other(format!("parsing prompter response: {e}")))?;
	debug!("prompter -> parsed response: {:?}", response);
	Ok(response)
}
