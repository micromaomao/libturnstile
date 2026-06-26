use libturnstile::{
	ManagedMountPoint, ManagedPlaceholder,
	access::{AccessRequest, fs::RwxPermission},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
struct PrompterRequest {
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
enum Action {
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
struct MountsToAdd {
	/// The path to mount on.
	pub mount_point: String,
	#[serde(flatten)]
	pub mount: ManagedMountPoint,
}

#[derive(Deserialize, Debug, Clone)]
struct PlaceholderToAdd {
	/// The path to create the placeholder at.
	pub path: String,
	#[serde(flatten)]
	pub placeholder: ManagedPlaceholder,
}

#[derive(Deserialize, Debug, Clone)]
struct PrompterResponse {
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
	/// for symlinks that are necessary to resolve the requested path.  It
	/// is also possible for the prompter to manually implement this by
	/// adding placeholders.
	#[serde(default)]
	pub auto_add_symlinks: bool,
}
