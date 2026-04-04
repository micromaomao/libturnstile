use std::{
	env,
	ffi::{CStr, CString},
	process::Command,
	sync::{Arc, OnceLock},
	thread::{self, sleep},
	time::Duration,
};

use clap::Parser;
use libturnstile::{BindMountSandbox, MountAttributes};
use log::error;

use crate::common::{ProcPidFd, handle_child_result};

mod common;

/// Trace file operations of a program using libturnstile
#[derive(Parser)]
#[command(name = "turnstile-sandbox")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Block the sandboxed process from creating more unprivileged user
	/// namespaces.
	#[arg(long = "block-nested-userns")]
	block_more_userns: bool,

	/// Program to run and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

#[derive(Debug)]
struct Context {
	sandbox: BindMountSandbox,
	pidfd: OnceLock<ProcPidFd>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	common::init_logger();

	let cli = Cli::parse();

	let context = Arc::new(Context {
		sandbox: BindMountSandbox::new(cli.block_more_userns)?,
		pidfd: OnceLock::new(),
	});

	let sandbox = &context.sandbox;
	let mount = |host_path: &CStr,
	             sandbox_path: &CStr,
	             attrs: MountAttributes|
	 -> Result<(), libturnstile::BindMountSandboxError> {
		let mut mount = sandbox.mount_host_into_sandbox(host_path, sandbox_path);
		mount.attributes(attrs);
		mount.mount()
	};

	mount(c"/usr", c"/usr", MountAttributes::rx())?;
	mount(c"/bin", c"/bin", MountAttributes::rx())?;
	mount(c"/lib", c"/lib", MountAttributes::rx())?;
	if std::fs::exists("/lib64").unwrap_or(false) {
		mount(c"/lib64", c"/lib64", MountAttributes::rx())?;
	}
	mount(c"/etc", c"/etc", MountAttributes::rx())?;
	mount(c"/dev", c"/dev", MountAttributes::rwx())?;
	mount(c"/proc", c"/proc", MountAttributes::rwx())?;
	let pwd = std::env::current_dir()?
		.into_os_string()
		.into_encoded_bytes();
	let pwd = CString::new(pwd).unwrap();
	mount(&pwd, &pwd, MountAttributes::ro())?;
	let sandbox_tmp = env::temp_dir().join("sandbox-tmp");
	std::fs::create_dir_all(&sandbox_tmp)?;
	let sandbox_tmp = CString::new(sandbox_tmp.into_os_string().into_encoded_bytes()).unwrap();
	mount(&sandbox_tmp, c"/tmp", MountAttributes::rwx())?;

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	let context_for_thread = context.clone();
	thread::spawn(move || {
		let context = context_for_thread;

		eprintln!("In 10 seconds, will allow write access on {:?}", pwd);
		sleep(Duration::from_secs(10));

		eprintln!("Now allowing write access on {:?}", pwd);
		if let Err(e) = context.sandbox.set_mount_attr_within_ns(
			&pwd,
			MountAttributes::rw(),
			MountAttributes::ro(),
		) {
			error!("Failed to set mount attributes: {e}");
		}

		eprintln!("Taking away write access in 10 seconds");
		sleep(Duration::from_secs(10));

		eprintln!("Now taking away write access on {:?}", pwd);
		if let Err(e) = context.sandbox.set_mount_attr_within_ns(
			&pwd,
			MountAttributes::ro(),
			MountAttributes::rw(),
		) {
			error!("Failed to set mount attributes: {e}");
		}
	});

	let child_result = sandbox.run_command(&mut cmd);
	handle_child_result(child_result, &context.pidfd)
}
