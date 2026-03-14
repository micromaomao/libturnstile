use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;

use clap::Parser;
use libturnstile::TurnstileTracer;

/// Trace file operations of a program using libturnstile
#[derive(Parser)]
#[command(name = "fstrace")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Write output to a file instead of stderr
	#[arg(short = 'o', value_name = "FILE")]
	output: Option<String>,

	/// Add timestamps to each output line
	#[arg(short = 't', long = "timestamps")]
	timestamps: bool,

	/// Program to trace and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	env_logger::init();

	let cli = Cli::parse();

	let mut output: Box<dyn Write> = match &cli.output {
		Some(path) => Box::new(std::fs::File::create(path)?),
		None => Box::new(std::io::stderr()),
	};

	let tracer = Arc::new(TurnstileTracer::new()?);

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	// spawn blocks until execve succeeds, but execve is intercepted by
	// seccomp-unotify, so we must be processing notifications on the main
	// thread via yield_request before spawn can return.
	let tracer_for_thread = Arc::clone(&tracer);
	let spawn_handle = std::thread::spawn(
		move || -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
			let child = tracer_for_thread.run_command(&mut cmd)?;
			Ok(child)
		},
	);

	loop {
		match tracer.yield_request() {
			Ok(Some((access_request, mut ctx))) => {
				if cli.timestamps {
					let now = SystemTime::now()
						.duration_since(SystemTime::UNIX_EPOCH)
						.unwrap_or_default();
					write!(output, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
				}
				let pid = ctx.sreq().pid;
				let comm = std::fs::read(format!("/proc/{}/comm", pid))
					.map(|r| String::from_utf8_lossy(&r).trim().to_string())
					.unwrap_or_else(|_| String::from("???"));
				for op in &access_request {
					writeln!(output, "{}[{}] {}", comm, pid, op)?;
				}
				ctx.send_continue()?;
			}
			Ok(None) => {
				// Syscall was auto-continued by the tracer (e.g. not a
				// file operation we care about), nothing to report.
			}
			Err(e) => {
				eprintln!("fstrace: error: {}", e);
				break;
			}
		}
	}

	let child_result = spawn_handle.join().expect("spawn thread panicked");
	match child_result {
		Ok(mut child) => {
			let status = child.wait()?;
			eprintln!("fstrace: child process exited with status {}", status);
			std::process::exit(status.code().unwrap_or(1));
		}
		Err(e) => {
			eprintln!("fstrace: error spawning child: {}", e);
			std::process::exit(1);
		}
	}
}
