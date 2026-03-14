use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use clap::Parser;
use libturnstile::TurnstileTracer;
use log::info;

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
		Some(path) => Box::new(
			std::fs::File::create(path)
				.map_err(|e| format!("failed to open output file '{}': {}", path, e))?,
		),
		None => Box::new(std::io::stderr()),
	};

	let tracer_arc = Arc::new(TurnstileTracer::new()?);

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	// We need to have started monitoring and responding to events before
	// the execve even happens, so we need to do this in a separate
	// thread.
	let tracer_arc_for_thread = Arc::clone(&tracer_arc);
	let jh = thread::spawn(move || {
		match tracer_arc_for_thread.run_command(&mut cmd) {
			Ok(mut child) => {
				info!("Started child process with pid {}", child.id());
				let wait_res = child.wait().unwrap();
				eprintln!("fstrace: child process exited with status {}", wait_res);
				std::process::exit(wait_res.code().unwrap_or(1));
			}
			Err(e) => {
				eprintln!("fstrace: error spawning child: {}", e);
				std::process::exit(1);
			}
		};
	});

	loop {
		match tracer_arc.yield_request() {
			Ok(Some((access_request, mut ctx))) => {
				if cli.timestamps {
					let now = std::time::SystemTime::now();
					let datetime: chrono::DateTime<chrono::Local> = now.into();
					write!(output, "[{}] ", datetime.format("%Y-%m-%d %H:%M:%S%.3f"))?;
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
				jh.join().expect("process wait thread panicked");
			}
		}
	}
}
