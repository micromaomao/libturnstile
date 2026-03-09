use std::io::Write;
use std::process::Command;
use std::time::SystemTime;

use clap::Parser;
use libturnstile::{Operation, TurnstileTracer};
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
	#[arg(required = true, allow_hyphen_values = true)]
	command: Vec<String>,
}

fn write_operation(
	output: &mut dyn Write,
	op: &Operation,
	timestamps: bool,
) -> std::io::Result<()> {
	if timestamps {
		let now = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap_or_default();
		write!(output, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
	}
	writeln!(output, "{:?}", op)
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

	let mut tracer = TurnstileTracer::new()?;

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	let mut child = tracer.run_command(&mut cmd)?;
	info!("Started child process with pid {}", child.id());

	loop {
		match tracer.yield_request() {
			Ok(Some((access_request, mut ctx))) => {
				for op in &access_request {
					write_operation(&mut output, op, cli.timestamps)?;
				}
				ctx.send_continue()?;
			}
			Ok(None) => {
				// Syscall was auto-continued by the tracer (e.g. not a
				// file operation we care about), nothing to report.
			}
			Err(e) => {
				if child.try_wait()?.is_some() {
					break;
				}
				eprintln!("fstrace: error: {}", e);
			}
		}
	}

	let status = child.wait()?;
	std::process::exit(status.code().unwrap_or(1));
}
