//! Measures one cold and repeated warm `collect_pid` calls without printing collected values.
//!
//! Usage: `cargo run --release -p procline --example bench -- [--iterations N] [--max-ancestors N] [--env] [--digest] [--no-signature] [--all-names] <pid>...`

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use procline::{CollectOptions, EnvPolicy, Redaction, collect_pid};
    use std::hint::black_box;
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    fn usage() {
        eprintln!(
            "usage: bench [--iterations N] [--max-ancestors N] [--env] [--digest] [--no-signature] [--all-names] <pid>..."
        );
    }

    let mut iterations = 50;
    let mut max_ancestors = 64;
    let mut env = EnvPolicy::None;
    let mut digest = false;
    let mut signature = true;
    let mut all_names = false;
    let mut pids = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iterations" | "--max-ancestors" => {
                let Some(value) = args.next() else {
                    usage();
                    return ExitCode::from(2);
                };
                let Ok(value) = value.parse::<usize>() else {
                    usage();
                    return ExitCode::from(2);
                };
                if arg == "--iterations" {
                    if value == 0 {
                        usage();
                        return ExitCode::from(2);
                    }
                    iterations = value;
                } else {
                    max_ancestors = value;
                }
            }
            "--env" => env = EnvPolicy::All,
            "--digest" => digest = true,
            "--no-signature" => signature = false,
            "--all-names" => all_names = true,
            "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            _ => match arg.parse::<i32>() {
                Ok(pid) if pid > 0 => pids.push(pid),
                _ => {
                    usage();
                    return ExitCode::from(2);
                }
            },
        }
    }
    if pids.is_empty() {
        usage();
        return ExitCode::from(2);
    }

    let options = CollectOptions {
        env,
        redaction: Redaction::default(),
        icon: false,
        digest,
        signature,
        all_names,
        max_ancestors,
    };
    fn timed_collect(
        pid: i32,
        options: &CollectOptions,
    ) -> Result<(Duration, usize, Option<procline::Truncated>), procline::CollectError> {
        let start = Instant::now();
        let chain = collect_pid(pid, options)?;
        let elapsed = start.elapsed();
        let count = chain.processes().len();
        let truncated = chain.truncated;
        std::hint::black_box(chain);
        Ok((elapsed, count, truncated))
    }

    for pid in pids {
        let (cold, count, truncated) = match timed_collect(pid, &options) {
            Ok(sample) => sample,
            Err(err) => {
                eprintln!("bench: pid {pid}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let mut warm = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            match timed_collect(pid, &options) {
                Ok((duration, _, _)) => warm.push(duration),
                Err(err) => {
                    eprintln!("bench: pid {pid}: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        black_box(&warm);
        warm.sort_unstable();
        let median =
            (warm[(iterations - 1) / 2].as_secs_f64() + warm[iterations / 2].as_secs_f64()) * 500.0;
        let p95 = warm[(iterations * 95).div_ceil(100) - 1].as_secs_f64() * 1000.0;
        println!(
            "pid={pid} processes={count} truncated={truncated:?} cold_ms={:.3} warm_min_ms={:.3} warm_median_ms={median:.3} warm_p95_ms={p95:.3} iterations={iterations}",
            cold.as_secs_f64() * 1000.0,
            warm[0].as_secs_f64() * 1000.0,
        );
    }
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("bench: collecting is implemented for macOS only");
    std::process::ExitCode::FAILURE
}
