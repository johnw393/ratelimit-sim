// ratelimit-sim: replay a log of timestamped requests through a token-bucket
// limiter and report which requests would have been allowed or throttled.
//
// Input lines look like:
//   <unix-timestamp> [key]
//
// The timestamp is a float number of seconds since the epoch (fractional
// seconds are fine). The key is optional and lets you simulate per-client
// limits (e.g. one bucket per IP) instead of a single global bucket.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::ExitCode;

const DEFAULT_KEY: &str = "_default";

struct Config {
    rate: f64,
    burst: f64,
    files: Vec<String>,
    quiet: bool,
}

// Classic token bucket: tokens refill continuously at `rate` per second, up
// to `capacity`. Each request costs one token. `last` is None until the
// first request, so the bucket starts full rather than refilling from an
// arbitrary point in time.
struct TokenBucket {
    capacity: f64,
    rate: f64,
    tokens: f64,
    last: Option<f64>,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        TokenBucket {
            capacity,
            rate,
            tokens: capacity,
            last: None,
        }
    }

    fn allow(&mut self, now: f64) -> bool {
        if let Some(last) = self.last {
            let elapsed = now - last;
            if elapsed > 0.0 {
                self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            }
        }
        self.last = Some(now);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Stats {
    total: u64,
    allowed: u64,
    denied: u64,
    malformed: u64,
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut rate = None;
    let mut burst = None;
    let mut files = Vec::new();
    let mut quiet = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rate" => {
                i += 1;
                let v = args.get(i).ok_or("--rate needs a value")?;
                rate = Some(v.parse::<f64>().map_err(|_| format!("bad --rate value: {}", v))?);
            }
            "--burst" => {
                i += 1;
                let v = args.get(i).ok_or("--burst needs a value")?;
                burst = Some(v.parse::<f64>().map_err(|_| format!("bad --burst value: {}", v))?);
            }
            "--quiet" => quiet = true,
            "-h" | "--help" => return Err(usage()),
            other => files.push(other.to_string()),
        }
        i += 1;
    }

    let rate = rate.ok_or_else(|| format!("--rate is required\n\n{}", usage()))?;
    let burst = burst.ok_or_else(|| format!("--burst is required\n\n{}", usage()))?;

    if rate <= 0.0 {
        return Err("--rate must be greater than 0".to_string());
    }
    if burst <= 0.0 {
        return Err("--burst must be greater than 0".to_string());
    }

    Ok(Config { rate, burst, files, quiet })
}

fn usage() -> String {
    "usage: ratelimit-sim --rate N --burst N [FILE...]\n\
     \n\
     Reads whitespace-separated \"timestamp [key]\" lines, one request per\n\
     line, and simulates a token-bucket rate limiter against them.\n\
     \n\
     With no FILE arguments, or when a FILE is \"-\", reads from stdin.\n\
     \n\
     options:\n\
     \x20 --rate N    tokens (requests) added per second\n\
     \x20 --burst N   bucket capacity (max requests in a burst)\n\
     \x20 --quiet     suppress per-line output, print only the summary\n"
        .to_string()
}

// Parses a line into (timestamp, key). Lines with no key use DEFAULT_KEY so
// all requests share one global bucket.
fn parse_line(line: &str) -> Option<(f64, &str)> {
    let mut parts = line.split_whitespace();
    let ts_str = parts.next()?;
    let ts = ts_str.parse::<f64>().ok()?;
    let key = parts.next().unwrap_or(DEFAULT_KEY);
    Some((ts, key))
}

fn process<R: BufRead>(
    reader: R,
    config: &Config,
    buckets: &mut HashMap<String, TokenBucket>,
    stats: &mut Stats,
    out: &mut impl Write,
) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (ts, key) = match parse_line(trimmed) {
            Some(v) => v,
            None => {
                stats.malformed += 1;
                eprintln!("ratelimit-sim: skipping malformed line: {}", trimmed);
                continue;
            }
        };

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(config.burst, config.rate));

        let allowed = bucket.allow(ts);
        stats.total += 1;
        if allowed {
            stats.allowed += 1;
        } else {
            stats.denied += 1;
        }

        if !config.quiet {
            let verdict = if allowed { "ALLOW" } else { "DENY" };
            writeln!(out, "{} {} {}", verdict, ts_display(ts), key)?;
        }
    }
    Ok(())
}

fn ts_display(ts: f64) -> String {
    format!("{:.3}", ts)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = parse_args(&args)?;

    let mut buckets: HashMap<String, TokenBucket> = HashMap::new();
    let mut stats = Stats::default();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if config.files.is_empty() {
        let stdin = io::stdin();
        process(stdin.lock(), &config, &mut buckets, &mut stats, &mut out)
            .map_err(|e| e.to_string())?;
    } else {
        for name in &config.files {
            if name == "-" {
                let stdin = io::stdin();
                process(stdin.lock(), &config, &mut buckets, &mut stats, &mut out)
                    .map_err(|e| e.to_string())?;
            } else {
                let file = File::open(name).map_err(|e| format!("{}: {}", name, e))?;
                process(BufReader::new(file), &config, &mut buckets, &mut stats, &mut out)
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    eprintln!(
        "total={} allowed={} denied={} malformed={} keys={}",
        stats.total,
        stats.allowed,
        stats.denied,
        stats.malformed,
        buckets.len()
    );

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}
