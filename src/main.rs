// ratelimit-sim: replay a log of timestamped requests through a token-bucket
// limiter and report which requests would have been allowed or throttled.
//
// Input lines look like:
//   <unix-timestamp> [key]
//
// The timestamp is a float number of seconds since the epoch (fractional
// seconds are fine). The key is optional and lets you simulate per-client
// limits (e.g. one bucket per IP) instead of a single global bucket.

use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::ExitCode;

const DEFAULT_KEY: &str = "_default";

#[derive(Clone, Copy)]
enum Algorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
}

impl Algorithm {
    fn parse(s: &str) -> Option<Algorithm> {
        match s {
            "token-bucket" => Some(Algorithm::TokenBucket),
            "sliding-window" => Some(Algorithm::SlidingWindow),
            "fixed-window" => Some(Algorithm::FixedWindow),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Format {
    Text,
    Json,
}

impl Format {
    fn parse(s: &str) -> Option<Format> {
        match s {
            "text" => Some(Format::Text),
            "json" => Some(Format::Json),
            _ => None,
        }
    }
}

struct Config {
    rate: f64,
    burst: f64,
    algorithm: Algorithm,
    format: Format,
    files: Vec<String>,
    quiet: bool,
    per_key: bool,
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

// Derives a (window length, request limit) pair from --rate/--burst so all
// three algorithms answer the same question: "at most `burst` requests per
// `burst / rate` seconds". That keeps the CLI flags meaningful regardless of
// which algorithm is selected instead of needing separate flags per algorithm.
fn window_params(rate: f64, burst: f64) -> (f64, usize) {
    let limit = burst.round().max(1.0) as usize;
    (burst / rate, limit)
}

// Sliding window log: keeps every allowed request's timestamp and counts how
// many fall within the trailing window. Exact, but memory grows with the
// number of allowed requests in a window.
struct SlidingWindowLog {
    window: f64,
    limit: usize,
    timestamps: VecDeque<f64>,
}

impl SlidingWindowLog {
    fn new(rate: f64, burst: f64) -> Self {
        let (window, limit) = window_params(rate, burst);
        SlidingWindowLog { window, limit, timestamps: VecDeque::new() }
    }

    fn allow(&mut self, now: f64) -> bool {
        while let Some(&oldest) = self.timestamps.front() {
            if now - oldest > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        if self.timestamps.len() < self.limit {
            self.timestamps.push_back(now);
            true
        } else {
            false
        }
    }
}

// Fixed window counter: time is sliced into windows of fixed length aligned
// to the epoch, and each window has its own independent request count. Cheap,
// but allows up to 2x the limit across a window boundary.
struct FixedWindowCounter {
    window: f64,
    limit: usize,
    current_index: Option<i64>,
    count: usize,
}

impl FixedWindowCounter {
    fn new(rate: f64, burst: f64) -> Self {
        let (window, limit) = window_params(rate, burst);
        FixedWindowCounter { window, limit, current_index: None, count: 0 }
    }

    fn allow(&mut self, now: f64) -> bool {
        let index = (now / self.window).floor() as i64;
        if self.current_index != Some(index) {
            self.current_index = Some(index);
            self.count = 0;
        }

        if self.count < self.limit {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

enum Limiter {
    TokenBucket(TokenBucket),
    SlidingWindow(SlidingWindowLog),
    FixedWindow(FixedWindowCounter),
}

impl Limiter {
    fn new(algorithm: Algorithm, rate: f64, burst: f64) -> Self {
        match algorithm {
            Algorithm::TokenBucket => Limiter::TokenBucket(TokenBucket::new(burst, rate)),
            Algorithm::SlidingWindow => Limiter::SlidingWindow(SlidingWindowLog::new(rate, burst)),
            Algorithm::FixedWindow => Limiter::FixedWindow(FixedWindowCounter::new(rate, burst)),
        }
    }

    fn allow(&mut self, now: f64) -> bool {
        match self {
            Limiter::TokenBucket(l) => l.allow(now),
            Limiter::SlidingWindow(l) => l.allow(now),
            Limiter::FixedWindow(l) => l.allow(now),
        }
    }
}

#[derive(Default)]
struct KeyStats {
    total: u64,
    allowed: u64,
    denied: u64,
}

#[derive(Default)]
struct Stats {
    malformed: u64,
    per_key: HashMap<String, KeyStats>,
}

impl Stats {
    fn totals(&self) -> (u64, u64, u64) {
        self.per_key.values().fold((0, 0, 0), |(total, allowed, denied), k| {
            (total + k.total, allowed + k.allowed, denied + k.denied)
        })
    }
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut rate = None;
    let mut burst = None;
    let mut algorithm = Algorithm::TokenBucket;
    let mut format = Format::Text;
    let mut files = Vec::new();
    let mut quiet = false;
    let mut per_key = false;

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
            "--algorithm" => {
                i += 1;
                let v = args.get(i).ok_or("--algorithm needs a value")?;
                algorithm = Algorithm::parse(v).ok_or_else(|| {
                    format!(
                        "bad --algorithm value: {} (expected token-bucket, sliding-window, or fixed-window)",
                        v
                    )
                })?;
            }
            "--format" => {
                i += 1;
                let v = args.get(i).ok_or("--format needs a value")?;
                format = Format::parse(v)
                    .ok_or_else(|| format!("bad --format value: {} (expected text or json)", v))?;
            }
            "--quiet" => quiet = true,
            "--per-key" => per_key = true,
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

    Ok(Config { rate, burst, algorithm, format, files, quiet, per_key })
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
     \x20 --rate N        tokens (requests) added per second\n\
     \x20 --burst N       bucket capacity (max requests in a burst)\n\
     \x20 --algorithm A   token-bucket (default), sliding-window, or fixed-window\n\
     \x20 --format F      text (default) or json for per-line output\n\
     \x20 --quiet         suppress per-line output, print only the summary\n\
     \x20 --per-key       print a summary line per key, not just the total\n"
        .to_string()
}

// Parses a line into (timestamp, key). Lines with no key use DEFAULT_KEY so
// all requests share one global bucket.
fn parse_line(line: &str) -> Option<(f64, &str)> {
    let mut parts = line.split_whitespace();
    let ts_str = parts.next()?;
    let ts = ts_str.parse::<f64>().ok()?;
    if !ts.is_finite() {
        return None;
    }
    let key = parts.next().unwrap_or(DEFAULT_KEY);
    Some((ts, key))
}

fn process<R: BufRead>(
    reader: R,
    config: &Config,
    buckets: &mut HashMap<String, Limiter>,
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
            .or_insert_with(|| Limiter::new(config.algorithm, config.rate, config.burst));

        let allowed = bucket.allow(ts);
        let key_stats = stats.per_key.entry(key.to_string()).or_default();
        key_stats.total += 1;
        if allowed {
            key_stats.allowed += 1;
        } else {
            key_stats.denied += 1;
        }

        if !config.quiet {
            match config.format {
                Format::Text => {
                    let verdict = if allowed { "ALLOW" } else { "DENY" };
                    writeln!(out, "{} {} {}", verdict, ts_display(ts), key)?;
                }
                Format::Json => {
                    let verdict = if allowed { "allow" } else { "deny" };
                    writeln!(
                        out,
                        "{{\"verdict\":\"{}\",\"timestamp\":{},\"key\":\"{}\"}}",
                        verdict,
                        ts,
                        json_escape(key)
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn ts_display(ts: f64) -> String {
    format!("{:.3}", ts)
}

// Escapes a string for use inside a JSON string literal. Keys come straight
// from input lines, so they may contain quotes, backslashes, or control
// characters that would otherwise produce invalid JSON.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = parse_args(&args)?;

    let mut buckets: HashMap<String, Limiter> = HashMap::new();
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

    let (total, allowed, denied) = stats.totals();
    eprintln!(
        "total={} allowed={} denied={} malformed={} keys={}",
        total,
        allowed,
        denied,
        stats.malformed,
        buckets.len()
    );

    if config.per_key {
        let mut keys: Vec<&String> = stats.per_key.keys().collect();
        keys.sort();
        for key in keys {
            let k = &stats.per_key[key];
            eprintln!("  {}: total={} allowed={} denied={}", key, k.total, k.allowed, k.denied);
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_full() {
        let mut b = TokenBucket::new(5.0, 1.0);
        assert_eq!(b.tokens, 5.0);
        assert!(b.allow(0.0));
        assert_eq!(b.tokens, 4.0);
    }

    #[test]
    fn denies_once_drained() {
        let mut b = TokenBucket::new(1.0, 1.0);
        assert!(b.allow(0.0));
        // No time has passed, so there's nothing to refill with.
        assert!(!b.allow(0.0));
    }

    #[test]
    fn refills_at_configured_rate() {
        let mut b = TokenBucket::new(2.0, 1.0);
        assert!(b.allow(0.0));
        assert!(b.allow(0.0));
        assert!(!b.allow(0.0));

        // One second later, one token's worth of refill should be available.
        assert!(b.allow(1.0));
        assert!(!b.allow(1.0));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let mut b = TokenBucket::new(2.0, 1.0);
        assert!(b.allow(0.0));
        // A huge gap should still only refill up to capacity, not beyond it.
        assert!(b.allow(1000.0));
        assert_eq!(b.tokens, 1.0);
        assert!(b.allow(1000.0));
        assert!(!b.allow(1000.0));
    }

    #[test]
    fn out_of_order_timestamps_do_not_refill() {
        let mut b = TokenBucket::new(1.0, 10.0);
        assert!(b.allow(10.0));
        // A timestamp earlier than the last one seen must not grant tokens
        // for negative elapsed time.
        assert!(!b.allow(5.0));
    }

    #[test]
    fn fractional_tokens_accumulate_across_requests() {
        let mut b = TokenBucket::new(1.0, 0.5);
        assert!(b.allow(0.0));
        assert!(!b.allow(1.0));
        // Two more seconds brings us to exactly one full token.
        assert!(b.allow(3.0));
    }

    #[test]
    fn sliding_window_denies_once_limit_hit_in_window() {
        // rate=1, burst=2 -> window of 2s, limit of 2 requests.
        let mut w = SlidingWindowLog::new(1.0, 2.0);
        assert!(w.allow(0.0));
        assert!(w.allow(1.0));
        assert!(!w.allow(1.5));
    }

    #[test]
    fn sliding_window_expires_old_requests() {
        let mut w = SlidingWindowLog::new(1.0, 2.0);
        assert!(w.allow(0.0));
        assert!(w.allow(1.0));
        // 2.1s later the request at t=0 has fallen out of the 2s window.
        assert!(w.allow(2.1));
    }

    #[test]
    fn fixed_window_resets_at_window_boundary() {
        // rate=1, burst=2 -> window of 2s, limit of 2 requests.
        let mut f = FixedWindowCounter::new(1.0, 2.0);
        assert!(f.allow(0.0));
        assert!(f.allow(1.0));
        assert!(!f.allow(1.5));
        // t=2.0 starts a new window (index 1), so the count resets.
        assert!(f.allow(2.0));
    }

    #[test]
    fn algorithm_parse_rejects_unknown_values() {
        assert!(Algorithm::parse("token-bucket").is_some());
        assert!(Algorithm::parse("sliding-window").is_some());
        assert!(Algorithm::parse("fixed-window").is_some());
        assert!(Algorithm::parse("leaky-bucket").is_none());
    }

    #[test]
    fn format_parse_rejects_unknown_values() {
        assert!(Format::parse("text").is_some());
        assert!(Format::parse("json").is_some());
        assert!(Format::parse("yaml").is_none());
    }

    #[test]
    fn parse_line_rejects_non_finite_timestamps() {
        assert!(parse_line("inf").is_none());
        assert!(parse_line("nan").is_none());
        assert!(parse_line("-infinity 10.0.0.1").is_none());
    }

    #[test]
    fn per_key_stats_tracked_independently() {
        let config = Config {
            rate: 1.0,
            burst: 1.0,
            algorithm: Algorithm::TokenBucket,
            format: Format::Text,
            files: Vec::new(),
            quiet: true,
            per_key: true,
        };
        let mut buckets = HashMap::new();
        let mut stats = Stats::default();
        let mut out = Vec::new();

        let input = "0.0 a\n0.0 a\n0.0 b\n";
        process(io::Cursor::new(input.as_bytes()), &config, &mut buckets, &mut stats, &mut out).unwrap();

        let a = &stats.per_key["a"];
        assert_eq!((a.total, a.allowed, a.denied), (2, 1, 1));
        let b = &stats.per_key["b"];
        assert_eq!((b.total, b.allowed, b.denied), (1, 1, 0));
        assert_eq!(stats.totals(), (3, 2, 1));
    }

    #[test]
    fn malformed_lines_do_not_count_toward_any_key() {
        let config = Config {
            rate: 1.0,
            burst: 1.0,
            algorithm: Algorithm::TokenBucket,
            format: Format::Text,
            files: Vec::new(),
            quiet: true,
            per_key: false,
        };
        let mut buckets = HashMap::new();
        let mut stats = Stats::default();
        let mut out = Vec::new();

        let input = "not-a-timestamp\n0.0 a\n";
        process(io::Cursor::new(input.as_bytes()), &config, &mut buckets, &mut stats, &mut out).unwrap();

        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.totals(), (1, 1, 0));
    }

    #[test]
    fn json_escape_handles_quotes_and_control_chars() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\u{1}b"), "a\\u0001b");
    }
}
