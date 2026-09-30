// ratelimit-sim: replay a log of timestamped requests through a token-bucket
// limiter and report which requests would have been allowed or throttled.
//
// Input lines look like either:
//   <unix-timestamp> [key]
// or an Apache/nginx common/combined log format line, e.g.:
//   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326
//
// The timestamp is a float number of seconds since the epoch (fractional
// seconds are fine). The key is optional and lets you simulate per-client
// limits (e.g. one bucket per IP) instead of a single global bucket; for
// access log lines the leading host is used as the key.

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
    from: Option<f64>,
    to: Option<f64>,
}

impl Config {
    fn has_time_filter(&self) -> bool {
        self.from.is_some() || self.to.is_some()
    }

    // --from is inclusive and --to is exclusive, so adjacent ranges such as
    // "--to 100" and "--from 100" split a log without overlap or gaps.
    fn in_range(&self, ts: f64) -> bool {
        self.from.map_or(true, |f| ts >= f) && self.to.map_or(true, |t| ts < t)
    }
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
    filtered: u64,
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
    let mut from = None;
    let mut to = None;

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
            "--from" => {
                i += 1;
                let v = args.get(i).ok_or("--from needs a value")?;
                from = Some(parse_bound(v).ok_or_else(|| format!("bad --from value: {}", v))?);
            }
            "--to" => {
                i += 1;
                let v = args.get(i).ok_or("--to needs a value")?;
                to = Some(parse_bound(v).ok_or_else(|| format!("bad --to value: {}", v))?);
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

    if let (Some(f), Some(t)) = (from, to) {
        if f >= t {
            return Err("--from must be less than --to".to_string());
        }
    }

    Ok(Config { rate, burst, algorithm, format, files, quiet, per_key, from, to })
}

fn parse_bound(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().filter(|v| v.is_finite())
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
     \x20 --from T        ignore requests before unix time T (inclusive bound)\n\
     \x20 --to T          ignore requests at or after unix time T\n\
     \x20 --quiet         suppress per-line output, print only the summary\n\
     \x20 --per-key       print a summary line per key, not just the total\n"
        .to_string()
}

// Parses a line into (timestamp, key). Tries the plain "timestamp [key]"
// format first, then falls back to Apache/nginx common/combined log format
// so access logs can be fed in directly without a pre-extraction pass.
fn parse_line(line: &str) -> Option<(f64, &str)> {
    parse_raw_line(line).or_else(|| parse_access_log_line(line))
}

// Lines with no key use DEFAULT_KEY so all requests share one global bucket.
fn parse_raw_line(line: &str) -> Option<(f64, &str)> {
    let mut parts = line.split_whitespace();
    let ts_str = parts.next()?;
    let ts = ts_str.parse::<f64>().ok()?;
    if !ts.is_finite() {
        return None;
    }
    let key = parts.next().unwrap_or(DEFAULT_KEY);
    Some((ts, key))
}

// Parses a Common/Combined Log Format line, e.g.:
//   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326
// The leading host token becomes the key, so per-IP bucketing falls out for
// free without needing a separate --key-field flag.
fn parse_access_log_line(line: &str) -> Option<(f64, &str)> {
    let host = line.split_whitespace().next()?;
    let start = line.find('[')?;
    let end = start + line[start..].find(']')?;
    let ts = parse_clf_timestamp(&line[start + 1..end])?;
    Some((ts, host))
}

const CLF_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn month_index(s: &str) -> Option<i64> {
    CLF_MONTHS.iter().position(|&m| m == s).map(|i| i as i64 + 1)
}

// Days since 1970-01-01 for a given proleptic Gregorian calendar date.
// https://howardhinnant.github.io/date_algorithms.html#days_from_civil
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// Parses the bracketed timestamp of a CLF/combined log line, e.g.
// "10/Oct/2000:13:55:36 -0700", into seconds since the epoch (UTC).
fn parse_clf_timestamp(s: &str) -> Option<f64> {
    let mut top = s.splitn(2, ' ');
    let date_time = top.next()?;
    let tz = top.next()?;

    let mut dt = date_time.splitn(2, ':');
    let date_str = dt.next()?;
    let time_str = dt.next()?;

    let mut date_fields = date_str.splitn(3, '/');
    let day: i64 = date_fields.next()?.parse().ok()?;
    let month = month_index(date_fields.next()?)?;
    let year: i64 = date_fields.next()?.parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }

    let mut time_fields = time_str.splitn(3, ':');
    let hour: i64 = time_fields.next()?.parse().ok()?;
    let min: i64 = time_fields.next()?.parse().ok()?;
    let sec: f64 = time_fields.next()?.parse().ok()?;
    if !(0..24).contains(&hour) || !(0..60).contains(&min) || !(0.0..60.0).contains(&sec) {
        return None;
    }

    if tz.len() != 5 {
        return None;
    }
    let tz_sign = match tz.as_bytes()[0] {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let tz_hh: i64 = tz[1..3].parse().ok()?;
    let tz_mm: i64 = tz[3..5].parse().ok()?;
    let tz_offset = tz_sign * (tz_hh * 3600 + tz_mm * 60);

    let days = days_from_civil(year, month, day);
    let local_secs = (days * 86400 + hour * 3600 + min * 60) as f64 + sec;
    Some(local_secs - tz_offset as f64)
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

        // Filtered lines never reach a limiter, so they don't drain tokens or
        // create buckets for keys that only appear outside the range.
        if !config.in_range(ts) {
            stats.filtered += 1;
            continue;
        }

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
    let filtered = if config.has_time_filter() {
        format!(" filtered={}", stats.filtered)
    } else {
        String::new()
    };
    eprintln!(
        "total={} allowed={} denied={} malformed={} keys={}{}",
        total,
        allowed,
        denied,
        stats.malformed,
        buckets.len(),
        filtered
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
    fn days_from_civil_matches_known_reference_points() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        // 30 years including 7 leap years (72, 76, 80, 84, 88, 92, 96).
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    #[test]
    fn parse_clf_timestamp_handles_utc() {
        let ts = parse_clf_timestamp("01/Jan/2000:00:00:00 +0000").unwrap();
        assert_eq!(ts, 946684800.0);
    }

    #[test]
    fn parse_clf_timestamp_applies_offset() {
        // -0500 means local time is 5 hours behind UTC, so UTC is later.
        let ts = parse_clf_timestamp("01/Jan/2000:00:00:00 -0500").unwrap();
        assert_eq!(ts, 946684800.0 + 5.0 * 3600.0);
    }

    #[test]
    fn parse_clf_timestamp_rejects_bad_fields() {
        assert!(parse_clf_timestamp("32/Oct/2000:13:55:36 -0700").is_none());
        assert!(parse_clf_timestamp("10/Foo/2000:13:55:36 -0700").is_none());
        assert!(parse_clf_timestamp("10/Oct/2000:25:55:36 -0700").is_none());
        assert!(parse_clf_timestamp("10/Oct/2000:13:55:36 700").is_none());
    }

    #[test]
    fn parse_access_log_line_extracts_host_and_timestamp() {
        let line = r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326"#;
        let (ts, key) = parse_access_log_line(line).unwrap();
        assert_eq!(key, "127.0.0.1");
        assert_eq!(ts, parse_clf_timestamp("10/Oct/2000:13:55:36 -0700").unwrap());
    }

    #[test]
    fn parse_line_falls_back_to_access_log_format() {
        let line = r#"10.0.0.5 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 10"#;
        let (ts, key) = parse_line(line).unwrap();
        assert_eq!(ts, 946684800.0);
        assert_eq!(key, "10.0.0.5");
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
            from: None,
            to: None,
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
            from: None,
            to: None,
        };
        let mut buckets = HashMap::new();
        let mut stats = Stats::default();
        let mut out = Vec::new();

        let input = "not-a-timestamp\n0.0 a\n";
        process(io::Cursor::new(input.as_bytes()), &config, &mut buckets, &mut stats, &mut out).unwrap();

        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.totals(), (1, 1, 0));
    }

    fn filter_config(from: Option<f64>, to: Option<f64>) -> Config {
        Config {
            rate: 1.0,
            burst: 1.0,
            algorithm: Algorithm::TokenBucket,
            format: Format::Text,
            files: Vec::new(),
            quiet: true,
            per_key: false,
            from,
            to,
        }
    }

    #[test]
    fn in_range_is_inclusive_of_from_and_exclusive_of_to() {
        let c = filter_config(Some(10.0), Some(20.0));
        assert!(!c.in_range(9.9));
        assert!(c.in_range(10.0));
        assert!(c.in_range(19.9));
        assert!(!c.in_range(20.0));
        assert!(filter_config(None, None).in_range(-5.0));
    }

    #[test]
    fn filtered_lines_do_not_touch_limiter_state() {
        let config = filter_config(Some(10.0), Some(20.0));
        let mut buckets = HashMap::new();
        let mut stats = Stats::default();
        let mut out = Vec::new();

        // The two requests at t=0 would drain the bucket if they were
        // counted; the one at t=30 is past --to and only creates key "c".
        let input = "0.0 a\n0.0 a\n10.0 a\n30.0 c\n";
        process(io::Cursor::new(input.as_bytes()), &config, &mut buckets, &mut stats, &mut out).unwrap();

        assert_eq!(stats.filtered, 3);
        assert_eq!(stats.totals(), (1, 1, 0));
        assert!(!buckets.contains_key("c"));
    }

    #[test]
    fn parse_args_validates_time_bounds() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let base = ["--rate", "1", "--burst", "1"];

        let ok = parse_args(&args(&[&base[..], &["--from", "5", "--to", "10"]].concat())).unwrap();
        assert_eq!((ok.from, ok.to), (Some(5.0), Some(10.0)));

        assert!(parse_args(&args(&[&base[..], &["--from", "10", "--to", "5"]].concat())).is_err());
        assert!(parse_args(&args(&[&base[..], &["--from", "abc"]].concat())).is_err());
        assert!(parse_args(&args(&[&base[..], &["--to", "inf"]].concat())).is_err());
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
