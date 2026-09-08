# ratelimit-sim

A command line tool for testing a rate limit before you commit to one.

The usual way to pick a rate limit is to guess a number, deploy it, and watch
how many real users get 429s. This tool lets you replay a log of past
request timestamps through a token-bucket simulation instead, so you can see
how many requests a candidate `--rate`/`--burst` pair would have rejected
before it's live anywhere.

Input is plain text, one request per line:

```
<unix-timestamp> [key]
```

The timestamp is seconds since the epoch (fractional seconds are fine). The
optional key groups requests into separate buckets, so you can simulate a
per-IP or per-API-key limit instead of one global one. Lines with no key
share a single default bucket.

## Usage

Read from a file:

```
$ ratelimit-sim --rate 5 --burst 10 requests.log
```

Read from stdin, so you can pull timestamps straight out of an existing
access log:

```
$ awk '{print $1}' access.log | ratelimit-sim --rate 50 --burst 100
```

Per-key limiting, e.g. one bucket per client IP:

```
$ cat requests.log
1690000000.0 10.0.0.1
1690000000.2 10.0.0.1
1690000000.4 10.0.0.1
1690000000.6 10.0.0.2

$ ratelimit-sim --rate 2 --burst 2 requests.log
ALLOW 1690000000.000 10.0.0.1
ALLOW 1690000000.200 10.0.0.1
DENY 1690000000.400 10.0.0.1
ALLOW 1690000000.600 10.0.0.2
total=4 allowed=3 denied=1 malformed=0 keys=2
```

Mix stdin with files by using `-` as a filename:

```
$ tail -f live.log | ratelimit-sim --rate 5 --burst 10 - backlog.log
```

Use `--quiet` to suppress the per-line verdicts and only see the summary
line, which is written to stderr so it doesn't interfere with piping the
per-line output elsewhere:

```
$ ratelimit-sim --rate 5 --burst 10 --quiet requests.log
total=4 allowed=3 denied=1 malformed=0 keys=2
```

## Algorithms

`--algorithm` selects which limiter simulates the requests. All three read
the same `--rate`/`--burst` pair; only how they use it differs.

- `token-bucket` (default): each key starts with `--burst` tokens, gains
  `--rate` tokens per second, caps at `--burst`, and spends one token per
  allowed request. This is the same algorithm used by most production rate
  limiters (nginx's `limit_req`, AWS API Gateway, etc.).
- `sliding-window`: allows at most `--burst` requests in any trailing
  `--burst / --rate` seconds, counted exactly from the timestamps of
  previously allowed requests. More precise than a fixed window but costs
  more memory per key.
- `fixed-window`: like `sliding-window`, but the window is a fixed
  `--burst / --rate` second slice aligned to the epoch instead of trailing
  the current request. Cheaper, but a burst that straddles a window
  boundary can let through close to twice `--burst` requests.

```
$ ratelimit-sim --rate 1 --burst 2 --algorithm sliding-window requests.log
```

## Building

Requires only the Rust standard library.

```
$ cargo build --release
```

## Status

Early skeleton. See the issue tracker for what's missing.
