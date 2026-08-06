# Oikos Entropy Generator — v0.1.0

**A from-first-principles, self-contained randomness extractor using CPU timing jitter, with a built-in statistical test harness.**

This is a completed, feature-complete v0.1.0 release. From this point forward, any functional change to the entropy pipeline, the RNG core, or the statistical tooling bumps the version number — v0.1.0 is a fixed, known snapshot of this codebase.

## What's new in v0.1.0

- Warm-up period (`warmupBytes` / `warmupIterations`) added ahead of production hashing, so `globalAvg` has converged before any bit that ends up in an output digest is extracted
- `EntropyAnalyzer` — full byte-frequency distribution report (mean, std deviation, min/max frequency vs. ideal uniform)
- `TestNIST` — a from-scratch implementation of all 15 tests in the NIST SP 800-22 Rev. 1a Statistical Test Suite, with a live console dashboard
- Locked, auto-refilling, securely-erased `BinaryEntropyPool`
- Standalone SHA-256 (NIST FIPS 180-4), no OpenSSL/libcrypto dependency
- Single-file implementation, C++23, no OS randomness APIs called anywhere in the pipeline

## What this release demonstrably does

- Produces output that passes the full NIST STS battery across the tests you've run it against — no detected bias, periodicity, or short-range correlation in the sample sizes tested
- Produces a byte distribution statistically consistent with uniform, per `EntropyAnalyzer`
- Runs entirely self-contained: no `/dev/urandom`, no `BCryptGenRandom`, no hardware RNG instruction — every bit traces back to measured CPU timing jitter, hashed through a hand-written SHA-256
- Is now stable enough as a pipeline (warm-up added, underflow bugs fixed, header/body encoding issues resolved) to treat as a real v0.1.0 baseline rather than a moving target

## What "passes NIST STS" does and doesn't mean

This is worth being precise about, because it's the crux of what this project is and isn't.

NIST STS checks whether a bit sequence is **statistically distinguishable from random** — that is, whether there's detectable bias, periodicity, or structure in the *output*. It says nothing about whether that output was **unpredictable to an attacker** before it was generated. Those are different properties, and only the second one is what cryptographic security depends on.

Concretely: SHA-256 whitening makes almost any input look statistically uniform in its output. A deterministic counter, hashed through SHA-256, would also pass every test in this suite. So passing STS confirms the *whitening stage* is working as designed — it is not evidence about how much real, attacker-unpredictable entropy went in on the other side.

## Status: not production-grade cryptography, and here's specifically why

This project has not been shown to have sufficient min-entropy or attacker-unpredictability to be relied on for real key material, wallets, transaction signing, or anything securing actual funds or secrets. Specifically:

- **No min-entropy estimate.** There's no measurement anywhere in the pipeline of how many bits of real unpredictability each timing sample actually contributes before it's folded into the ring buffer. "Passes NIST STS" and "has N bits of min-entropy per sample" are different claims — this project only supports the first one.
- **CPU timing jitter is a well-studied weak entropy source.** On modern hardware it's shaped by CPU frequency scaling, branch prediction warm-up, thermal throttling, and OS scheduler behavior — several of which are at least partially observable or influenceable by another process on the same machine.
- **The SHA-256 implementation is hand-written from spec, unaudited, and not constant-time.** Even if functionally correct, it has none of the side-channel hardening or track record of libsodium, OpenSSL, or BoringSSL's implementations — including against timing leaks in the hashing step itself.
- **No independent third-party audit, no formal security proof, no head-to-head validation against a known-good CSPRNG.**

This is standard, close-to-universal security guidance, not a hedge specific to this project: don't roll your own crypto for anything that needs to actually hold up against a real attacker. That guidance applies here regardless of how solid the rest of the engineering is.

## If you want a genuine path to production use

The realistic next step isn't "prove the jitter source is good enough" — it's stop relying on it alone. Mix your jitter-derived bits in as a *supplement* to an OS-provided CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows) rather than as the sole entropy source, e.g. XOR or HKDF-combine them before use. That way even if the jitter source turns out to contribute near-zero real entropy, security still rests on the OS CSPRNG underneath it — and you keep the self-contained jitter harvesting as a legitimate additional input rather than a single point of failure.

## Architecture

### 1. `SystemClock`
High-resolution timing via `std::chrono::high_resolution_clock`, exposed as raw nanoseconds since epoch.

### 2. `CRYPTO::SHA256`
Independent streaming implementation following NIST FIPS 180-4, used to whiten raw jitter bits. Exposes `hashBytes`, `hashString`, `hashBinary`, `hashHex`, plus incremental `update()`/`digest()` for streaming use.

### 3. `RandomNumberGenerator` — the entropy harvester

**Entropy source** — nanosecond duration of a trivial busy-wait loop:

```cpp
volatile int x = 10;
auto start = systemClock.getNanoseconds();
while (x > 0) {
    int tmp = x;
    x = tmp - 1;
}
long long duration = systemClock.getNanoseconds() - start;
```

**Pipeline, per `run()`:**

1. **Warm-up** (`warmupIterations` = 10,000): samples run through the same threshold/ring-buffer mechanics as production, letting `globalAvg` converge. The 512-slot ring buffer (`localBits`) fills well before warm-up ends, but nothing is hashed yet.
2. **Production** (512 further iterations): each timing sample is thresholded against the now-converged `globalAvg` (`bit = duration < globalAvg ? 0 : 1`), written into the ring buffer, and the full 512-bit window is packed into 64 bytes and hashed through SHA-256. Every production iteration emits one 256-bit digest.
3. One `run()` call therefore emits exactly 512 × 256 = 131,072 bits from 10,512 total timing samples.

### 4. `BinaryEntropyPool` — the reservoir

Wraps `RandomNumberGenerator` behind a locked, auto-refilling, securely-erased bit pool:

- `POOL_CAPACITY` = 512 × 256 = 131,072 bits — one `run()` worth of output
- `POOL_RESERVED` = `POOL_CAPACITY` × 2 — upfront reservation, memory-locked via `VirtualLock`/`mlock`
- `LOW_WATERMARK` = 512 × 128 — refill trigger, halfway through capacity
- Bits are zeroed and erased from the pool immediately after being handed out, so nothing is reused
- Thread-safe via `poolMutex`

### 5. `EntropyAnalyzer`
Feeds generated bits in as bytes and reports the full 256-value frequency distribution, plus mean, standard deviation, and min/max frequency against the ideal uniform expectation.

### 6. `TestNIST`
Full from-scratch implementation of the 15 tests in NIST SP 800-22 Rev. 1a: Frequency (Monobit), Block Frequency, Runs, Longest Run of Ones, Binary Matrix Rank, DFT (Spectral), Non-Overlapping Template Matching, Overlapping Template Matching, Maurer's Universal, Linear Complexity, Serial, Approximate Entropy, Cumulative Sums, Random Excursions, and Random Excursions Variant. Live console dashboard tracks progress test-by-test.

## Command-Line Demo

`main()` prompts for a number of bits, pulls that many from the pool via `bep.request(amount)`, then:

- Writes **`entropy.bin`** — the raw '0'/'1' bit string
- Writes **`entropy_info.txt`** — bits generated, elapsed time (ms/s), throughput (bits/sec, Mbps)
- Runs `EntropyAnalyzer` and prints the full byte distribution table
- Runs the full NIST STS battery via `TestNIST` and prints pass/fail, statistic, and p-value for all 15 tests

## Versioning

This README describes **v0.1.0** exactly as it stands. Any change to the RNG core, the entropy pool, the analyzer, or the NIST test implementations from this point forward requires a version bump — v0.1.0 should be treated as a fixed, citable snapshot, not a rolling label.

👤 Author

oiko-nomikos

Built from first principles, for understanding — not shortcuts.
