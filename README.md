# Oikos Entropy Generator

**A from-first-principles, self-contained randomness extractor using CPU timing jitter.**

This is an educational C++ (C++23) project that demonstrates how to harvest entropy from **tiny execution-time variations** in a simple loop — without any OS-provided randomness APIs, hardware RNGs, or external cryptographic libraries.

The core innovation is a custom **timing-jitter bit extractor** combined with a **thread-safe entropy pool** and SHA-256 whitening — all built from scratch.

**This is NOT cryptographically secure randomness - unless of course you trust it!**
It is a teaching tool to understand entropy collection mechanics.

## Features

- Pure software-based entropy source: measures nanosecond-level jitter in a trivial countdown loop
- Real-time debiasing via running average comparison
- Fixed-size circular bit buffer (512 bits); once filled, every subsequent iteration re-hashes the buffer contents through SHA-256, producing an overlapping stream of 256-bit whitened outputs
- On-demand, thread-safe entropy pool (`BinaryEntropyPool`) with a low-watermark auto-refill policy
- Standalone SHA-256 implementation (no OpenSSL/libcrypto dependency)
- Configurable output: request any number of bits via `get()`, or arbitrarily large amounts via `getLarge()` (internally chunked)
- Locked/secure-erased memory for the bit pool (`VirtualLock`/`mlock`, zero-on-erase)
- Nondeterministic behavior: different runs produce different output due to real-world timing variance
- Command-line demo that writes raw entropy to `entropy.bin` plus a metadata/throughput report to `entropy_info.txt`
- Single-file implementation (RNG.cpp) for easy study

## The Heart of the Project: Custom Randomness Generation

The **primary motivation** for building this entire demo was to create a **completely self-contained randomness system** — no OS APIs, no hardware RNGs, no external dependencies — just pure software extracting entropy from the real world.

### RandomNumberGenerator – The Bit Harvester

This class is the core invention: it turns tiny variations in **CPU execution timing** into usable random bits.

**How it works (step by step):**

1. Runs a fixed number of iterations (`totalIterations = 1024`).
2. In each iteration:
   - Measures the exact nanosecond duration of a trivial countdown loop (`volatile int x = 10; while (x > 0) x--;`), using a `volatile` counter so the compiler can't optimize the loop away.
   - Compares the duration to a running global average (`globalSum / count`) computed across all iterations so far.
   - If shorter than the running average → bit = 0
     If longer than or equal to the running average → bit = 1
   (This simple comparison acts as a basic debiasing mechanism.)
3. Writes the bit into a fixed-size circular buffer of 512 slots (`localBits`), advancing a `tail` index each iteration.
4. Once the buffer has been written to for the first time all the way around (after the 511th iteration), it's marked `filled`, and **every iteration from then on** — not just once per 512 bits — packs the current buffer into a 64-byte block, feeds it into SHA-256, and appends the 256-bit binary digest to the output.
5. After all 1024 iterations, `run()` returns one long bit string. Because whitened output is produced on almost every iteration once the buffer fills (roughly `totalIterations - localBufferSize` times), a single `run()` call yields on the order of hundreds of thousands of output bits, even though the underlying entropy is only ever collected from 1024 timing samples.

**Why this is clever / educational:**
- Demonstrates real entropy extraction from **non-obvious sources** (CPU jitter caused by scheduling, cache, interrupts, etc.).
- Shows basic debiasing (average comparison) and whitening (hash function).
- Illustrates how a small, fixed-size internal state can still be turned into a much larger output stream by repeatedly re-hashing it as it's updated — while making clear that this **does not create new entropy**, it just reshapes/stretches what little was harvested.
- Fully transparent — you can see exactly where randomness comes from.

**Limitations (important!):**
- Entropy quality is **very low** on modern hardware (timings are often too stable or predictable).
- Easily influenced by system load, CPU frequency scaling, virtualization, etc.
- Because the buffer is re-hashed every iteration rather than consumed and reset, most of the underlying jitter bits are reused across many consecutive output blocks — output volume is not the same thing as entropy volume.
- Not suitable for cryptographic key material — included only for learning.

### BinaryEntropyPool – The On-Demand Bit Reservoir

This class manages the bits produced by `RandomNumberGenerator` in a reusable, thread-safe way.

**How it works:**

1. Maintains a growing string `bitPool` of '0'/'1' characters, reserved upfront to `POOL_RESERVED` (200% of one `run()` worth of output) and memory-locked (`VirtualLock` on Windows, `mlock` elsewhere) so it can't be paged to disk.
2. When someone calls `get(bitsNeeded)`:
   - If the pool has dropped below `LOW_WATERMARK` (half of `POOL_CAPACITY`), it refills by calling `rng.run()` and appending the result.
   - Keeps refilling in a loop until the pool has at least `bitsNeeded` bits available.
   - Extracts exactly `bitsNeeded` bits from the front, then securely erases those bits from the pool (zeroes the memory before erasing) so used bits are never left lingering.
3. `getLarge(bitsNeeded)` transparently services requests larger than one pool's capacity by looping `get()` in `POOL_CAPACITY`-sized chunks.
4. `available()` reports the current pool size, and `drain()` securely clears the whole pool and resets its reserved capacity.
5. Everything is protected by a mutex (`poolMutex`) for thread safety, even though the current demo is single-threaded.

**Why it's useful:**
- Lazy evaluation: only generates bits when actually needed (e.g., for salt or IV).
- Acts as a buffer so you don't waste entropy by regenerating on every call.
- Simple interface: `bep.get(128)` → 128 random bits as a string; `bep.getLarge(1'000'000)` for bulk requests.

**Combined effect:**
Together, these classes let the entire program generate salts and IVs **without ever calling the OS for randomness** — making the demo 100% self-contained and a nice teaching tool for "how randomness can be harvested from nothing".

## Architecture

### 1. SystemClock
High-resolution timing using `std::chrono::high_resolution_clock`, exposed as raw nanoseconds since epoch.

### 2. SHA256 (in `CRYPTO` namespace, to avoid conflicts with OpenSSL headers)
Independent streaming implementation following NIST FIPS 180-4 — used solely for whitening the raw jitter bits. Exposes `hashBytes`, `hashString`, `hashBinary`, and `hashHex` convenience wrappers, plus incremental `update()`/`digest()` for streaming use.

### 3. RandomNumberGenerator — The Core Entropy Harvester

**Entropy source**
Measures execution time of a tiny loop:

```cpp
volatile int x = 10;
auto start = systemClock.getNanoseconds();
while (x > 0) {
    int tmp = x;
    x = tmp - 1;
}
long long duration = systemClock.getNanoseconds() - start;
```

### 4. BinaryEntropyPool — The Reservoir

Wraps `RandomNumberGenerator` behind a locked, auto-refilling, securely-erased bit pool (see above), sized in constants:

- `POOL_CAPACITY` = 512 × 256 = 131,072 bits — one `rng.run()` worth of output
- `POOL_RESERVED` = `POOL_CAPACITY` × 2 — upfront reservation
- `LOW_WATERMARK` = 512 × 128 — refill trigger, halfway through capacity

## Command-Line Demo

`main()` prompts for a number of bits, pulls that many bits out of the pool via `bep.get(amount)`, and writes:

- **`entropy.bin`** — the raw '0'/'1' bit string (suitable as input to statistical test suites such as NIST's STS)
- **`entropy_info.txt`** — a small report with bits generated, elapsed time (ms/s), and throughput in bits/sec and Mbps

👤 Author

oiko-nomikos

Built from first principles, for understanding — not shortcuts.
