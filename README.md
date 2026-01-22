# Oikos Entropy Generator

**A from-first-principles, self-contained randomness extractor using CPU timing jitter.**

This is an educational C++ (C++23) project that demonstrates how to harvest entropy from **tiny execution-time variations** in a simple loop — without any OS-provided randomness APIs, hardware RNGs, or external cryptographic libraries.

The core innovation is a custom **timing-jitter bit extractor** combined with a **thread-safe entropy pool** and SHA-256 whitening — all built from scratch.

**This is NOT cryptographically secure randomness - unless of course you trust it!**  
It is a teaching tool to understand entropy collection mechanics.

## Features

- Pure software-based entropy source: measures nanosecond-level jitter in a trivial countdown loop  
- Real-time debiasing via running average comparison  
- Sliding-window collection (512 bits) → SHA-256 whitening → 256-bit uniform chunks  
- On-demand, thread-safe entropy pool (`BinaryEntropyPool`)  
- Standalone SHA-256 implementation (no OpenSSL/libcrypto dependency)  
- Configurable output: request any number of bits  
- Nondeterministic behavior: different runs produce different output due to real-world timing variance  
- Single-file implementation (RNG.cpp) for easy study

## The Heart of the Project: Custom Randomness Generation

The **primary motivation** for building this entire demo was to create a **completely self-contained randomness system** — no OS APIs, no hardware RNGs, no external dependencies — just pure software extracting entropy from the real world.

### RandomNumberGenerator – The Bit Harvester

This class is the core invention: it turns tiny variations in **CPU execution timing** into usable random bits.

**How it works (step by step):**

1. Runs a fixed number of iterations (default: 1000).
2. In each iteration:
   - Measures the exact nanosecond duration of a trivial countdown loop (`while (x > 0) x--;` with x=10).
   - Compares the duration to a running global average.
   - If shorter than average → bit = 0  
     If longer than average → bit = 1  
   (This simple comparison acts as a basic debiasing mechanism.)
3. Stores bits in a sliding window deque of size 512.
4. When the window is full:
   - Packs the 512 bits into a 64-byte block.
   - Feeds it into SHA-256.
   - Converts the 256-bit hash output into a string of 256 '0'/'1' characters (whitening step).
   - Appends this to the result.
5. After all iterations, returns a long bit string (typically hundreds of thousands of bits).

**Why this is clever / educational:**
- Demonstrates real entropy extraction from **non-obvious sources** (CPU jitter caused by scheduling, cache, interrupts, etc.).
- Shows basic debiasing (average comparison) and whitening (hash function).
- Fully transparent — you can see exactly where randomness comes from.

**Limitations (important!):**
- Entropy quality is **very low** on modern hardware (timings are often too stable or predictable).
- Easily influenced by system load, CPU frequency scaling, virtualization, etc.
- Not suitable for cryptographic key material — included only for learning.

### BinaryEntropyPool – The On-Demand Bit Reservoir

This class manages the bits produced by `RandomNumberGenerator` in a reusable, thread-safe way.

**How it works:**

1. Maintains a growing string `bitPool` of '0'/'1' characters.
2. When someone requests `get(bitsNeeded)`:
   - If not enough bits in pool → calls `rng.run()` to generate more and appends them.
   - Extracts exactly `bitsNeeded` bits from the front.
   - Removes the used bits (keeps the rest for next time).
3. Protected by a mutex for thread safety (though the demo is single-threaded).

**Why it's useful:**
- Lazy evaluation: only generates bits when actually needed (e.g., for salt or IV).
- Acts as a buffer so you don't waste entropy by regenerating on every call.
- Simple interface: `bep.get(128)` → 128 random bits as string.

**Combined effect:**
Together, these classes let the entire program generate salts and IVs **without ever calling the OS for randomness** — making the demo 100% self-contained and a nice teaching tool for "how randomness can be harvested from nothing".

## Architecture

### 1. SystemClock
High-resolution timing using `std::chrono::system_clock` (nanoseconds).

### 2. SHA256 (in CRYPTO namespace so as to avoid conflicts with OpenSSL .h files)
Independent streaming implementation following NIST FIPS 180-4 — used solely for whitening the raw jitter bits.

### 3. RandomNumberGenerator — The Core Entropy Harvester

**Entropy source**  
Measures execution time of a tiny loop:

```cpp
int x = 10;
auto start = systemClock.getNanoseconds();
while (x > 0) x--;
auto end = systemClock.getNanoseconds();
long long duration = end - start;
👤 Author

oiko-nomikos

Built from first principles, for understanding — not shortcuts.
