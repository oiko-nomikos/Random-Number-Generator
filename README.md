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

## Architecture & How It Works

### 1. SystemClock
High-resolution timing using `std::chrono::system_clock` (nanoseconds).

### 2. SHA256 (in CRYPTO namespace)
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
