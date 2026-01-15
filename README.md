Oikos Entropy Generator (C++)

A from-scratch entropy and random bit generator written in modern C++ (C++23), using high-resolution timing jitter and SHA-256 whitening to produce configurable amounts of binary entropy.

This project is intentionally self-contained, with no external crypto or RNG libraries, and is designed as an educational and experimental entropy pipeline rather than a drop-in replacement for OS CSPRNGs.

✨ Features

⏱️ Timing-based entropy source

Uses nanosecond-resolution timing jitter as the raw entropy signal

🔐 SHA-256 whitening

Custom SHA-256 implementation (no OpenSSL / libsodium)

Converts noisy entropy into uniformly distributed output

🧠 Sliding window entropy extraction

512-bit local buffer hashed into 256-bit outputs

🧵 Thread-safe entropy pool

std::mutex-protected entropy pool

Supports concurrent access

📏 User-configurable entropy size

Generate any number of bits at runtime

🧪 Deterministic structure, nondeterministic output

Same code path, different entropy every run

⚠️ Disclaimer

This project is for educational and experimental purposes.
It is not audited, not certified, and not recommended for production cryptographic use where security guarantees are required. 

If you need cryptographically secure randomness in production, use your OS-provided CSPRNG (e.g. /dev/urandom, CryptGenRandom, getrandom()).

🧩 Architecture Overview
1. SystemClock

Provides high-resolution timestamps (seconds → nanoseconds) used for timing jitter.

2. SHA256

A complete, standalone implementation of SHA-256:

Supports streaming updates

Outputs hex or 256-bit binary strings

Used exclusively for entropy whitening

3. RandomNumberGenerator

Measures execution-time jitter

Converts timing variance into raw bits

Maintains a 512-bit sliding window

Hashes each window into a 256-bit binary output

4. BinaryEntropyPool

Accumulates entropy from the RNG

Stores entropy as a binary string

Thread-safe via std::mutex

Supplies exactly the number of bits requested

🚀 Usage
Build (MSYS2 / MinGW example)
g++ -std=c++23 -Wall -Wextra -pthread RNG.cpp - seen. exe


(Adjust paths/compiler as needed.)

Run
Welcome to Oikos Entropy Generator!

Please enter the amount of entropy you wish to Generate!
1000

Entropy: 011010100101...


The output is a binary string of exactly the requested length.

📦 Example Code
BinaryEntropyPool bep;

size_t bits = 1024;
std::string entropy = bep.get(bits);

// entropy.size() == 1024

📈 Performance Notes

Entropy generation speed depends on CPU timing resolution

SHA-256 whitening dominates runtime cost

Larger entropy requests scale linearly

🛠️ Possible Extensions

Hex / Base64 output modes

Entropy estimation metrics

Persistent entropy pool (disk-backed)

UUID / mnemonic / key generation

Multithreaded entropy harvesting

Statistical randomness testing (NIST STS)

📜 License

MIT License
Copyright © 2026 oiko-nomikos

See the LICENSE file or header comments for full license text.

👤 Author

oiko-nomikos

Built from first principles, for understanding — not shortcuts.
