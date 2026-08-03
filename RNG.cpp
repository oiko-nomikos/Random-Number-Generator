
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//
// =================================================================================
// MIT License
//
// Copyright (c) 2026 oiko-nomikos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// =================================================================================
//
// IMPORTANT SECURITY & LEGAL NOTICES
//
// This program contains independent, from-scratch re-implementations of the
// following cryptographic algorithms, based solely on their public specifications:
//
//   • SHA-256                            — NIST FIPS 180-4
//
// No third-party copyrighted code is included for these primitives.
// They are educational/reference implementations only.
//
// All other parts of this program — including:
//
//   • Random Number Generator
//   • Binary Entropy Pool
//
//   — are original work by oiko-nomikos.
//
// CRITICAL WARNING:
// ---------------------------------------------------------------------------------
// THIS IS NOT PRODUCTION-GRADE CRYPTOGRAPHY.
//
// Discretion  must be given - use at own risk!
//
// If you find a bug or weakness — please report it responsibly.
//
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

//----------------------------------------------------------------------------------
// Core C++ Input/Output and Strings
//----------------------------------------------------------------------------------

#include <fstream>  // std::ifstream, std::ofstream — file input/output
#include <iostream> // std::cout, std::cin, std::cerr — console input/output
#include <string>   // std::string — dynamic string class
#include <iomanip>  // std::setw, std::setfill, std::setprecision — formatted output
#include <limits>   // std::numeric_limits — type limits and stream buffer utilities

//----------------------------------------------------------------------------------
// Containers and Data Structures
//----------------------------------------------------------------------------------

#include <vector> // std::vector — dynamic contiguous array
#include <deque>  // std::deque — double-ended queue with fast front/back insertion

//----------------------------------------------------------------------------------
// Timing
//----------------------------------------------------------------------------------

#include <chrono> // std::chrono — clocks, durations, and time measurements

//----------------------------------------------------------------------------------
// Thread Synchronisation
//----------------------------------------------------------------------------------

#include <mutex> // std::mutex, std::lock_guard, std::unique_lock — thread synchronisation

//----------------------------------------------------------------------------------
// Math specific headers
//----------------------------------------------------------------------------------

#include <cmath> // std::sqrt, std::round, std::sin, std::cos, etc.

//----------------------------------------------------------------------------------
// Windows API
//----------------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN // Exclude rarely used Windows headers to reduce compile time
#include <windows.h>        // Windows API (VirtualLock, VirtualUnlock, Sleep, etc.)

//----------------------------------------------------------------------------------
// Global Type Aliases
//----------------------------------------------------------------------------------

using Bytes = std::vector<uint8_t>; // Convenience alias for a byte buffer

//----------------------------------------------------------------------------------
// Marcos: Version
//----------------------------------------------------------------------------------

#define CSPRNG_VERSION "v0.1.0"

//----------------------------------------------------------------------------------
// Windows Specific Utilities
//----------------------------------------------------------------------------------

void maximizeConsoleWindow() {
#ifdef _WIN32
    HWND consoleWindow = GetConsoleWindow();

    if (consoleWindow != nullptr) {
        ShowWindow(consoleWindow, SW_MAXIMIZE);
    }
#endif
}

inline void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SystemClock {
  public:
    inline long long getNanoseconds() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Functions {
  public:
    // All integral types (int, long, long long, uint64_t, etc.)
    template <typename T> static std::enable_if_t<std::is_integral_v<T>, std::string> format(T value) { return addCommas(std::to_string(value)); }

    // Default: 2 decimal places
    static std::string format(double value) { return formatFixed(value, 2); }

    // Custom precision
    static std::string formatFixed(double value, int precision) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(precision) << value;
        return addCommas(ss.str());
    }

    // Prints in-place using \r — call repeatedly to animate
    static void printProgressBar(int current, int total, int width = 50) {
        std::cout << '\r' << makeProgressBar(current, total, width);
        std::cout.flush();
    }

  private:
    // Inserts thousand separators into a numeric string
    static std::string addCommas(std::string s) {
        size_t dotPos = s.find('.');
        if (dotPos == std::string::npos)
            dotPos = s.size();

        int pos = static_cast<int>(dotPos) - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    static std::string makeProgressBar(int current, int total, int width = 50) {
        if (total <= 0) {
            total = 1;
        }

        double progress = std::clamp(static_cast<double>(current) / static_cast<double>(total), 0.0, 1.0);
        int filled      = static_cast<int>(std::round(progress * width));

        std::ostringstream oss;
        oss << "[";
        for (int i = 0; i < filled; ++i) {
            oss << "#";
        }
        for (int i = filled; i < width; ++i) {
            oss << " ";
        }
        oss << "] " << std::setw(3) << static_cast<int>(progress * 100) << "%";

        return oss.str();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class EntropyAnalyzer {
  public:
    void feedBits(const std::string &bits) {
        for (size_t i = 0; i + 8 <= bits.size(); i += 8) {
            uint8_t byte = 0;
            for (int b = 0; b < 8; b++) {
                byte <<= 1;
                byte |= (bits[i + b] == '1') ? 1 : 0;
            }
            freq[byte]++;
            totalBytes++;
        }
    }

    void print() const {
        if (totalBytes == 0) {
            std::cout << "No data.\n";
            return;
        }

        uint64_t maxFreq = *std::max_element(freq.begin(), freq.end());

        std::cout << "\nBYTE FREQUENCY DISTRIBUTION\n";
        std::cout << "Total bytes:                 " << totalBytes << "\n";
        std::cout << "Expected per byte (uniform): " << std::fixed << std::setprecision(2) << (100.0 / 256.0) << "%\n";
        std::cout << std::string(60, '-') << "\n\n";

        for (int i = 0; i < 256; i++) {
            double pct   = (static_cast<double>(freq[i]) / totalBytes) * 100.0;
            double ofMax = (static_cast<double>(freq[i]) / maxFreq) * 100.0;
            int blocks   = static_cast<int>(ofMax / 10.0);
            if (blocks > 10)
                blocks = 10;

            std::cout << std::dec << std::setw(3) << i << " (0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << i << std::dec << std::setfill(' ') << ")"
                      << " (";
            for (int b = 7; b >= 0; b--)
                std::cout << ((i >> b) & 1);
            std::cout << ")"
                      << " | ";

            for (int b = 0; b < 10; b++)
                std::cout << (b < blocks ? "█" : "·");

            std::cout << "  " << std::fixed << std::setprecision(3) << pct << "%"
                      << "  (" << freq[i] << ")\n";
        }

        double mean     = static_cast<double>(totalBytes) / 256.0;
        double variance = 0.0;
        for (int i = 0; i < 256; i++) {
            double diff = static_cast<double>(freq[i]) - mean;
            variance += diff * diff;
        }
        variance /= 256.0;
        double stddev = std::sqrt(variance);

        uint64_t minFreq = *std::min_element(freq.begin(), freq.end());

        std::cout << "\n" << std::string(60, '-') << "\n";
        std::cout << "Min frequency: " << minFreq << "  (" << std::fixed << std::setprecision(3) << (static_cast<double>(minFreq) / totalBytes * 100.0) << "%)\n";
        std::cout << "Max frequency: " << maxFreq << "  (" << std::fixed << std::setprecision(3) << (static_cast<double>(maxFreq) / totalBytes * 100.0) << "%)\n";
        std::cout << "Std deviation: " << std::fixed << std::setprecision(2) << stddev << " bytes\n";
        std::cout << "Ideal uniform: " << std::fixed << std::setprecision(2) << mean << " bytes per value\n";
    }

  private:
    static constexpr size_t BYTE_RANGE = 256;

    std::array<uint64_t, BYTE_RANGE> freq{};
    uint64_t totalBytes = 0;

    void reset() {
        freq.fill(0);
        totalBytes = 0;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// wrapper around platform-specific "pin memory, prevent swap" calls.
// used anywhere sensitive data (entropy pools, key material) needs to stay
// out of swap/pagefile for the lifetime of the object holding it.
class SecureMemory {
  public:
    static inline bool lock(void *ptr, size_t bytes) {
#ifdef _WIN32
        return VirtualLock(ptr, bytes) != 0;
#else
        return mlock(ptr, bytes) == 0;
#endif
    }

    static inline bool unlock(void *ptr, size_t bytes) {
#ifdef _WIN32
        return VirtualUnlock(ptr, bytes) != 0;
#else
        return munlock(ptr, bytes) == 0;
#endif
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace CRYPTO {
class SHA256 {
  public:
    SHA256() { reset(); }

    // clang format off
    // ------------------------------------------------------------
    // Input: {0x48, 0x65, 0x6C, 0x6C, 0x6F}
    // Output: {0x2C, 0xF2, 0x4D, 0xBA, ...}
    // Useful for: HMAC, key derivation, checksums, binary protocols
    // ------------------------------------------------------------
    inline Bytes hashBytes(const Bytes &data) {
        update(data.data(), data.size());
        return digestBytes();
    }

    // ------------------------------------------------------------
    // Input: "hello"
    // Output: {0x2C, 0xF2, 0x4D, 0xBA, ...}
    // Useful when: You need the hash in hex (prefix "0x") for further processing
    // ------------------------------------------------------------
    inline Bytes hashString(const std::string &data) {
        update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
        return digestBytes();
    }

    // ------------------------------------------------------------
    // Input: "hello"
    // Output: "00101100111100100100110110111010..."
    // Useful for: Entropy pools, mnemonic generation, bit manipulation, debugging
    // ------------------------------------------------------------
    inline std::string hashBinary(const std::string &data) {
        update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
        return digestBinary();
    }

    // ------------------------------------------------------------
    // Input: "hello"
    // Output: "1b161e5c1fa7425e73043362938b9824"
    // Useful for: Transaction IDs, fingerprints, certificates, wallet identifiers, logging and display
    // ------------------------------------------------------------
    inline std::string hashHex(const std::string &data) {
        update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
        return digest();
    }

    inline void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }
    // clang format on

    inline std::string digest() {
        uint64_t totalBits = bitlen + bufferLen * 8;

        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            while (bufferLen < 64)
                buffer[bufferLen++] = 0x00;
            transform(buffer);
            bufferLen = 0;
        }

        while (bufferLen < 56)
            buffer[bufferLen++] = 0x00;

        for (int i = 7; i >= 0; --i)
            buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;

        transform(buffer);

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i)
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];

        reset(); // reset internal state after digest
        return oss.str();
    }

    inline Bytes digestBytes() {
        std::string hex = digest();
        Bytes out;
        out.reserve(32);
        for (size_t i = 0; i < hex.size(); i += 2)
            out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        return out;
    }

    inline std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    inline void reset() {
        h[0]      = 0x6a09e667;
        h[1]      = 0xbb67ae85;
        h[2]      = 0x3c6ef372;
        h[3]      = 0xa54ff53a;
        h[4]      = 0x510e527f;
        h[5]      = 0x9b05688c;
        h[6]      = 0x1f83d9ab;
        h[7]      = 0x5be0cd19;
        bitlen    = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    inline void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a     = h[0];
        uint32_t b     = h[1];
        uint32_t c     = h[2];
        uint32_t d     = h[3];
        uint32_t e     = h[4];
        uint32_t f     = h[5];
        uint32_t g     = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val          = g;
            g              = f;
            f              = e;
            e              = d + temp1;
            d              = c;
            c              = b;
            b              = a;
            a              = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    inline static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    inline static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    inline static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    inline static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    inline static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    inline static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    inline static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    inline static constexpr uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                                              0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                                              0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                                              0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                              0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                                              0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
};
} // namespace CRYPTO

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        // first, reserve enough space for the expected output size to avoid repeated reallocations during string concatenation.
        std::string result;
        result.reserve(expectedBits); // capacity hint only — see note on expectedBits below, actual output can be slightly longer
        // one must always reset the state before each run() to ensure that the ring buffer and running averages are fresh for this invocation.
        resetState();

        for (int i = 0; i < totalIterations; ++i) {
            // apply the most imprtant function - see bellow in private section for more details
            long long duration = countdown();
            // increment the count of samples, add the duration to the running sum, and compute the new running average.
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count; // running average, used as the threshold for this iteration's bit extraction

            // extract 1 bit of raw entropy: was this timing sample above or below the running average?
            // this is the "jitter" bit — noisy, biased, low-quality on its own, which is why it gets pooled and hashed below
            int bit = duration < globalAvg ? 0 : 1;

            // ring buffer write (push newest bit)
            localBits[tail] = bit;
            tail            = (tail + 1) % localBufferSize;

            // assuming 4 values - 0 equals the point at which the series wraps around, marking the end of the local buffer size.
            // pushed  1 | ... | head=0 tail=1
            // pushed  2 | ... | head=0 tail=2
            // pushed  3 | ... | head=0 tail=3
            // pushed  4 | ... | head=0 tail=0   <- wrapped! tail went 3 -> (3+1) % 4 = 0
            // pushed  5 | ... | head=1 tail=1
            //
            // how it works, the array is faster to compute, hashLocalBits() later orders the bits for SHA256 to hash
            // [1, None, None, None]
            // [1, 2, None, None]
            // [1, 2, 3, None]
            // [1, 2, 3, 4]
            // [5, 2, 3, 4]   <- only slot 0 changed: 1 -> 5
            // [5, 6, 3, 4]   <- only slot 1 changed: 2 -> 6
            // [5, 6, 7, 4]   <- only slot 2 changed: 3 -> 7
            // [5, 6, 7, 8]   <- only slot 3 changed: 4 -> 8
            //
            // then we are back to zero, completeing the loop in the fastest time possible
            // the oldest bit is now at head=0, the newest bit is at tail=0, and the buffer is full.
            if (!filled) {
                // buffer isn't full yet — we're still in the initial fill-up phase.
                if (tail == 0)
                    filled = true;
            } else {
                head = (head + 1) % localBufferSize;
            }

            // once full, every iteration represents one full 512-bit sliding window (oldest -> newest),
            // 512 bits = 2^512 = 64 bytes, which is exactly what SHA-256 expects as input.
            // this is an astronimcally large number of combinations, so the output is effectively "whitened" and conditioned.
            // in scientific notation, 2⁵¹² ≈ 1.34 × 10¹⁵⁴ which is a 155 digit long number so large that it is effectively impossible to brute-force or predict.
            // we now hash it every time to keep the output stream continuously fed with fresh digests.
            if (filled) {
                result += hashLocalBits();
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    SystemClock systemClock;

    static constexpr int update_interval       = 10;   // update the progress bar every 10 iterations
    static constexpr int totalIterations       = 1024; // total number of timing samples drawn per run()
    static constexpr size_t localBufferSize    = 512;  // ring buffer capacity — holds the last 512 raw entropy bits, hashed together to whiten/condition the output
    std::array<int, localBufferSize> localBits = {};   // the ring buffer itself — one int (0/1) per bit; array chosen over vector for fixed size + speed
    static constexpr size_t total              = 256;  // SHA-256 digest size in bits — size of each unit of output this class produces
    static constexpr int byte64                = 64;   // 512 bits (localBufferSize) expressed in bytes — what actually gets fed into SHA256::update()

    // NOTE: this is a lower-bound estimate for reserve(), not an exact count.
    // filled flips true partway through iteration (localBufferSize - 1), so hashing actually starts
    // one iteration earlier than this subtraction assumes — actual output is expectedBits + one extra digest.
    // localBufferSize - 1 = 511 is the last valid index, precisely because of 0-indexing.
    static constexpr size_t producingIterations = totalIterations - localBufferSize;
    static constexpr size_t expectedBits        = producingIterations * total;

    size_t head         = 0;     // index of the OLDEST live bit in the ring buffer (next to be evicted on write, once full)
    size_t tail         = 0;     // index of the NEXT WRITE position (where the newest bit goes)
    bool filled         = false; // latches true once the ring buffer has been fully populated at least once
    long long globalSum = 0;     // running sum of all timing samples seen so far this run
    long long globalAvg = 0;     // running average of timing samples — used as the live threshold for bit extraction
    long long count     = 0;     // number of timing samples taken so far this run (denominator for globalAvg)

    // busy-wait a fixed, tiny amount of work and measure how long it actually took in nanoseconds.
    // for faster computers, this will be a smaller number; for slower computers, it will be larger.
    // therefore: the volitile value x = 10 can be changed for x = 100 etc,.
    // the actual duration is noisy due to CPU/OS scheduling jitter, cache state, thermal throttling, etc —
    // that jitter is the raw entropy source this whole class is built on.
    inline long long countdown() {
        volatile int x = 10;
        auto start     = systemClock.getNanoseconds();
        while (x > 0) {
            int tmp = x;
            x       = tmp - 1;
        }
        return systemClock.getNanoseconds() - start;
    }

    // packs the current 512-bit ring buffer window into 64 bytes (oldest bit first, MSB-first within each byte),
    // then runs it through SHA-256 to condition/whiten the raw jitter bits into a uniform-looking digest.
    inline std::string hashLocalBits() {
        uint8_t bytes[64] = {0};

        for (size_t i = 0; i < localBufferSize; ++i) {
            // walk the ring starting at head (oldest) and wrapping forward to tail (newest) —
            // this only reads the correct chronological order because head is now actually maintained above.
            size_t idx = (head + i) % localBufferSize;
            if (localBits[idx]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, byte64);

        return sha.digestBinary();
    }

    // resets all run-scoped state so run() can be called repeatedly and produce independent output each time.
    // note: localBits itself is intentionally NOT cleared here — it gets fully overwritten during the
    // fill-up phase of the next run() before filled ever becomes true again, so stale bits never get hashed.
    void resetState() {
        head      = 0;
        tail      = 0;
        count     = 0;
        filled    = false;
        globalSum = 0;
        globalAvg = 0;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    BinaryEntropyPool() {
        bitPool.reserve(POOL_RESERVED);                    // pre-allocate 200% of one refill's worth upfront
        SecureMemory::lock(bitPool.data(), POOL_RESERVED); // pin the reserved region so it can't be swapped to disk
        // refill(); // intentionally left disabled — pool starts empty, first get() call triggers the initial fill
    }

    ~BinaryEntropyPool() {
        drain();                                             // zero out any remaining bits before releasing memory
        SecureMemory::unlock(bitPool.data(), POOL_RESERVED); // must match the size used in lock() above
    }

    // Fetches bitsNeeded bits, automatically choosing the right strategy:
    // - <= POOL_CAPACITY (one refill's worth): served directly via get(), fastest path, no chunking overhead.
    // - >  POOL_CAPACITY: routed to getLarge(), which pulls it in POOL_CAPACITY-sized chunks.
    // This is the method callers should use by default — get() or getLarge() remain available directly
    // if you specifically know which strategy you want (e.g. a tight loop issuing many small requests).
    inline std::string request(size_t bitsNeeded) {
        if (bitsNeeded <= POOL_CAPACITY)
            return get(bitsNeeded);
        return getLarge(bitsNeeded);
    }

    // Current number of unconsumed bits sitting in the pool. Mainly for diagnostics/monitoring.
    inline size_t available() const {
        std::lock_guard<std::mutex> lock(poolMutex);
        return bitPool.size();
    }

    // Securely wipes the entire pool and re-reserves capacity for future refills.
    // Called on destruction, and available to call manually if you need to force-discard
    // the current pool contents (e.g. suspected compromise, or before a sensitive operation).
    inline void drain() {
        std::lock_guard<std::mutex> lock(poolMutex);
        secureClear(bitPool);
        bitPool.reserve(POOL_CAPACITY);
    }

  private:
    RandomNumberGenerator rng;
    Functions functions;

    static constexpr size_t POOL_CAPACITY = 512 * 256;         // intended: 131,072 bits — one rng.run()
    static constexpr size_t POOL_RESERVED = POOL_CAPACITY * 2; // 262,144 bits — 200% headroom over one refill
    static constexpr size_t LOW_WATERMARK = 512 * 128;         // refill proactively once below half of POOL_CAPACITY

    std::string bitPool;          // the pool itself — a flat string of '0'/'1' characters acting as a bit queue
    mutable std::mutex poolMutex; // guards all reads/writes to bitPool, since get()/available()/drain() can be called from multiple threads

    // Returns exactly bitsNeeded bits, refilling from the RNG first if the pool is running low
    // or doesn't have enough to satisfy the request. Consumed bits are securely erased from the
    // pool immediately after being copied out, so they can't linger in memory post-use.
    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex); // pool is shared across threads — serialize all access

        if (bitsNeeded > POOL_RESERVED) {
            throw std::invalid_argument("get(): requested bits exceed pool's maximum single-request capacity — use request() or getLarge() instead");
        }

        if (bitPool.size() < LOW_WATERMARK)
            refill(); // proactive top-up once we drop below the halfway mark, before we're actually starved
        while (bitPool.size() < bitsNeeded)
            refill(); // reactive top-up — guarantees enough bits exist to satisfy this specific request

        std::string result = bitPool.substr(0, bitsNeeded); // copy out the requested prefix
        secureErase(bitsNeeded);                            // wipe + remove those bits from the pool so they're one-time-use

        return result;
    }

    // Same contract as get(), but for requests larger than a single refill's worth (POOL_CAPACITY).
    // Pulls bits in POOL_CAPACITY-sized chunks via repeated get() calls and concatenates them.
    inline std::string getLarge(size_t bitsNeeded) {
        std::string result;
        result.reserve(bitsNeeded);

        size_t remaining = bitsNeeded;
        size_t completed = 0;
        std::cout << '\n';

        while (remaining > 0) {
            size_t chunkSize = std::min(remaining, POOL_CAPACITY);
            result += get(chunkSize);
            completed += chunkSize;
            remaining -= chunkSize;

            functions.printProgressBar(completed, bitsNeeded);
        }

        std::cout << '\n';

        return result;
    }

    // Unused — getLarge() currently reimplements this chunking loop inline instead of calling this.
    // Either wire this in or remove it so there's only one chunking implementation to maintain.
    inline std::vector<std::string> getChunked(size_t bitsNeeded) {
        std::vector<std::string> chunks;

        size_t remaining = bitsNeeded;

        while (remaining > 0) {
            size_t chunkSize = std::min(remaining, POOL_CAPACITY);
            chunks.push_back(get(chunkSize));
            remaining -= chunkSize;
        }

        return chunks;
    }

    inline void refill() {
        if (bitPool.size() >= POOL_RESERVED)
            return; // already at max reserved capacity — adding more would force a reallocation, invalidating the memory lock

        std::string fresh = rng.run();
        size_t room       = POOL_RESERVED - bitPool.size();

        if (fresh.size() > room)
            fresh.resize(room); // trim to whatever room remains — wastes some freshly-generated entropy bits, but that's a far cheaper cost than an unlocked buffer

        bitPool += fresh;
    }

    // Overwrites every byte of the given string with 0 before clearing it, so freed/reused
    // memory doesn't retain the old bit pattern. volatile prevents the compiler from optimizing
    // this "pointless-looking" write-then-discard away — a plain loop without volatile could
    // legally be eliminated entirely by the optimizer since the values are never read afterward.
    inline void secureClear(std::string &s) {
        volatile char *p = s.data();
        for (size_t i = 0; i < s.size(); ++i)
            p[i] = 0;
        s.clear();
    }

    // Same secure-wipe technique as secureClear(), but only for the first n bits/chars —
    // used by get() to destroy just the bits that were handed out, leaving the rest of the pool intact.
    inline void secureErase(size_t n) {
        volatile char *p = bitPool.data();
        for (size_t i = 0; i < n; ++i)
            p[i] = 0;
        bitPool.erase(0, n);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    maximizeConsoleWindow();
    SetConsoleTitle(TEXT("Oiko's RNG: " CSPRNG_VERSION));
#endif

    RandomNumberGenerator rng;
    BinaryEntropyPool bep;
    EntropyAnalyzer analyzer;
    Functions functions;

    std::cout << "Welcome to Oikos Random Number Generator!\n";
    std::cout << "Version: " << CSPRNG_VERSION << "\n\n";
    std::cout << "Please enter the amount of entropy you wish to Generate!\n\n";

    int amount;
    std::cin >> amount;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "\n";
    std::cout << "Output: entropy.bin      - Contains the raw binary data\n";
    std::cout << "Output: entropy_info.txt - Contains statistics: National Institute of Standards and Technology (NIST)\n";

    auto start = std::chrono::steady_clock::now();

    std::string entropy = bep.request(amount);

    auto end        = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double seconds  = durationMs / 1000.0;
    double bps      = amount / seconds;

    // Write raw entropy (NIST input)
    {
        std::ofstream out("entropy.bin", std::ios::binary);
        out << entropy;
    }

    // Write metadata
    {
        std::ofstream info("entropy_info.txt");

        info << "Oikos Entropy Generator\n";
        info << "Version:               " << CSPRNG_VERSION << "\n";
        info << "Bits generated:        " << functions.format(amount) << "\n";
        info << "Time (ms):             " << functions.format(durationMs) << "\n";
        info << "Time (s):              " << functions.formatFixed(seconds, 3) << "\n";
        info << "Throughput (bits/sec): " << functions.format(bps) << "\n";
        info << "Throughput (Mbps):     " << functions.formatFixed(bps / 1'000'000.0, 2) << "\n";
    }

    std::cout << "\nDone.\n";
    std::cout << "Time (ms):             " << functions.format(durationMs) << "\n";
    std::cout << "Time (s):              " << functions.formatFixed(seconds, 3) << "\n";
    std::cout << "Bits generated:        " << functions.format(amount) << "\n";
    std::cout << "Throughput (bits/sec): " << functions.format(bps) << "\n";
    std::cout << "Throughput (Mbps):     " << functions.formatFixed(bps / 1'000'000.0, 2) << "\n\n";

    analyzer.feedBits(entropy); // add the entropy output to check the distribution across bytes
    analyzer.print();           // print the distribution table

    std::cout << "\nProgram finished. Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
