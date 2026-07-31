
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
// Windows API
//----------------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN // Exclude rarely used Windows headers to reduce compile time
#include <windows.h>        // Windows API (VirtualLock, VirtualUnlock, Sleep, etc.)

//----------------------------------------------------------------------------------
// Global Type Aliases
//----------------------------------------------------------------------------------

using Bytes = std::vector<uint8_t>; // Convenience alias for a byte buffer

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
    static constexpr const char *CLASS_NAME = "SHA256";
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
        const size_t producingIterations = totalIterations - localBufferSize;
        const size_t expectedBits        = producingIterations * total;

        std::string result;
        result.reserve(expectedBits);

        // reset state
        head      = 0;
        tail      = 0;
        count     = 0;
        filled    = false;
        globalSum = 0;
        globalAvg = 0;

        for (int i = 0; i < totalIterations; ++i) {
            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            localBits[tail] = bit;
            tail            = (tail + 1) % localBufferSize;

            if (!filled && tail == localBufferSize - 1)
                filled = true;

            if (filled) {
                result += hashLocalBits();
            }
        }

        return result;
    }

  private:
    static constexpr const char *CLASS_NAME = "RandomNumberGenerator";
    CRYPTO::SHA256 sha;
    SystemClock systemClock;

    static constexpr int totalIterations    = 1024;
    static constexpr size_t localBufferSize = 512;
    static constexpr size_t total           = 256;
    static constexpr int byte64             = 64;

    std::array<int, localBufferSize> localBits = {};
    size_t head                                = 0;
    size_t tail                                = 0;
    bool filled                                = false;
    long long globalSum                        = 0;
    long long globalAvg                        = 0;
    int count                                  = 0;

    inline long long countdown() {
        volatile int x = 10;
        auto start     = systemClock.getNanoseconds();
        while (x > 0) {
            int tmp = x;
            x       = tmp - 1;
        }
        return systemClock.getNanoseconds() - start;
    }

    inline std::string hashLocalBits() {
        uint8_t bytes[64] = {0};

        for (size_t i = 0; i < localBufferSize; ++i) {
            size_t idx = (head + i) % localBufferSize;
            if (localBits[idx]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, byte64);

        return sha.digestBinary();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    BinaryEntropyPool() {
        bitPool.reserve(POOL_RESERVED); // reserve 200% upfront
        lockMemory();
        // refill();
    }

    ~BinaryEntropyPool() {
        drain();
        unlockMemory();
    }

    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        if (bitPool.size() < LOW_WATERMARK)
            refill();
        while (bitPool.size() < bitsNeeded)
            refill();

        std::string result = bitPool.substr(0, bitsNeeded);
        secureErase(bitsNeeded);

        return result;
    }

    inline std::string getLarge(size_t bitsNeeded) {
        std::string result;
        result.reserve(bitsNeeded);

        size_t remaining = bitsNeeded;

        while (remaining > 0) {
            size_t chunkSize = std::min(remaining, POOL_CAPACITY);
            result += get(chunkSize);
            remaining -= chunkSize;
        }

        return result;
    }

    inline size_t available() const {
        std::lock_guard<std::mutex> lock(poolMutex);
        return bitPool.size();
    }

    inline void drain() {
        std::lock_guard<std::mutex> lock(poolMutex);
        secureClear(bitPool);
        bitPool.reserve(POOL_CAPACITY);
    }

  private:
    RandomNumberGenerator rng;

    static constexpr const char *CLASS_NAME = "BinaryEntropyPool";
    static constexpr size_t POOL_CAPACITY   = 512 * 256;         // 131,072 bits — one rng.run()
    static constexpr size_t POOL_RESERVED   = POOL_CAPACITY * 2; // 262,144 bits — 200%
    static constexpr size_t LOW_WATERMARK   = 512 * 128;         // refill below halfway

    std::string bitPool;
    mutable std::mutex poolMutex;

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

    inline void refill() { bitPool += rng.run(); }

    inline void secureClear(std::string &s) {
        volatile char *p = s.data();
        for (size_t i = 0; i < s.size(); ++i)
            p[i] = 0;
        s.clear();
    }

    inline void secureErase(size_t n) {
        volatile char *p = bitPool.data();
        for (size_t i = 0; i < n; ++i)
            p[i] = 0;
        bitPool.erase(0, n);
    }

    inline void lockMemory() {
#ifdef _WIN32
        VirtualLock(bitPool.data(), POOL_RESERVED);
#else
        mlock(bitPool.data(), POOL_RESERVED);
#endif
    }

    inline void unlockMemory() {
#ifdef _WIN32
        VirtualUnlock(bitPool.data(), POOL_CAPACITY);
#else
        munlock(bitPool.data(), POOL_CAPACITY);
#endif
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

int main() {
    RandomNumberGenerator rng;
    BinaryEntropyPool bep;

    std::cout << "Welcome to Oikos Entropy Generator!\n\n";
    std::cout << "Please enter the amount of entropy you wish to Generate!\n";

    int amount;
    std::cin >> amount;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Output: entropy.bin, comes equiped with a metadata file\n";
    std::cout << "You can use this file for statistics: National Institute of Standards and Technology (NIST)\n";

    auto start = std::chrono::steady_clock::now();

    std::string entropy = bep.get(amount);

    auto end        = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Write raw entropy (NIST input)
    {
        std::ofstream out("entropy.bin", std::ios::binary);
        out << entropy;
    }

    // Write metadata
    {
        std::ofstream info("entropy_info.txt");
        double seconds = durationMs / 1000.0;
        double bps     = amount / seconds;

        info << "Oikos Entropy Generator\n";
        info << "Bits generated: " << amount << "\n";
        info << "Time (ms): " << durationMs << "\n";
        info << "Time (s): " << seconds << "\n";
        info << "Throughput (bits/sec): " << bps << "\n";
        info << "Throughput (Mbps): " << (bps / 1'000'000.0) << "\n";
    }

    std::cout << "\nDone.\n";
    std::cout << "Generated " << amount << " bits\n";
    std::cout << "Time: " << durationMs << " ms\n";

    std::cout << "\nProgram finished. Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
