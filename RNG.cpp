
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// MIT License

// Copyright (c) 2026 oiko-nomikos

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// === Core C++ Input/Output and Strings ===
#include <iostream> // std::cout, std::cin — console I/O
#include <string>   // std::string — string handling
#include <iomanip>  // std::setw, std::setprecision — formatted output

// === Containers and Data Structures ===
#include <vector> // std::vector — dynamic arrays
#include <deque>  // std::deque — double-ended queues (used for entropy pools)

// === Timing and Delays ===
#include <chrono> // std::chrono::high_resolution_clock — precise timing

// === Multithreading and Synchronization ===
#include <mutex> // std::mutex — mutual exclusion

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Functions {
  public:
    // Put this function somewhere in your code
    void pressEnterToContinue() {
        std::cout << "\nPress Enter to continue...\n";
        std::cin.clear(); // in case of previous input errors
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get(); // wait for one more newline (Enter)
    }
};

class SystemClock {
  public:
    inline long long getSeconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    }

    inline long long getMilliseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    inline long long getMicroseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }

    inline long long getNanoseconds() {
        auto now = std::chrono::system_clock::now();
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

    void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }

    void update(const std::string &data) { update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); }

    std::string digest() {
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

    std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    void reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        bitlen = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
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

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
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

inline std::string sha256Binary(const std::string &data) {
    CRYPTO::SHA256 sha;
    sha.update(data);
    return sha.digestBinary(); // directly returns 256-bit binary string
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        std::string result;
        result.reserve((totalIterations - localBufferSize) * 256);

        for (int i = 0; i < totalIterations; ++i) {

            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            if (localBits.size() >= localBufferSize)
                localBits.pop_front();

            localBits.push_back(bit);

            if (localBits.size() == localBufferSize) {
                // 32 raw bytes → 256 bit string
                std::string hashBits = hashLocalBits();
                result += hashBits;
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    SystemClock systemClock;
    std::deque<int> localBits;
    const int totalIterations = 1000;
    const size_t localBufferSize = 512;
    long long globalSum = 0;
    long long globalAvg = 0;
    int count = 0;

    inline long long countdown() {
        int x = 10;
        auto start = systemClock.getNanoseconds();
        while (x > 0)
            x--;
        auto end = systemClock.getNanoseconds();
        return end - start;
    }

    inline std::string hashLocalBits() {
        uint8_t bytes[64] = {0};
        for (size_t i = 0; i < localBits.size(); ++i) {
            if (localBits[i]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }
        std::string byteString(reinterpret_cast<char *>(bytes), 64);
        return sha256Binary(byteString);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    BinaryEntropyPool(size_t maxBits = 10000) : maxPoolSize(maxBits) {}

    std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // Refill the pool until we have enough bits, but never exceed maxPoolSize
        while (bitPool.size() < bitsNeeded && bitPool.size() < maxPoolSize) {
            std::string newBits = rng.run();

            // Only add as many bits as will fit
            if (bitPool.size() + newBits.size() > maxPoolSize) {
                newBits = newBits.substr(0, maxPoolSize - bitPool.size());
            }

            bitPool += newBits;
        }

        // Extract exactly the number of bits requested
        std::string result = bitPool.substr(0, bitsNeeded);
        bitPool.erase(0, bitsNeeded); // remove consumed bits

        return result;
    }

  private:
    std::string bitPool; // bit string directly
    RandomNumberGenerator rng;
    mutable std::mutex poolMutex;
    size_t maxPoolSize;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

int main() {
    RandomNumberGenerator rng;
    BinaryEntropyPool bep;
    Functions functions;

    functions.pressEnterToContinue();

    rng.run();

    std::string oneBitOfEntropy = bep.get(1);

    std::cout << "One bit of entrpy: " << oneBitOfEntropy;

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------