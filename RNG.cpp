
// =================================================================================
//
// Oikos Random Number Generator
// Copyright (c) 2026 oiko-nomikos
//
// Licensed under the MIT License.
// SPDX-License-Identifier: MIT
//
// See the LICENSE file in the project root for the full license text.
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
// THIS IS NOT PRODUCTION-GRADE CRYPTOGRAPHY - NOT YET!
//
// Discretion must be given - use at own risk!
//
// If you find a bug or weakness — please report it responsibly.
//
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
#include <fstream>  // std::ifstream, std::ofstream — file I/O
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
        std::cout << "Ideal uniform: " << std::fixed << std::setprecision(2) << mean << " bytes per value\n\n";
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

class TestNIST {
  public:
    explicit TestNIST(const std::string &bits)
        : bits(bits) {}

    struct TestResult {
        std::string name;
        bool passed      = false;
        double statistic = 0.0;
        double pValue    = 0.0;
        std::string description;
    };

    //======================================================================
    // Draw NIST Statistical Test Suite Dashboard
    //======================================================================

    static constexpr int LINE_WIDTH = 90; // wide enough to blank out any leftover text

    // Writes one line, padded with spaces to LINE_WIDTH so stale
    // characters from a previous (longer) frame get erased without
    // ever calling a screen-clear function.
    void printLine(const std::string &text) {
        std::string padded = text;
        if (padded.size() < LINE_WIDTH)
            padded.append(LINE_WIDTH - padded.size(), ' ');
        std::cout << padded << '\n';
    }

    void drawProgress(int currentTest, int totalTests, const std::vector<std::string> &completedTests, const std::string &currentTestName) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Anchor to wherever the dashboard actually started, not (0,0).
        SetConsoleCursorPosition(hConsole, dashboardOrigin);

        printLine("===================================================================");
        printLine("                NIST Statistical Test Suite (STS)");
        printLine("          NIST SP 800-22 Revision 1a (SP 800-22 Rev. 1a)");
        printLine("===================================================================");
        printLine("");
        printLine("Overall Progress");

        // Capture the progress bar text instead of letting it print
        // directly, so we can pad it like everything else.
        {
            std::ostringstream oss;
            auto *old = std::cout.rdbuf(oss.rdbuf());
            functions.printProgressBar(currentTest, totalTests);
            std::cout.rdbuf(old);
            printLine(oss.str());
        }

        printLine("");
        printLine("Completed Tests");
        printLine("-------------------------------------------------------------------");

        // Fixed-height block: always print exactly `totalTests` lines
        // so the layout below never shifts between frames.
        for (int i = 0; i < totalTests; ++i) {
            if (i < static_cast<int>(completedTests.size()))
                printLine("[DONE] " + completedTests[i]); // ✓
            else
                printLine("");
        }

        printLine("");
        printLine("Currently Running");
        printLine("-------------------------------------------------------------------");

        if (currentTest < totalTests)
            printLine(currentTestName); // →
        else
            printLine("All tests complete.");

        std::cout.flush();
    }

    //======================================================================
    // Execute NIST Statistical Test Suite
    //======================================================================

    void runAll() {

        results.clear();

        constexpr int TOTAL_TESTS = 15;

        int currentTest = 0;

        std::vector<std::string> completedTests;

        // Anchor the dashboard to whatever line the cursor is on
        // *right now* (below the banner/entropy info/byte table that
        // was already printed), instead of hardcoding {0,0}.
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        dashboardOrigin = csbi.dwCursorPosition;

        drawProgress(currentTest, TOTAL_TESTS, completedTests, "Frequency (Monobit) Test");

        results.push_back(runFrequency());
        completedTests.push_back("Frequency (Monobit) Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Frequency Test Within a Block");

        results.push_back(runBlockFrequency());
        completedTests.push_back("Frequency Test Within a Block");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Runs Test");

        results.push_back(runRuns());
        completedTests.push_back("Runs Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Longest Run of Ones in a Block Test");

        results.push_back(runLongestRun());
        completedTests.push_back("Longest Run of Ones in a Block Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Binary Matrix Rank Test");

        results.push_back(runMatrixRank());
        completedTests.push_back("Binary Matrix Rank Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Discrete Fourier Transform (Spectral) Test");

        results.push_back(runDFT());
        completedTests.push_back("Discrete Fourier Transform (Spectral) Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Non-Overlapping Template Matching Test");

        results.push_back(runNonOverlappingTemplate());
        completedTests.push_back("Non-Overlapping Template Matching Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Overlapping Template Matching Test");

        results.push_back(runOverlappingTemplate());
        completedTests.push_back("Overlapping Template Matching Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Maurer's Universal Statistical Test");

        results.push_back(runMaurer());
        completedTests.push_back("Maurer's Universal Statistical Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Linear Complexity Test");

        results.push_back(runLinearComplexity());
        completedTests.push_back("Linear Complexity Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Serial Test");

        results.push_back(runSerial());
        completedTests.push_back("Serial Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Approximate Entropy Test");

        results.push_back(runApproximateEntropy());
        completedTests.push_back("Approximate Entropy Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Cumulative Sums (Cusum) Test");

        results.push_back(runCumulativeSums());
        completedTests.push_back("Cumulative Sums (Cusum) Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Random Excursions Test");

        results.push_back(runRandomExcursions());
        completedTests.push_back("Random Excursions Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "Random Excursions Variant Test");

        results.push_back(runRandomExcursionsVariant());
        completedTests.push_back("Random Excursions Variant Test");
        drawProgress(++currentTest, TOTAL_TESTS, completedTests, "");

        std::cout << "\n\n";
        std::cout << "NIST Statistical Test Suite completed successfully.\n\n";
    }

    const std::vector<TestResult> &getResults() const { return results; }

  private:
    Functions functions;
    std::string bits;
    std::vector<TestResult> results;
    COORD dashboardOrigin{0, 0};
    static constexpr double PI = 3.14159265358979323846;

    //======================================================================
    // Shared math helpers (regularized incomplete gamma function, used by
    // every chi-square-based test below to turn a statistic into a p-value)
    //======================================================================

    static double gser(double a, double x) {
        constexpr int ITMAX  = 200;
        constexpr double EPS = 3e-9;

        if (x <= 0.0)
            return 0.0;

        double gln = std::lgamma(a);
        double ap  = a;
        double sum = 1.0 / a;
        double del = sum;

        for (int n = 1; n <= ITMAX; ++n) {
            ap += 1.0;
            del *= x / ap;
            sum += del;

            if (std::fabs(del) < std::fabs(sum) * EPS)
                break;
        }

        return sum * std::exp(-x + a * std::log(x) - gln);
    }

    static double gcf(double a, double x) {
        constexpr int ITMAX    = 200;
        constexpr double EPS   = 3e-9;
        constexpr double FPMIN = 1e-300;

        double gln = std::lgamma(a);

        double b = x + 1.0 - a;
        double c = 1.0 / FPMIN;
        double d = 1.0 / b;
        double h = d;

        for (int i = 1; i <= ITMAX; ++i) {
            double an = -i * (i - a);
            b += 2.0;
            d = an * d + b;

            if (std::fabs(d) < FPMIN)
                d = FPMIN;

            c = b + an / c;

            if (std::fabs(c) < FPMIN)
                c = FPMIN;

            d          = 1.0 / d;
            double del = d * c;
            h *= del;

            if (std::fabs(del - 1.0) < EPS)
                break;
        }

        return std::exp(-x + a * std::log(x) - gln) * h;
    }

    // Regularized upper incomplete gamma function Q(a, x).
    // This is what every NIST chi-square test converts its statistic
    // through to get a p-value: pValue = igamc(df / 2, chiSquared / 2).
    static double igamc(double a, double x) {
        if (x < 0.0 || a <= 0.0)
            return 0.0;

        if (x == 0.0)
            return 1.0;

        if (x < a + 1.0)
            return 1.0 - gser(a, x);

        return gcf(a, x);
    }

    // Iterative in-place Cooley-Tukey FFT. Zero-pads to the next power of
    // two if needed (runDFT avoids relying on that by pre-truncating to a
    // power-of-two prefix, so the padding path here only matters if this
    // helper is reused elsewhere).
    static void fft(std::vector<std::complex<double>> &a) {
        size_t n = a.size();

        if (n <= 1)
            return;

        size_t m = 1;

        while (m < n)
            m <<= 1;

        a.resize(m, std::complex<double>(0.0, 0.0));
        n = m;

        for (size_t i = 1, j = 0; i < n; ++i) {
            size_t bit = n >> 1;

            for (; j & bit; bit >>= 1)
                j ^= bit;

            j ^= bit;

            if (i < j)
                std::swap(a[i], a[j]);
        }

        for (size_t len = 2; len <= n; len <<= 1) {
            double angle = -2.0 * PI / static_cast<double>(len);
            std::complex<double> wlen(std::cos(angle), std::sin(angle));

            for (size_t i = 0; i < n; i += len) {
                std::complex<double> w(1.0, 0.0);

                for (size_t k = 0; k < len / 2; ++k) {
                    std::complex<double> u = a[i + k];
                    std::complex<double> v = a[i + k + len / 2] * w;

                    a[i + k]           = u + v;
                    a[i + k + len / 2] = u - v;

                    w *= wlen;
                }
            }
        }
    }

    //======================================================================
    // 1. Frequency (Monobit) Test
    //======================================================================

    TestResult runFrequency() {
        TestResult result;
        result.name = "Frequency (Monobit) Test";

        const size_t n = bits.size();

        if (n == 0) {
            result.description = "Input contains no data.";
            return result;
        }

        long long sum = 0;

        for (char bit : bits) {
            if (bit == '1') {
                sum++;
            } else if (bit == '0') {
                sum--;
            }
        }

        result.statistic = std::abs(sum) / std::sqrt(static_cast<double>(n));
        result.pValue    = std::erfc(result.statistic / std::sqrt(2.0));
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Sequence passes the frequency test.";
        else
            result.description = "Sequence exhibits a significant bias toward zeros or ones.";

        return result;
    }

    //======================================================================
    // 2. Block Frequency Test
    //======================================================================

    TestResult runBlockFrequency() {
        TestResult result;
        result.name = "Block Frequency Test";

        const size_t M = 128; // bits per block
        const size_t n = bits.size();
        const size_t N = n / M; // number of complete blocks

        if (N == 0) {
            result.description = "Not enough data.";
            return result;
        }

        double chiSquared = 0.0;

        for (size_t block = 0; block < N; ++block) {
            size_t ones = 0;

            for (size_t i = 0; i < M; ++i) {
                if (bits[block * M + i] == '1')
                    ++ones;
            }

            double pi = static_cast<double>(ones) / M;
            chiSquared += 4.0 * M * (pi - 0.5) * (pi - 0.5);
        }

        result.statistic = chiSquared;
        result.pValue    = igamc(N / 2.0, chiSquared / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "All blocks have an acceptable balance of zeros and ones.";
        else
            result.description = "One or more blocks exhibit significant bias.";

        return result;
    }

    //======================================================================
    // 3. Runs Test
    //======================================================================

    TestResult runRuns() {
        TestResult result;
        result.name = "Runs Test";

        const size_t n = bits.size();

        if (n < 2) {
            result.description = "Not enough data.";
            return result;
        }

        size_t ones = 0;

        for (char bit : bits) {
            if (bit == '1')
                ++ones;
        }

        double pi = static_cast<double>(ones) / n;

        if (std::fabs(pi - 0.5) >= (2.0 / std::sqrt(static_cast<double>(n)))) {
            result.description = "Frequency test prerequisite not satisfied.";
            return result;
        }

        size_t runs = 1;

        for (size_t i = 1; i < n; ++i) {
            if (bits[i] != bits[i - 1])
                ++runs;
        }

        result.statistic   = static_cast<double>(runs);
        double numerator   = std::fabs(runs - (2.0 * n * pi * (1.0 - pi)));
        double denominator = 2.0 * std::sqrt(2.0 * n) * pi * (1.0 - pi);
        result.pValue      = std::erfc(numerator / denominator);
        result.passed      = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Run lengths are consistent with randomness.";
        else
            result.description = "Run lengths are inconsistent with randomness.";

        return result;
    }

    //======================================================================
    // 4. Longest Run of Ones in a Block Test
    //======================================================================

    size_t longestRunInRange(size_t start, size_t length) const {
        size_t longest = 0;
        size_t current = 0;

        for (size_t i = start; i < start + length; ++i) {
            if (bits[i] == '1') {
                ++current;

                if (current > longest)
                    longest = current;
            } else {
                current = 0;
            }
        }

        return longest;
    }

    TestResult runLongestRun() {
        TestResult result;
        result.name = "Longest Run of Ones in a Block Test";

        const size_t n = bits.size();

        if (n < 128) {
            result.description = "Not enough data.";
            return result;
        }

        size_t M, K, N;
        std::vector<double> pi;

        if (n < 6272) {
            M  = 8;
            K  = 3;
            N  = 16;
            pi = {0.2148, 0.3672, 0.2305, 0.1875};
        } else if (n < 750000) {
            M  = 128;
            K  = 5;
            N  = 49;
            pi = {0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124};
        } else {
            M  = 10000;
            K  = 6;
            N  = 75;
            pi = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
        }

        auto classify = [&](size_t runLen) -> size_t {
            if (M == 8) {
                if (runLen <= 1)
                    return 0;
                if (runLen == 2)
                    return 1;
                if (runLen == 3)
                    return 2;
                return 3;
            } else if (M == 128) {
                if (runLen <= 4)
                    return 0;
                if (runLen == 5)
                    return 1;
                if (runLen == 6)
                    return 2;
                if (runLen == 7)
                    return 3;
                if (runLen == 8)
                    return 4;
                return 5;
            } else {
                if (runLen <= 10)
                    return 0;
                if (runLen == 11)
                    return 1;
                if (runLen == 12)
                    return 2;
                if (runLen == 13)
                    return 3;
                if (runLen == 14)
                    return 4;
                if (runLen == 15)
                    return 5;
                return 6;
            }
        };

        std::vector<int> v(pi.size(), 0);

        for (size_t block = 0; block < N; ++block) {
            size_t longest = longestRunInRange(block * M, M);
            v[classify(longest)]++;
        }

        double chi = 0.0;

        for (size_t i = 0; i < pi.size(); ++i) {
            double expected = N * pi[i];
            double diff     = v[i] - expected;
            chi += diff * diff / expected;
        }

        result.statistic = chi;
        result.pValue    = igamc(K / 2.0, chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Longest run lengths per block are consistent with randomness.";
        else
            result.description = "Longest run lengths per block deviate from randomness.";

        return result;
    }

    //======================================================================
    // 5. Binary Matrix Rank Test
    //======================================================================

    TestResult matrixRank(Matrix32 matrix) const {
        TestResult result;
        result.name = "Matrix Rank (internal)";
        int rank    = 0;

        for (int col = 0; col < 32; col++) {
            int pivot = -1;

            for (int row = rank; row < 32; row++) {
                if (matrix[row][col]) {
                    pivot = row;
                    break;
                }
            }

            if (pivot == -1)
                continue;

            if (pivot != rank)
                std::swap(matrix[pivot], matrix[rank]);

            for (int row = 0; row < 32; row++) {
                if (row == rank)
                    continue;

                if (matrix[row][col]) {
                    for (int c = col; c < 32; c++)
                        matrix[row][c] = matrix[row][c] ^ matrix[rank][c];
                }
            }

            rank++;
        }

        result.statistic = static_cast<double>(rank);
        return result;
    }

    TestResult runMatrixRank() {
        TestResult result;
        result.name = "Binary Matrix Rank Test";

        constexpr size_t rows = 32, cols = 32;
        constexpr size_t bitsPerMatrix = rows * cols; // 1024
        const size_t n                 = bits.size();
        const size_t N                 = n / bitsPerMatrix;

        if (N == 0) {
            result.description = "Not enough data.";
            return result;
        }

        double fullRank = 0, rankMinus1 = 0, rankLess = 0;

        for (size_t idx = 0; idx < N; ++idx) {
            Matrix32 matrix{};
            size_t offset = idx * bitsPerMatrix;

            for (size_t r = 0; r < rows; ++r) {
                for (size_t c = 0; c < cols; ++c) {
                    matrix[r][c] = (bits[offset + r * cols + c] == '1');
                }
            }

            int rank = static_cast<int>(matrixRank(matrix).statistic);

            if (rank == 32)
                ++fullRank;
            else if (rank == 31)
                ++rankMinus1;
            else
                ++rankLess;
        }

        double expectedFull = 0.2888 * N;
        double expectedM1   = 0.5776 * N;
        double expectedLess = 0.1336 * N;

        double chi = (fullRank - expectedFull) * (fullRank - expectedFull) / expectedFull + (rankMinus1 - expectedM1) * (rankMinus1 - expectedM1) / expectedM1
                     + (rankLess - expectedLess) * (rankLess - expectedLess) / expectedLess;

        result.statistic = chi;
        result.pValue    = igamc(1.0, chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Matrix ranks are consistent with randomness.";
        else
            result.description = "Matrix rank distribution deviates from randomness.";

        return result;
    }

    //======================================================================
    // 6. Discrete Fourier Transform (Spectral) Test
    //======================================================================

    TestResult runDFT() {
        TestResult result;
        result.name = "Discrete Fourier Transform Test";

        // Use the largest power-of-two prefix so the FFT works on real
        // data with no zero-padding artifacts skewing the spectrum.
        size_t n = 1;

        while (n * 2 <= bits.size())
            n *= 2;

        if (n < 1024) {
            result.description = "Insufficient data.";
            return result;
        }

        std::vector<std::complex<double>> signal(n);

        for (size_t i = 0; i < n; i++) {
            signal[i] = (bits[i] == '1') ? 1.0 : -1.0;
        }

        fft(signal);

        const double T = std::sqrt(std::log(20.0) * n);

        size_t count = 0;

        for (size_t i = 0; i < n / 2; i++) {
            double mag = std::abs(signal[i]);

            if (mag < T)
                count++;
        }

        double N0        = 0.95 * n / 2.0;
        double d         = (count - N0) / std::sqrt(n * 0.95 * 0.05 / 4.0);
        result.statistic = d;
        result.pValue    = std::erfc(std::fabs(d) / std::sqrt(2.0));
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "No significant periodic features detected.";
        else
            result.description = "Periodic structure detected.";

        return result;
    }

    //======================================================================
    // 7. Non-Overlapping Template Matching Test
    //======================================================================

    TestResult countNonOverlapping(size_t start, size_t length, const std::string &pattern) const {
        TestResult result;
        result.name = "Non-Overlapping Template Test (internal)";

        size_t count = 0;
        size_t i     = start;

        while (i + pattern.size() <= start + length) {
            bool match = true;

            for (size_t j = 0; j < pattern.size(); j++) {
                if (bits[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                count++;
                i += pattern.size();
            } else {
                i++;
            }
        }

        result.statistic = static_cast<double>(count);
        return result;
    }

    TestResult runNonOverlappingTemplate() {
        TestResult result;
        result.name = "Non-Overlapping Template Matching Test";

        const std::string pattern = "000000001"; // canonical 9-bit aperiodic template
        const size_t m            = pattern.size();
        const size_t n            = bits.size();
        const size_t N            = 8; // number of blocks (NIST default)
        const size_t M            = n / N;

        if (N == 0 || M <= m) {
            result.description = "Not enough data.";
            return result;
        }

        double mu  = static_cast<double>(M - m + 1) / std::pow(2.0, static_cast<double>(m));
        double var = M * (1.0 / std::pow(2.0, static_cast<double>(m)) - (2.0 * m - 1.0) / std::pow(2.0, 2.0 * m));

        double chi = 0.0;

        for (size_t block = 0; block < N; ++block) {
            double count = countNonOverlapping(block * M, M, pattern).statistic;
            double diff  = count - mu;
            chi += diff * diff / var;
        }

        result.statistic = chi;
        result.pValue    = igamc(static_cast<double>(N) / 2.0, chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Template occurrence counts are consistent with randomness.";
        else
            result.description = "Template occurs with unusual frequency in one or more blocks.";

        return result;
    }

    //======================================================================
    // 8. Overlapping Template Matching Test
    //======================================================================

    size_t countOverlapping(size_t start, size_t length, const std::string &pattern) const {
        size_t count = 0;

        for (size_t i = start; i + pattern.size() <= start + length; ++i) {
            bool match = true;

            for (size_t j = 0; j < pattern.size(); j++) {
                if (bits[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }

            if (match)
                ++count;
        }

        return count;
    }

    TestResult runOverlappingTemplate() {
        TestResult result;
        result.name = "Overlapping Template Test";

        constexpr size_t M       = 1032;
        constexpr char PATTERN[] = "111111111";
        const size_t n           = bits.size();
        const size_t N           = n / M;

        if (N == 0) {
            result.description = "Not enough data.";
            return result;
        }

        int counts[6] = {0};

        for (size_t block = 0; block < N; ++block) {
            size_t c = countOverlapping(block * M, M, PATTERN);

            if (c >= 5)
                counts[5]++;
            else
                counts[c]++;
        }

        constexpr double pi[6] = {0.364091, 0.185659, 0.139381, 0.100571, 0.070432, 0.139865};

        double chi = 0.0;

        for (int i = 0; i < 6; i++) {
            double expected = N * pi[i];
            double diff     = counts[i] - expected;
            chi += diff * diff / expected;
        }

        result.statistic = chi;
        result.pValue    = igamc(2.5, chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Overlapping template frequencies are consistent with randomness.";
        else
            result.description = "Excessive repeated template occurrences detected.";

        return result;
    }

    //======================================================================
    // 9. Maurer's Universal Statistical Test
    //======================================================================

    TestResult runMaurer() {
        TestResult result;
        result.name = "Maurer's Universal Test";

        constexpr int L          = 8;
        constexpr int Q          = 2560;
        const size_t totalBlocks = bits.size() / L;

        if (totalBlocks <= Q) {
            result.description = "Not enough data.";
            return result;
        }

        const size_t K = totalBlocks - Q;
        std::vector<int> lastSeen(1 << L, -1);

        for (int i = 0; i < Q; i++) {
            int value = 0;

            for (int b = 0; b < L; b++) {
                value <<= 1;

                if (bits[i * L + b] == '1')
                    value |= 1;
            }

            lastSeen[value] = i;
        }

        double sum = 0.0;

        for (size_t i = Q; i < totalBlocks; i++) {
            int value = 0;

            for (int b = 0; b < L; b++) {
                value <<= 1;

                if (bits[i * L + b] == '1')
                    value |= 1;
            }

            int distance = static_cast<int>(i) - lastSeen[value];
            sum += std::log2(distance);
            lastSeen[value] = static_cast<int>(i);
        }

        double fn        = sum / K;
        result.statistic = fn;

        constexpr double expected = 7.1836656;
        constexpr double variance = 3.238;
        double sigma              = std::sqrt(variance / K);

        result.pValue = std::erfc(std::fabs(fn - expected) / (std::sqrt(2.0) * sigma));
        result.passed = result.pValue >= 0.01;

        if (result.passed)
            result.description = "Sequence exhibits expected universal behavior.";
        else
            result.description = "Sequence appears overly compressible.";

        return result;
    }

    //======================================================================
    // 10. Linear Complexity Test (Berlekamp-Massey)
    //======================================================================

    int berlekampMassey(const std::vector<int> &s) const {
        const int n = static_cast<int>(s.size());

        std::vector<int> C(n, 0);
        std::vector<int> B(n, 0);

        C[0] = 1;
        B[0] = 1;

        int L = 0;
        int m = -1;

        for (int N = 0; N < n; N++) {
            int d = s[N];

            for (int i = 1; i <= L; i++)
                d ^= (C[i] & s[N - i]);

            if (d) {
                auto T = C;

                for (int j = 0; j < n - (N - m); j++)
                    C[N - m + j] ^= B[j];

                if (L <= N / 2) {
                    L = N + 1 - L;
                    m = N;
                    B = T;
                }
            }
        }

        return L;
    }

    TestResult runLinearComplexity() {
        TestResult result;
        result.name = "Linear Complexity Test";

        constexpr int M = 500; // block size (NIST default)
        const size_t n  = bits.size();
        const size_t N  = n / M;

        if (N == 0) {
            result.description = "Not enough data.";
            return result;
        }

        constexpr double pi[7] = {0.01047, 0.03125, 0.12500, 0.50000, 0.25000, 0.06250, 0.020833};
        std::array<int, 7> v{};

        double signM1 = (M % 2 == 0) ? -1.0 : 1.0; // (-1)^(M+1), used in mu
        double signM  = -signM1;                   // (-1)^M, used in T
        double mu     = (M / 2.0) + (9.0 + signM1) / 36.0 - ((M / 3.0) + (2.0 / 9.0)) / std::pow(2.0, static_cast<double>(M));

        for (size_t block = 0; block < N; ++block) {
            std::vector<int> s(M);

            for (int i = 0; i < M; ++i)
                s[i] = (bits[block * M + i] == '1') ? 1 : 0;

            int L    = berlekampMassey(s);
            double T = signM * (L - mu) + 2.0 / 9.0;

            int bin;

            if (T <= -2.5)
                bin = 0;
            else if (T <= -1.5)
                bin = 1;
            else if (T <= -0.5)
                bin = 2;
            else if (T <= 0.5)
                bin = 3;
            else if (T <= 1.5)
                bin = 4;
            else if (T <= 2.5)
                bin = 5;
            else
                bin = 6;

            v[bin]++;
        }

        double chi = 0.0;

        for (int i = 0; i < 7; ++i) {
            double expected = N * pi[i];
            double diff     = v[i] - expected;
            chi += diff * diff / expected;
        }

        result.statistic = chi;
        result.pValue    = igamc(3.0, chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Linear complexity values are consistent with randomness.";
        else
            result.description = "Linear complexity distribution deviates from randomness.";

        return result;
    }

    //======================================================================
    // 11. Serial Test
    //======================================================================

    double psiSquared(int m) const {
        if (m <= 0)
            return 0.0;

        const size_t n     = bits.size();
        const int patterns = 1 << m;
        std::vector<int> counts(patterns, 0);

        for (size_t i = 0; i < n; ++i) {
            int value = 0;

            for (int j = 0; j < m; ++j) {
                value <<= 1;
                size_t index = (i + j) % n;

                if (bits[index] == '1')
                    value |= 1;
            }

            counts[value]++;
        }

        double sum = 0.0;

        for (int c : counts)
            sum += static_cast<double>(c) * c;

        return (sum * patterns / n) - n;
    }

    TestResult runSerial() {
        TestResult result;
        result.name = "Serial Test";

        constexpr int m = 2; // small block length, general-purpose default
        const size_t n  = bits.size();

        if (n < static_cast<size_t>(1 << (m + 1))) {
            result.description = "Not enough data.";
            return result;
        }

        double psiM  = psiSquared(m);
        double psiM1 = psiSquared(m - 1);
        double psiM2 = psiSquared(m - 2);

        double deltaPsi  = psiM - psiM1;
        double delta2Psi = psiM - 2.0 * psiM1 + psiM2;

        double p1 = igamc(std::pow(2.0, m - 1) / 2.0, deltaPsi / 2.0);
        double p2 = igamc(std::pow(2.0, m - 2) / 2.0, delta2Psi / 2.0);

        result.statistic = deltaPsi;
        result.pValue    = std::min(p1, p2);
        result.passed    = (p1 >= 0.01 && p2 >= 0.01);

        if (result.passed)
            result.description = "Overlapping m-bit pattern frequencies are consistent with randomness.";
        else
            result.description = "Overlapping m-bit pattern frequencies deviate from randomness.";

        return result;
    }

    //======================================================================
    // 12. Approximate Entropy Test
    //======================================================================

    double phiM(int m) const {
        const size_t n     = bits.size();
        const int patterns = 1 << m;
        std::vector<int> counts(patterns, 0);

        for (size_t i = 0; i < n; i++) {
            int value = 0;

            for (int j = 0; j < m; j++) {
                value <<= 1;

                if (bits[(i + j) % n] == '1')
                    value |= 1;
            }

            counts[value]++;
        }

        double sum = 0.0;

        for (int c : counts) {
            if (c > 0) {
                double p = static_cast<double>(c) / n;
                sum += p * std::log(p);
            }
        }

        return sum;
    }

    TestResult runApproximateEntropy() {
        TestResult result;
        result.name = "Approximate Entropy Test";

        constexpr int m = 2; // small block length, general-purpose default
        const size_t n  = bits.size();

        if (n < static_cast<size_t>(1 << (m + 2))) {
            result.description = "Not enough data.";
            return result;
        }

        double apEn = phiM(m) - phiM(m + 1);
        double chi  = 2.0 * n * (std::log(2.0) - apEn);

        result.statistic = chi;
        result.pValue    = igamc(std::pow(2.0, m - 1), chi / 2.0);
        result.passed    = (result.pValue >= 0.01);

        if (result.passed)
            result.description = "Approximate entropy is consistent with randomness.";
        else
            result.description = "Approximate entropy deviates from randomness.";

        return result;
    }

    //======================================================================
    // 13. Cumulative Sums (Cusum) Test
    //======================================================================

    TestResult runCumulativeSums() {
        TestResult result;
        result.name = "Cumulative Sums Test";

        const size_t n = bits.size();

        if (n == 0) {
            result.description = "No data.";
            return result;
        }

        int sum = 0;
        int z   = 0;

        for (char bit : bits) {
            sum += (bit == '1') ? 1 : -1;
            z = std::max(z, std::abs(sum));
        }

        result.statistic = z;

        auto Phi = [](double x) {
            return 0.5 * std::erfc(-x / std::sqrt(2.0));
        };

        double nD = static_cast<double>(n);
        double zD = static_cast<double>(z);

        double p = 1.0;

        int kStart1 = static_cast<int>(std::floor((-nD / zD + 1.0) / 4.0));
        int kEnd1   = static_cast<int>(std::floor((nD / zD - 1.0) / 4.0));

        for (int k = kStart1; k <= kEnd1; k++) {
            p -= Phi((4 * k + 1) * zD / std::sqrt(nD));
            p += Phi((4 * k - 1) * zD / std::sqrt(nD));
        }

        int kStart2 = static_cast<int>(std::floor((-nD / zD - 3.0) / 4.0));
        int kEnd2   = static_cast<int>(std::floor((nD / zD - 1.0) / 4.0));

        for (int k = kStart2; k <= kEnd2; k++) {
            p += Phi((4 * k + 3) * zD / std::sqrt(nD));
            p -= Phi((4 * k + 1) * zD / std::sqrt(nD));
        }

        result.pValue = p;
        result.passed = (p >= 0.01);

        if (result.passed)
            result.description = "Random walk is consistent with randomness.";
        else
            result.description = "Random walk exhibits excessive drift.";

        return result;
    }

    //======================================================================
    // 14. Random Excursions Test
    //======================================================================

    TestResult runRandomExcursions() {
        TestResult result;
        result.name = "Random Excursions Test";

        // Build the cumulative-sum walk, padded with a 0 at both ends so
        // every excursion away from zero is bracketed by zeros.
        std::vector<int> walk;
        walk.reserve(bits.size() + 2);
        walk.push_back(0);

        int sum = 0;

        for (char bit : bits) {
            sum += (bit == '1') ? 1 : -1;
            walk.push_back(sum);
        }

        walk.push_back(0);

        // Extract cycles: the values strictly between two consecutive
        // zeros form one cycle (an "excursion").
        std::vector<std::vector<int>> cycles;
        std::vector<int> current;

        for (size_t i = 1; i < walk.size(); ++i) {
            if (walk[i] == 0) {
                if (!current.empty()) {
                    cycles.push_back(current);
                    current.clear();
                }
            } else {
                current.push_back(walk[i]);
            }
        }

        const int J = static_cast<int>(cycles.size());

        if (J < 500) {
            result.statistic   = J;
            result.description = "Insufficient cycles (need at least 500).";
            return result;
        }

        constexpr int states[8] = {-4, -3, -2, -1, 1, 2, 3, 4};

        double worst = 1.0;

        for (int x : states) {
            // v[k] = number of cycles with exactly k visits to state x
            // (k == 5 represents "5 or more visits").
            std::array<int, 6> v{};

            for (const auto &cycle : cycles) {
                int visits = 0;

                for (int value : cycle) {
                    if (value == x)
                        ++visits;
                }

                v[std::min(visits, 5)]++;
            }

            double absX = std::fabs(static_cast<double>(x));
            double p0   = 1.0 / (2.0 * absX);

            double chi = 0.0;

            for (int k = 0; k <= 5; ++k) {
                double pi;

                if (k == 0)
                    pi = 1.0 - p0;
                else if (k < 5)
                    pi = (1.0 / (4.0 * absX * absX)) * std::pow(1.0 - p0, k - 1);
                else
                    pi = p0 * std::pow(1.0 - p0, 4);

                double expected = J * pi;
                double diff     = v[k] - expected;
                chi += diff * diff / expected;
            }

            double pValue = igamc(2.5, chi / 2.0);

            if (pValue < worst)
                worst = pValue;
        }

        result.statistic = J;
        result.pValue    = worst;
        result.passed    = (worst >= 0.01);

        if (result.passed)
            result.description = "State visit frequencies across excursions are consistent with randomness.";
        else
            result.description = "State visit frequencies across excursions deviate from randomness.";

        return result;
    }

    //======================================================================
    // 15. Random Excursions Variant Test
    //======================================================================

    TestResult runRandomExcursionsVariant() {
        TestResult result;
        result.name = "Random Excursions Variant Test";

        std::vector<int> walk;
        walk.reserve(bits.size() + 1);
        walk.push_back(0);

        int sum = 0;

        for (char bit : bits) {
            sum += (bit == '1') ? 1 : -1;
            walk.push_back(sum);
        }

        int J = 0;

        for (int x : walk) {
            if (x == 0)
                ++J;
        }

        if (J < 500) {
            result.statistic   = J;
            result.description = "Insufficient cycles.";
            return result;
        }

        std::array<int, 19> visits{};

        for (int x : walk) {
            if (x >= -9 && x <= 9 && x != 0) {
                visits[x + 9]++;
            }
        }

        double worst = 1.0;

        for (int state = -9; state <= 9; ++state) {
            if (state == 0)
                continue;

            double numerator   = std::fabs(visits[state + 9] - J);
            double denominator = std::sqrt(2.0 * J * (4.0 * std::abs(state) - 2.0));
            double p           = std::erfc(numerator / denominator);

            if (p < worst)
                worst = p;
        }

        result.statistic = J;
        result.pValue    = worst;
        result.passed    = (worst >= 0.01);

        if (result.passed)
            result.description = "State visit frequencies are consistent with randomness.";
        else
            result.description = "State visit frequencies are inconsistent with randomness.";

        return result;
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

    TestNIST tester(entropy);
    tester.runAll();

    for (const auto &r : tester.getResults()) {
        std::cout << std::left << std::setw(45) << r.name << " | stat=" << std::setw(12) << r.statistic << " p=" << std::setw(10) << r.pValue << " " << (r.passed ? "PASS" : "FAIL")
                  << " (" << r.description << ")\n";
    }

    std::cout << "\nProgram finished. Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
