# Multivariate Witness Hiding Adaptor Signatures (MWAS)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](build.bat)
[![Research](https://img.shields.io/badge/type-research-orange.svg)](README.md)

A research implementation of Multivariate Witness Hiding Adaptor Signatures (MWAS) extending UOV and MAYO post-quantum signature schemes with adaptor functionality. 

## Overview

This project implements a novel cryptographic primitive that combines multivariate cryptography (UOV and MAYO schemes), witness hiding properties, adaptor signature functionality, and post-quantum security guarantees. The implementation provides comprehensive testing, benchmarking, and performance analysis tools for evaluating the schemes under various network conditions.

## Architecture

```
src/
├── implementations/     # Core cryptographic implementations
├── interfaces/         # Public API definitions
└── utils/             # Utility functions and helpers

tests/
├── Unit Tests/        # Core functionality tests
├── Integration Tests/ # End-to-end workflow tests
├── Performance Tests/ # Benchmarking and profiling
└── Robustness Tests/  # Stress and negative testing

results/
├── performance/       # Benchmark results and analysis
├── unit/             # Unit test results
├── integration/      # Integration test results
└── robustness/       # Robustness test results
```

## Prerequisites

- CMake 3.16 or higher
- GCC/Clang with C99 support
- OpenSSL for cryptographic operations
- Python 3 for analysis scripts
- Docker (optional, for containerized builds)

## Installation

> **Recommended**: We suggest using Linux for the best compatibility and performance. Docker may have limitations with certain cryptographic operations and network latency testing.

### Linux/Raspberry Pi

```bash
git clone https://github.com/Ash-OblivionKey/multivariate-adaptor-signatures.git
cd "Multivariate Witness Hiding Adaptor Signatures"

# Clone liboqs dependency
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DOQS_USE_OPENSSL=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON ..
make -j4
cd ../..

./build.sh build
```

### Windows

```cmd
git clone https://github.com/Ash-OblivionKey/multivariate-adaptor-signatures.git
cd "Multivariate Witness Hiding Adaptor Signatures"

# Clone liboqs dependency
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON ..
make -j4
cd ../..

build.bat
```

### Docker

```bash
docker-compose up --build
```

## Testing

### Unit Tests

```bash
cd build/bin/Unit_Tests

# UOV Tests
./test_core --scheme UOV --level 128
./test_core --scheme UOV --level 192
./test_core --scheme UOV --level 256

# MAYO Tests
./test_core --scheme MAYO --level 128
./test_core --scheme MAYO --level 192
./test_core --scheme MAYO --level 256
```

### Integration Tests

```bash
cd build/bin/Integration_Tests
./test_integration
```

### Performance Tests

```bash
cd build/bin/Performance_Tests
./test_bench --iterations 1000 --warmup 10 --csv
```

## Performance Analysis

### Baseline Benchmark

```bash
./build/bin/Performance_Tests/test_bench
mv benchmark_results.csv results/performance/raw_bench.csv
```

### Latency Testing

For each latency level (30ms, 120ms, 225ms, 320ms):

```bash
# Add network latency (Linux only)
sudo tc qdisc add dev eth0 root netem delay 30ms

# Verify latency
ping 8.8.8.8

# Run benchmark
./build/bin/Performance_Tests/test_bench --iterations 1000 --warmup 10 --csv

# Save results
mv benchmark_results.csv results/performance/latency_30ms.csv

# Remove latency rule
sudo tc qdisc del dev eth0 root
```

### Analysis Generation

```bash
python3 analyze_latency_data.py
```

## Configuration

### Security Levels

- Level 128: NIST Level 1 equivalent
- Level 192: NIST Level 3 equivalent  
- Level 256: NIST Level 5 equivalent

### Supported Schemes

- UOV: Unbalanced Oil and Vinegar
- MAYO: Multivariate Asymmetric Yet Optimized

## Research Context

This implementation is part of ongoing research into post-quantum cryptographic primitives. The adaptor signature functionality enables atomic swaps in blockchain applications, payment channels with dispute resolution, cross-chain interoperability protocols, and privacy-preserving transaction schemes.


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is a research implementation and should not be used in production systems. The code is provided for educational and research purposes only.

