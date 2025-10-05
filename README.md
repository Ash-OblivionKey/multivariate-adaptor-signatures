Multivariate Witness Hiding Adaptor Signatures for post-quantum cryptography. Extends UOV and MAYO schemes with adaptor functionality for atomic swaps and privacy-preserving protocols.

clone our project then clone liboqs
git clone https://github.com/open-quantum-safe/liboqs.git

Linux/Raspberry Pi:

cd "Multivariate Witness Hiding Adaptor Signatures"

cd liboqs

mkdir build

cd build

cmake -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON ..

make -j4

cd ../..

chmod +x build.sh

./build.sh build

Windows:

cd liboqs

mkdir build

cd build

cmake -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON ..

make -j4

cd ../..

build.bat

Individual Test Execution

cd build/bin/Unit_Tests

UOV Tests
./test_core --scheme UOV --level 128

./test_core --scheme UOV --level 192

./test_core --scheme UOV --level 256

MAYO Tests
./test_core --scheme MAYO --level 128

./test_core --scheme MAYO --level 192

./test_core --scheme MAYO --level 256

Step 1: Raw Benchmark

Normal Result

Run raw benchmark first

./build/bin/Performance_Tests/test_bench 

Rename to raw benchmark

mv benchmark_results.csv results/performance/raw_bench.csv

Step 2: 30ms Latency Test

Add 30ms latency

sudo tc qdisc add dev eth0 root netem delay 30ms

Verify latency

ping 8.8.8.8

Run benchmark

./build/bin/Performance_Tests/test_bench --iterations 1000 --warmup 10 --csv

Rename and save

mv benchmark_results.csv results/performance/latency_30ms.csv

Remove latency rule

sudo tc qdisc del dev eth0 root

Step 3: 120ms Latency Test

Add 120ms latency

sudo tc qdisc add dev eth0 root netem delay 120ms

Verify latency

ping 8.8.8.8

Run benchmark

./build/bin/Performance_Tests/test_bench --iterations 1000 --warmup 10 --csv

Rename and save

mv benchmark_results.csv results/performance/latency_120ms.csv

Remove latency rule

sudo tc qdisc del dev eth0 root

Step 4: 225ms Latency Test

Add 225ms latency

sudo tc qdisc add dev eth0 root netem delay 225ms

Verify latency

ping 8.8.8.8

Run benchmark

./build/bin/Performance_Tests/test_bench --iterations 1000 --warmup 10 --csv

Rename and save

mv benchmark_results.csv results/performance/latency_225ms.csv

Remove latency rule

sudo tc qdisc del dev eth0 root

Step 5: 320ms Latency Test

Add 320ms latency

sudo tc qdisc add dev eth0 root netem delay 320ms

Verify latency

ping 8.8.8.8

Run benchmark

./build/bin/Performance_Tests/test_bench --iterations 1000 --warmup 10 --csv

Rename and save

mv benchmark_results.csv results/performance/latency_320ms.csv

Remove latency rule

sudo tc qdisc del dev eth0 root

Generate all graphs and analysis

python3 analyze_latency_data.py

Expected Output:

results/performance/

raw_bench.csv
latency_30ms.csv
latency_120ms.csv
latency_225ms.csv
latency_320ms.csv
latency_analysis.pdf
latency_analysis.png
latency_analysis.svg
degradation_analysis.pdf
degradation_analysis.png
degradation_analysis.svg
operation_breakdown.pdf
operation_breakdown.png
operation_breakdown.svg
throughput_heatmap.pdf
throughput_heatmap.png
throughput_heatmap.svg
