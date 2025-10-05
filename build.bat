@echo off
echo Building Multivariate Witness Hiding Adaptor Signatures
echo ========================================================

REM Check for CMake first (preferred method)
where cmake >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Using CMake build system...
    goto :cmake_build
)

REM Fallback to manual build
echo Using manual build system...
goto :manual_build

:cmake_build
REM Check dependencies
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: GCC not found. Please install MinGW-w64 or use Visual Studio.
    exit /b 1
)

REM Build liboqs if needed
if not exist "liboqs\build\lib\liboqs.a" (
    echo Building liboqs...
    cd liboqs
    if not exist build mkdir build
    cd build
    cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DOPENSSL_ROOT_DIR=C:/msys64/ucrt64 ..
    cmake --build . --config Release
    cd ..\..
) else (
    echo Using existing liboqs build...
)

REM Configure and build project
if not exist build mkdir build
cd build
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=C:/msys64/ucrt64 ..
cmake --build . --config Release
cd ..

echo.
echo CMake build completed successfully!
echo.
echo Available executables (organized by category):
echo.
echo Unit Tests:
echo   - build\bin\Unit_Tests\test_core.exe
echo   - build\bin\Unit_Tests\test_validation.exe
echo   - build\bin\Unit_Tests\test_sizing.exe
echo   - build\bin\Unit_Tests\test_witness.exe
echo   - build\bin\Unit_Tests\test_utility.exe
echo   - build\bin\Unit_Tests\test_boundary.exe
echo.
echo Integration Tests:
echo   - build\bin\Integration_Tests\test_integration.exe
echo.
echo Performance Tests:
echo   - build\bin\Performance_Tests\test_performance.exe
echo   - build\bin\Performance_Tests\test_bench.exe
echo.
echo Robustness Tests:
echo   - build\bin\Robustness_Tests\test_negative.exe
echo   - build\bin\Robustness_Tests\test_stress.exe
echo.
goto :end

:manual_build
REM Set compiler flags for robust compilation
set CFLAGS=-Wall -Wextra -O2 -g -std=c99 -DADAPTOR_DISABLE_UNUSED_FUNCTIONS -DBENCHMARK_DISABLE_UNUSED_FUNCTIONS
set LDFLAGS=-mconsole -Wl,--subsystem,console
set INCLUDES=-I./src/interfaces -I./src/implementations -I./src/utils -I./liboqs/build/include
set LIBDIRS=-L./liboqs/build/lib
set LIBS=-loqs -lssl -lcrypto

REM Create build directory and organized results subdirectories in project root
if not exist build mkdir build
if not exist results mkdir results
if not exist results\unit mkdir results\unit
if not exist results\integration mkdir results\integration
if not exist results\performance mkdir results\performance
if not exist results\robustness mkdir results\robustness

REM Create build directories only (no results directories in build)
if not exist build\bin mkdir build\bin
if not exist build\bin\Unit_Tests mkdir build\bin\Unit_Tests
if not exist build\bin\Integration_Tests mkdir build\bin\Integration_Tests
if not exist build\bin\Performance_Tests mkdir build\bin\Performance_Tests
if not exist build\bin\Robustness_Tests mkdir build\bin\Robustness_Tests

echo Compiling core implementation...
gcc %CFLAGS% %INCLUDES% -c src/implementations/multivariate_adaptor.c -o build/multivariate_adaptor.o
if errorlevel 1 goto error

echo Compiling CSV utilities...
gcc %CFLAGS% %INCLUDES% -c src/utils/csv_utils.c -o build/csv_utils.o
if errorlevel 1 goto error


echo.
echo Building consolidated test suite...
echo ==================================

echo Compiling test_core.c (Fast CI correctness tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_core.c" -o build/test_core.o
if errorlevel 1 goto error

echo Compiling test_negative.c (Robustness and security validation)...
gcc %CFLAGS% %INCLUDES% -c "tests/Robustness Tests/test_negative.c" -o build/test_negative.o
if errorlevel 1 goto error

echo Compiling test_integration.c (Multi-config integration testing)...
gcc %CFLAGS% %INCLUDES% -c "tests/Integration Tests/test_integration.c" -o build/test_integration.o
if errorlevel 1 goto error

echo Compiling test_validation.c (Parameter validation tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_validation.c" -o build/test_validation.o
if errorlevel 1 goto error

echo Compiling test_sizing.c (Size calculation tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_sizing.c" -o build/test_sizing.o
if errorlevel 1 goto error

echo Compiling test_witness.c (Witness verification tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_witness.c" -o build/test_witness.o
if errorlevel 1 goto error
echo Compiling test_utility.c (Utility function tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_utility.c" -o build/test_utility.o
if errorlevel 1 goto error
echo Compiling test_boundary.c (Boundary condition tests)...
gcc %CFLAGS% %INCLUDES% -c "tests/Unit Tests/test_boundary.c" -o build/test_boundary.o
if errorlevel 1 goto error
echo Compiling test_stress.c (Stress testing)...
gcc %CFLAGS% %INCLUDES% -c "tests/Robustness Tests/test_stress.c" -o build/test_stress.o
if errorlevel 1 goto error
echo Compiling test_performance.c (Performance profiling)...
gcc %CFLAGS% %INCLUDES% -c "tests/Performance Tests/test_performance.c" -o build/test_performance.o
if errorlevel 1 goto error


echo Compiling test_bench.c (Performance benchmarking and research)...
gcc %CFLAGS% %INCLUDES% -c "tests/Performance Tests/test_bench.c" -o build/test_bench.o
if errorlevel 1 goto error

echo.
echo Linking test executables...
echo ==========================

echo Linking test_core.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_core.exe build/test_core.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo Linking test_negative.exe...
gcc %LDFLAGS% -o build\bin\Robustness_Tests\test_negative.exe build/test_negative.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo Linking test_integration.exe...
gcc %LDFLAGS% -o build\bin\Integration_Tests\test_integration.exe build/test_integration.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo Linking test_validation.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_validation.exe build/test_validation.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo Linking test_sizing.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_sizing.exe build/test_sizing.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo Linking test_witness.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_witness.exe build/test_witness.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error
echo Linking test_utility.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_utility.exe build/test_utility.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error
echo Linking test_boundary.exe...
gcc %LDFLAGS% -o build\bin\Unit_Tests\test_boundary.exe build/test_boundary.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error
echo Linking test_stress.exe...
gcc %LDFLAGS% -o build\bin\Robustness_Tests\test_stress.exe build/test_stress.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error
echo Linking test_performance.exe...
gcc %LDFLAGS% -o build\bin\Performance_Tests\test_performance.exe build/test_performance.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error


echo Linking test_bench.exe...
gcc %LDFLAGS% -o build\bin\Performance_Tests\test_bench.exe build/test_bench.o build/multivariate_adaptor.o build/csv_utils.o %LIBDIRS% %LIBS%
if errorlevel 1 goto error

echo.
echo Build completed successfully!
echo.
echo Available executables (11 modular tests):
echo   - build/test_core.exe (CORRECTNESS: Fast CI correctness tests T1-T8)
echo   - build/test_negative.exe (ROBUSTNESS: Security validation tests N1-N7)
echo   - build/test_integration.exe (INTEGRATION: Multi-config testing T1-T8)
echo   - build/test_validation.exe (VALIDATION: Parameter validation tests T9-T11)
echo   - build/test_sizing.exe (SIZING: Size calculation tests T12-T14)
echo   - build/test_witness.exe (WITNESS: Witness verification tests T15-T16)
echo   - build/test_utility.exe (UTILITY: Utility function tests T17-T18)
echo   - build/test_boundary.exe (BOUNDARY: Boundary condition tests T19)
echo   - build/test_stress.exe (STRESS: Stress testing T20)
echo   - build/test_performance.exe (PERFORMANCE: Performance profiling T21-T22)
echo   - build/test_bench.exe (BENCHMARK: Performance benchmarking and research)
echo.
echo Modular Test Architecture:
echo   - Each test focuses on specific functionality
echo   - Fast execution with focused test coverage
echo   - Clean separation of concerns
echo   - Individual test execution and analysis
echo   - Comprehensive coverage: T1-T8, T9-T11, T12-T14, T15-T16, T17-T18, T19, T20, T21-T22, N1-N7
echo   - Performance profiling and research capabilities
echo.
echo Test Usage:
echo   Fast CI (correctness only):
echo     .\build\bin\Unit_Tests\test_core.exe --scheme UOV --level 128
echo.
echo   Comprehensive testing:
echo     .\build\bin\Robustness_Tests\test_negative.exe --scheme UOV --level 128
echo     .\build\bin\Integration_Tests\test_integration.exe --csv
echo     .\build\bin\Unit_Tests\test_validation.exe --csv
echo     .\build\bin\Unit_Tests\test_sizing.exe --csv
echo     .\build\bin\Unit_Tests\test_witness.exe --csv
echo     .\build\bin\Unit_Tests\test_utility.exe --csv
echo     .\build\bin\Unit_Tests\test_boundary.exe --csv
echo     .\build\bin\Robustness_Tests\test_stress.exe --csv
echo     .\build\bin\Performance_Tests\test_performance.exe --csv
echo     .\build\bin\Performance_Tests\test_bench.exe --iterations 100 --csv
echo.
echo   Individual test execution:
echo     .\build\bin\Unit_Tests\test_core.exe --scheme UOV --level 128
echo     .\build\bin\Robustness_Tests\test_negative.exe --scheme UOV --level 128
echo     .\build\bin\Integration_Tests\test_integration.exe --csv
echo     .\build\bin\Unit_Tests\test_validation.exe --csv
echo     .\build\bin\Unit_Tests\test_sizing.exe --csv
echo     .\build\bin\Unit_Tests\test_witness.exe --csv
echo     .\build\bin\Unit_Tests\test_utility.exe --csv
echo     .\build\bin\Unit_Tests\test_boundary.exe --csv
echo     .\build\bin\Performance_Tests\test_bench.exe --iterations 100 --csv
echo.
echo   Output files will be saved to:
echo     results\unit\core-*.json (test_core)
echo     results\unit\validation-*.csv (test_validation)
echo     results\unit\sizing-*.csv (test_sizing)
echo     results\unit\witness-*.csv (test_witness)
echo     results\unit\utility-*.csv (test_utility)
echo     results\unit\boundary-*.csv (test_boundary)
echo     results\integration\integration-*.csv (test_integration)
echo     results\robustness\stress-*.csv (test_stress)
echo     results\performance\performance-*.csv (test_performance)
echo     results\performance\bench-*.csv (test_bench)
echo.
echo   Note: Run tests from the project root directory for proper output paths
echo.
echo   All schemes and levels:
echo     .\build\bin\Integration_Tests\test_integration.exe
echo     .\build\bin\Performance_Tests\test_bench.exe --iterations 50
echo.
echo   Complete test suite execution:
echo     .\build\bin\Unit_Tests\test_core.exe --scheme UOV --level 128
echo     .\build\bin\Robustness_Tests\test_negative.exe --scheme UOV --level 128
echo     .\build\bin\Integration_Tests\test_integration.exe --csv
echo     .\build\bin\Unit_Tests\test_validation.exe --csv
echo     .\build\bin\Unit_Tests\test_sizing.exe --csv
echo     .\build\bin\Unit_Tests\test_witness.exe --csv
echo     .\build\bin\Unit_Tests\test_utility.exe --csv
echo     .\build\bin\Unit_Tests\test_boundary.exe --csv
echo     .\build\bin\Robustness_Tests\test_stress.exe --csv
echo     .\build\bin\Performance_Tests\test_performance.exe --csv
echo     .\build\bin\Performance_Tests\test_bench.exe --iterations 100 --csv
echo.
echo   Help for each test:
echo     .\build\bin\Unit_Tests\test_core.exe --help
echo     .\build\bin\Robustness_Tests\test_negative.exe --help
echo     .\build\bin\Integration_Tests\test_integration.exe --help
echo     .\build\bin\Unit_Tests\test_validation.exe --help
echo     .\build\bin\Unit_Tests\test_sizing.exe --help
echo     .\build\bin\Unit_Tests\test_witness.exe --help
echo     .\build\bin\Unit_Tests\test_utility.exe --help
echo     .\build\bin\Unit_Tests\test_boundary.exe --help
echo     .\build\bin\Robustness_Tests\test_stress.exe --help
echo     .\build\bin\Performance_Tests\test_performance.exe --help
echo     .\build\bin\Performance_Tests\test_bench.exe --help
echo.
echo   Note: test_sizing.exe tests size calculations and memory layout
echo         - T12: Key size calculations (secret key, public key, signature sizes)
echo         - T13: Buffer size validation (minimum/maximum buffer requirements)
echo         - T14: Memory layout verification (struct sizes, alignment, constraints)
echo.
echo   Note: test_witness.exe tests witness generation and extraction
echo         - T15: Witness generation and validation (witness creation, verification, binding)
echo         - T16: Witness extraction and recovery (extraction from signatures, integrity checks)
echo.
echo   Note: test_utility.exe tests utility and helper functions
echo         - T17: Utility function validation (scheme descriptions, error strings, validation)
echo         - T18: Helper function testing (memory management, string handling, cleanup)
echo.
echo   Note: test_boundary.exe tests boundary conditions and edge cases
echo         - T19: Boundary condition testing (edge cases, limits, extreme values)
echo.
echo   Note: test_stress.exe tests system stability under extreme conditions
echo         - T20: Stress testing (high iterations, memory pressure, resource exhaustion)
echo.
echo   Note: test_performance.exe tests performance characteristics and optimization
echo         - T21: Performance profiling (CPU usage, operations per second, efficiency)
echo         - T22: Memory profiling (peak memory, average memory, leak detection)
echo.
echo.
echo   Current Test Coverage Summary:
echo     - T1-T8: Core workflow tests (test_integration.c)
echo     - T9-T11: Parameter validation tests (test_validation.c)
echo     - T12-T14: Size calculation tests (test_sizing.c)
echo     - T15-T16: Witness verification tests (test_witness.c)
echo     - T17-T18: Utility function tests (test_utility.c)
echo     - T19: Boundary condition tests (test_boundary.c)
echo     - T20: Stress testing (test_stress.c)
echo     - T21-T22: Performance profiling (test_performance.c)
echo     - N1-N7: Negative/robustness tests (test_negative.c)
echo     - Performance: Benchmarking and research (test_bench.c)
echo     - Fast CI: Quick correctness tests (test_core.c)
echo.
goto end

:error
echo.
echo Build failed! Please check the error messages above.
exit /b 1

:end