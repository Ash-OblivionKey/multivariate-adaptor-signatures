@echo off
REM Multivariate Witness Hiding Adaptor Signatures - Windows Runner
REM Supports: Windows (PowerShell/CMD)

setlocal enabledelayedexpansion

REM Check if Docker is available
where docker >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set DOCKER_AVAILABLE=1
) else (
    set DOCKER_AVAILABLE=0
)

REM Parse arguments
set COMMAND=
set USE_DOCKER=
set ITERATIONS=10
set CSV_FLAG=
set VERBOSE_FLAG=

:parse_args
if "%~1"=="" goto :execute
if "%~1"=="build" set COMMAND=build & shift & goto :parse_args
if "%~1"=="test" set COMMAND=test & shift & goto :parse_args
if "%~1"=="unit" set COMMAND=unit & shift & goto :parse_args
if "%~1"=="integration" set COMMAND=integration & shift & goto :parse_args
if "%~1"=="performance" set COMMAND=performance & shift & goto :parse_args
if "%~1"=="robustness" set COMMAND=robustness & shift & goto :parse_args
if "%~1"=="bench" set COMMAND=bench & shift & goto :parse_args
if "%~1"=="shell" set COMMAND=shell & shift & goto :parse_args
if "%~1"=="clean" set COMMAND=clean & shift & goto :parse_args
if "%~1"=="help" set COMMAND=help & shift & goto :parse_args
if "%~1"=="--docker" set USE_DOCKER=true & shift & goto :parse_args
if "%~1"=="--native" set USE_DOCKER=false & shift & goto :parse_args
if "%~1"=="--iterations" set ITERATIONS=%~2 & shift & shift & goto :parse_args
if "%~1"=="--csv" set CSV_FLAG=--csv & shift & goto :parse_args
if "%~1"=="--verbose" set VERBOSE_FLAG=--verbose & shift & goto :parse_args
if "%~1"=="-h" set COMMAND=help & shift & goto :parse_args
if "%~1"=="--help" set COMMAND=help & shift & goto :parse_args
echo Unknown option: %~1
goto :show_usage

:execute
if "%COMMAND%"=="" set COMMAND=help

if "%COMMAND%"=="help" goto :show_usage
if "%COMMAND%"=="build" goto :build_project
if "%COMMAND%"=="test" goto :run_tests
if "%COMMAND%"=="unit" goto :run_unit_tests
if "%COMMAND%"=="integration" goto :run_integration_tests
if "%COMMAND%"=="performance" goto :run_performance_tests
if "%COMMAND%"=="robustness" goto :run_robustness_tests
if "%COMMAND%"=="bench" goto :run_benchmarks
if "%COMMAND%"=="shell" goto :open_shell
if "%COMMAND%"=="clean" goto :clean_build

:show_usage
echo Multivariate Witness Hiding Adaptor Signatures
echo ==============================================
echo.
echo Usage: %0 [COMMAND] [OPTIONS]
echo.
echo Commands:
echo   build        Build the project (native or Docker)
echo   test         Run all tests (native or Docker)
echo   unit         Run unit tests only (fast)
echo   integration  Run integration tests only
echo   performance  Run performance tests only
echo   robustness   Run robustness tests only
echo   bench        Run benchmarks (native or Docker)
echo   shell        Open development shell (Docker)
echo   clean        Clean build artifacts
echo   help         Show this help
echo.
echo Options:
echo   --docker     Force Docker usage
echo   --native     Force native build
echo   --iterations N  Set test iterations (default: 10)
echo   --csv        Generate CSV output
echo   --verbose    Verbose output
echo.
echo Examples:
echo   %0 build                    # Build project
echo   %0 test --csv              # Run all tests with CSV output
echo   %0 unit                    # Run fast unit tests only
echo   %0 integration --csv       # Run integration tests with CSV
echo   %0 performance             # Run performance tests
echo   %0 robustness              # Run robustness tests
echo   %0 bench --iterations 100  # Run 100-iteration benchmarks
echo   %0 shell                   # Open Docker development shell
echo   %0 --docker test           # Force Docker for testing
echo.
goto :end

:build_project
if "%USE_DOCKER%"=="true" (
    echo Building with Docker...
    docker build -t multivariate-adaptor .
    echo Docker build completed!
) else if "%DOCKER_AVAILABLE%"=="1" (
    echo Building with Docker...
    docker build -t multivariate-adaptor .
    echo Docker build completed!
) else (
    echo Building natively...
    call build.bat
)
goto :end

:run_tests
if "%USE_DOCKER%"=="true" (
    echo Running tests with Docker...
    docker run --rm -v "%CD%\results:/workspace/build/results" multivariate-adaptor bash -c "cd build && echo '=== Unit Tests ===' && ./bin/test_core --scheme UOV --level 128 && ./bin/test_validation %CSV_FLAG% && ./bin/test_sizing %CSV_FLAG% && ./bin/test_witness %CSV_FLAG% && ./bin/test_utility %CSV_FLAG% && ./bin/test_boundary %CSV_FLAG% && echo '=== Integration Tests ===' && ./bin/test_integration %CSV_FLAG% && echo '=== Robustness Tests ===' && ./bin/test_negative --scheme UOV --level 128 && ./bin/test_stress %CSV_FLAG% && echo '=== Performance Tests ===' && ./bin/test_performance %CSV_FLAG% && ./bin/test_bench --iterations %ITERATIONS% %CSV_FLAG%"
    echo Docker tests completed!
) else if "%DOCKER_AVAILABLE%"=="1" (
    echo Running tests with Docker...
    docker run --rm -v "%CD%\results:/workspace/build/results" multivariate-adaptor bash -c "cd build && echo '=== Unit Tests ===' && ./bin/test_core --scheme UOV --level 128 && ./bin/test_validation %CSV_FLAG% && ./bin/test_sizing %CSV_FLAG% && ./bin/test_witness %CSV_FLAG% && ./bin/test_utility %CSV_FLAG% && ./bin/test_boundary %CSV_FLAG% && echo '=== Integration Tests ===' && ./bin/test_integration %CSV_FLAG% && echo '=== Robustness Tests ===' && ./bin/test_negative --scheme UOV --level 128 && ./bin/test_stress %CSV_FLAG% && echo '=== Performance Tests ===' && ./bin/test_performance %CSV_FLAG% && ./bin/test_bench --iterations %ITERATIONS% %CSV_FLAG%"
    echo Docker tests completed!
) else (
    echo Running tests natively...
    call build.bat
    REM Ensure results directory exists in project root
    if not exist results mkdir results
    if not exist results\unit mkdir results\unit
    if not exist results\integration mkdir results\integration
    if not exist results\performance mkdir results\performance
    if not exist results\robustness mkdir results\robustness
    echo === Unit Tests ===
    REM Run tests from project root so results are saved in correct location
    build\bin\Unit_Tests\test_core.exe --scheme UOV --level 128
    build\bin\Unit_Tests\test_validation.exe %CSV_FLAG%
    build\bin\Unit_Tests\test_sizing.exe %CSV_FLAG%
    build\bin\Unit_Tests\test_witness.exe %CSV_FLAG%
    build\bin\Unit_Tests\test_utility.exe %CSV_FLAG%
    build\bin\Unit_Tests\test_boundary.exe %CSV_FLAG%
    echo === Integration Tests ===
    build\bin\Integration_Tests\test_integration.exe %CSV_FLAG%
    echo === Robustness Tests ===
    build\bin\Robustness_Tests\test_negative.exe --scheme UOV --level 128
    build\bin\Robustness_Tests\test_stress.exe %CSV_FLAG%
    echo === Performance Tests ===
    build\bin\Performance_Tests\test_performance.exe %CSV_FLAG%
    build\bin\Performance_Tests\test_bench.exe --iterations %ITERATIONS% %CSV_FLAG%
)
goto :end

:run_unit_tests
echo Running unit tests...
call build.bat
REM Ensure results directory exists in project root
if not exist results mkdir results
if not exist results\unit mkdir results\unit
echo === Unit Tests ===
REM Run tests from project root so results are saved in correct location
build\bin\Unit_Tests\test_core.exe --scheme UOV --level 128
build\bin\Unit_Tests\test_validation.exe %CSV_FLAG%
build\bin\Unit_Tests\test_sizing.exe %CSV_FLAG%
build\bin\Unit_Tests\test_witness.exe %CSV_FLAG%
build\bin\Unit_Tests\test_utility.exe %CSV_FLAG%
build\bin\Unit_Tests\test_boundary.exe %CSV_FLAG%
goto :end

:run_integration_tests
echo Running integration tests...
call build.bat
REM Ensure results directory exists in project root
if not exist results mkdir results
if not exist results\integration mkdir results\integration
echo === Integration Tests ===
REM Run tests from project root so results are saved in correct location
build\bin\Integration_Tests\test_integration.exe %CSV_FLAG%
goto :end

:run_performance_tests
echo Running performance tests...
call build.bat
REM Ensure results directory exists in project root
if not exist results mkdir results
if not exist results\performance mkdir results\performance
echo === Performance Tests ===
REM Run tests from project root so results are saved in correct location
build\bin\Performance_Tests\test_performance.exe %CSV_FLAG%
build\bin\Performance_Tests\test_bench.exe --iterations %ITERATIONS% %CSV_FLAG%
goto :end

:run_robustness_tests
echo Running robustness tests...
call build.bat
REM Ensure results directory exists in project root
if not exist results mkdir results
if not exist results\robustness mkdir results\robustness
echo === Robustness Tests ===
REM Run tests from project root so results are saved in correct location
build\bin\Robustness_Tests\test_negative.exe --scheme UOV --level 128
build\bin\Robustness_Tests\test_stress.exe %CSV_FLAG%
goto :end

:run_benchmarks
if "%USE_DOCKER%"=="true" (
    echo Running benchmarks with Docker...
    docker run --rm -v "%CD%\results:/workspace/build/results" multivariate-adaptor bash -c "cd build && ./bin/test_bench --iterations %ITERATIONS% %CSV_FLAG% --detailed"
    echo Docker benchmarks completed!
) else if "%DOCKER_AVAILABLE%"=="1" (
    echo Running benchmarks with Docker...
    docker run --rm -v "%CD%\results:/workspace/build/results" multivariate-adaptor bash -c "cd build && ./bin/test_bench --iterations %ITERATIONS% %CSV_FLAG% --detailed"
    echo Docker benchmarks completed!
) else (
    echo Running benchmarks natively...
    call build.bat
    cd build
    .\bin\Performance_Tests\test_bench.exe --iterations %ITERATIONS% %CSV_FLAG% --detailed
    cd ..
)
goto :end

:open_shell
echo Opening Docker development shell...
docker run -it --rm -v "%CD%:/workspace" -v "%CD%\results:/workspace/build/results" multivariate-adaptor /bin/bash
goto :end

:clean_build
echo Cleaning build artifacts...
if exist build rmdir /s /q build
if exist results rmdir /s /q results
docker system prune -f 2>nul
echo Clean completed!
goto :end

:end
