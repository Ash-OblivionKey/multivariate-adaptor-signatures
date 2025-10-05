#!/bin/bash

# Multivariate Witness Hiding Adaptor Signatures - Universal Runner
# Supports: Linux, macOS, Windows (with WSL/Git Bash)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if Docker is available
check_docker() {
    if command -v docker &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Show usage
show_usage() {
    echo -e "${BLUE}Multivariate Witness Hiding Adaptor Signatures${NC}"
    echo -e "${BLUE}==============================================${NC}"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  build        Build the project (native or Docker)"
    echo "  test         Run all tests (native or Docker)"
    echo "  unit         Run unit tests only (fast)"
    echo "  integration  Run integration tests only"
    echo "  performance  Run performance tests only"
    echo "  robustness   Run robustness tests only"
    echo "  bench        Run benchmarks (native or Docker)"
    echo "  shell        Open development shell (Docker)"
    echo "  clean        Clean build artifacts"
    echo "  help         Show this help"
    echo ""
    echo "Options:"
    echo "  --docker     Force Docker usage"
    echo "  --native     Force native build"
    echo "  --iterations N  Set test iterations (default: 10)"
    echo "  --csv        Generate CSV output"
    echo "  --verbose    Verbose output"
    echo ""
    echo "Examples:"
    echo "  $0 build                    # Build project"
    echo "  $0 test --csv              # Run all tests with CSV output"
    echo "  $0 unit                    # Run fast unit tests only"
    echo "  $0 integration --csv       # Run integration tests with CSV"
    echo "  $0 performance             # Run performance tests"
    echo "  $0 robustness              # Run robustness tests"
    echo "  $0 bench --iterations 100  # Run 100-iteration benchmarks"
    echo "  $0 shell                   # Open Docker development shell"
    echo "  $0 --docker test           # Force Docker for testing"
    echo ""
}

# Build project
build_project() {
    local use_docker=$1
    
    if [ "$use_docker" = "true" ] || (! check_docker && [ "$use_docker" != "false" ]); then
        echo -e "${BLUE}Building with Docker...${NC}"
        docker build -t multivariate-adaptor .
        echo -e "${GREEN}Docker build completed!${NC}"
    else
        echo -e "${BLUE}Building natively...${NC}"
        if [ -f "build.sh" ]; then
            chmod +x build.sh
            ./build.sh build
        else
            echo -e "${RED}build.sh not found. Please ensure you're in the project root.${NC}"
            exit 1
        fi
    fi
}

# Run tests
run_tests() {
    local use_docker=$1
    local iterations=${2:-10}
    local csv_flag=$3
    local verbose_flag=$4
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    if [ "$use_docker" = "true" ] || (! check_docker && [ "$use_docker" != "false" ]); then
        echo -e "${BLUE}Running tests with Docker...${NC}"
        docker run --rm \
            -v "$(pwd)/results:/workspace/build/results" \
            multivariate-adaptor \
            bash -c "
                cd build &&
                echo '=== Unit Tests ===' &&
                ./bin/test_core --scheme UOV --level 128 &&
                ./bin/test_validation $test_args &&
                ./bin/test_sizing $test_args &&
                ./bin/test_witness $test_args &&
                ./bin/test_utility $test_args &&
                ./bin/test_boundary $test_args &&
                echo '=== Integration Tests ===' &&
                ./bin/test_integration $test_args &&
                echo '=== Robustness Tests ===' &&
                ./bin/test_negative --scheme UOV --level 128 &&
                ./bin/test_stress $test_args &&
                echo '=== Performance Tests ===' &&
                ./bin/test_performance $test_args &&
                ./bin/test_bench --iterations $iterations $test_args
            "
        echo -e "${GREEN}Docker tests completed!${NC}"
    else
        echo -e "${BLUE}Running tests natively...${NC}"
        if [ -f "build.sh" ]; then
            chmod +x build.sh
            ./build.sh test
        else
            echo -e "${RED}build.sh not found. Please ensure you're in the project root.${NC}"
            exit 1
        fi
    fi
}

# Run unit tests
run_unit_tests() {
    local use_docker=$1
    local csv_flag=$2
    local verbose_flag=$3
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    echo -e "${BLUE}Running unit tests...${NC}"
    if [ -f "build.sh" ]; then
        chmod +x build.sh
        ./build.sh build
    fi
    
    cd build
    echo -e "${YELLOW}=== Unit Tests ===${NC}"
    ./test_core --scheme UOV --level 128
    ./test_validation $test_args
    ./test_sizing $test_args
    ./test_witness $test_args
    ./test_utility $test_args
    ./test_boundary $test_args
    cd ..
    echo -e "${GREEN}Unit tests completed!${NC}"
}

# Run integration tests
run_integration_tests() {
    local use_docker=$1
    local csv_flag=$2
    local verbose_flag=$3
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    echo -e "${BLUE}Running integration tests...${NC}"
    if [ -f "build.sh" ]; then
        chmod +x build.sh
        ./build.sh build
    fi
    
    cd build
    echo -e "${YELLOW}=== Integration Tests ===${NC}"
    ./test_integration $test_args
    cd ..
    echo -e "${GREEN}Integration tests completed!${NC}"
}

# Run performance tests
run_performance_tests() {
    local use_docker=$1
    local iterations=${2:-100}
    local csv_flag=$3
    local verbose_flag=$4
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    echo -e "${BLUE}Running performance tests...${NC}"
    if [ -f "build.sh" ]; then
        chmod +x build.sh
        ./build.sh build
    fi
    
    cd build
    echo -e "${YELLOW}=== Performance Tests ===${NC}"
    ./test_performance $test_args
    ./test_bench --iterations $iterations $test_args
    cd ..
    echo -e "${GREEN}Performance tests completed!${NC}"
}

# Run robustness tests
run_robustness_tests() {
    local use_docker=$1
    local csv_flag=$2
    local verbose_flag=$3
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    echo -e "${BLUE}Running robustness tests...${NC}"
    if [ -f "build.sh" ]; then
        chmod +x build.sh
        ./build.sh build
    fi
    
    cd build
    echo -e "${YELLOW}=== Robustness Tests ===${NC}"
    ./test_negative --scheme UOV --level 128
    ./test_stress $test_args
    cd ..
    echo -e "${GREEN}Robustness tests completed!${NC}"
}

# Run benchmarks
run_benchmarks() {
    local use_docker=$1
    local iterations=${2:-100}
    local csv_flag=$3
    local verbose_flag=$4
    
    local test_args=""
    if [ "$csv_flag" = "true" ]; then
        test_args="$test_args --csv"
    fi
    if [ "$verbose_flag" = "true" ]; then
        test_args="$test_args --verbose"
    fi
    
    if [ "$use_docker" = "true" ] || (! check_docker && [ "$use_docker" != "false" ]); then
        echo -e "${BLUE}Running benchmarks with Docker...${NC}"
        docker run --rm \
            -v "$(pwd)/results:/workspace/build/results" \
            multivariate-adaptor \
            bash -c "
                cd build &&
                ./bin/test_bench --iterations $iterations $test_args --detailed
            "
        echo -e "${GREEN}Docker benchmarks completed!${NC}"
    else
        echo -e "${BLUE}Running benchmarks natively...${NC}"
        if [ -f "build.sh" ]; then
            chmod +x build.sh
            ./build.sh test
        else
            echo -e "${RED}build.sh not found. Please ensure you're in the project root.${NC}"
            exit 1
        fi
    fi
}

# Open development shell
open_shell() {
    echo -e "${BLUE}Opening Docker development shell...${NC}"
    docker run -it --rm \
        -v "$(pwd):/workspace" \
        -v "$(pwd)/results:/workspace/build/results" \
        multivariate-adaptor \
        /bin/bash
}

# Clean build artifacts
clean_build() {
    echo -e "${YELLOW}Cleaning build artifacts...${NC}"
    rm -rf build
    rm -rf results
    docker system prune -f 2>/dev/null || true
    echo -e "${GREEN}Clean completed!${NC}"
}

# Main function
main() {
    local command=""
    local use_docker=""
    local iterations=10
    local csv_flag="false"
    local verbose_flag="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            build|test|unit|integration|performance|robustness|bench|shell|clean|help)
                command="$1"
                shift
                ;;
            --docker)
                use_docker="true"
                shift
                ;;
            --native)
                use_docker="false"
                shift
                ;;
            --iterations)
                iterations="$2"
                shift 2
                ;;
            --csv)
                csv_flag="true"
                shift
                ;;
            --verbose)
                verbose_flag="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Default command
    if [ -z "$command" ]; then
        command="help"
    fi
    
    # Execute command
    case "$command" in
        "build")
            build_project "$use_docker"
            ;;
        "test")
            run_tests "$use_docker" "$iterations" "$csv_flag" "$verbose_flag"
            ;;
        "unit")
            run_unit_tests "$use_docker" "$csv_flag" "$verbose_flag"
            ;;
        "integration")
            run_integration_tests "$use_docker" "$csv_flag" "$verbose_flag"
            ;;
        "performance")
            run_performance_tests "$use_docker" "$iterations" "$csv_flag" "$verbose_flag"
            ;;
        "robustness")
            run_robustness_tests "$use_docker" "$csv_flag" "$verbose_flag"
            ;;
        "bench")
            run_benchmarks "$use_docker" "$iterations" "$csv_flag" "$verbose_flag"
            ;;
        "shell")
            open_shell
            ;;
        "clean")
            clean_build
            ;;
        "help")
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown command: $command${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
