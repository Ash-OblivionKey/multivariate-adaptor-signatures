#!/bin/bash

# Multivariate Witness Hiding Adaptor Signatures - Universal Build Script
# Supports: Linux, macOS, FreeBSD, Windows (WSL/Git Bash), and other Unix-like systems
# Research version with timing attack mitigation removed for reliable benchmarking

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM="Linux";;
        Darwin*)    PLATFORM="macOS";;
        FreeBSD*)   PLATFORM="FreeBSD";;
        OpenBSD*)   PLATFORM="OpenBSD";;
        NetBSD*)    PLATFORM="NetBSD";;
        *)          PLATFORM="Unknown";;
    esac
    echo "Detected platform: $PLATFORM"
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
        missing_tools+=("C compiler (gcc or clang)")
    fi
    
    if ! command -v cmake &> /dev/null; then
        missing_tools+=("cmake")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_tools+=("make")
    fi
    
    if ! command -v pkg-config &> /dev/null; then
        missing_tools+=("pkg-config")
    fi
    
    # Check for OpenSSL
    if ! pkg-config --exists openssl; then
        missing_tools+=("OpenSSL development libraries")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        echo ""
        echo "Install instructions:"
        case "$PLATFORM" in
            "Linux")
                echo "  Ubuntu/Debian: sudo apt-get install build-essential cmake pkg-config libssl-dev"
                echo "  CentOS/RHEL:   sudo yum install gcc cmake pkgconfig openssl-devel"
                echo "  Arch Linux:    sudo pacman -S base-devel cmake pkg-config openssl"
                ;;
            "macOS")
                echo "  Install Xcode Command Line Tools: xcode-select --install"
                echo "  Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                echo "  Install dependencies: brew install cmake pkg-config openssl"
                ;;
            "FreeBSD")
                echo "  sudo pkg install gcc cmake pkgconf openssl"
                ;;
        esac
        exit 1
    fi
    
    echo -e "${GREEN}All dependencies found!${NC}"
}

# Build liboqs if not present
build_liboqs() {
    if [ ! -d "liboqs/build" ] || [ ! -f "liboqs/build/lib/liboqs.a" ]; then
        echo -e "${YELLOW}Building liboqs...${NC}"
        
        cd liboqs
        mkdir -p build
        cd build
        
        # Configure liboqs
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DOQS_USE_OPENSSL=ON \
              -DOQS_BUILD_ONLY_LIB=ON \
              -DOQS_DIST_BUILD=ON \
              ..
        
        # Build liboqs
        make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
        
        cd ../..
        echo -e "${GREEN}liboqs built successfully!${NC}"
    else
        echo -e "${GREEN}liboqs already built!${NC}"
    fi
}

# Build the project
build_project() {
    echo -e "${BLUE}Building Multivariate Adaptor Signatures...${NC}"
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure with CMake
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          ..
    
    # Build
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    # Create results directory
    mkdir -p results
    
    cd ..
    echo -e "${GREEN}Build completed successfully!${NC}"
}

# Run tests
run_tests() {
    echo -e "${BLUE}Running tests...${NC}"
    
    cd build
    
    # Run individual tests
    echo -e "${YELLOW}Running unit tests...${NC}"
    ./bin/Unit_Tests/test_core --scheme UOV --level 128
    ./bin/Unit_Tests/test_validation --csv
    ./bin/Unit_Tests/test_sizing --csv
    ./bin/Unit_Tests/test_witness --csv
    ./bin/Unit_Tests/test_utility --csv
    ./bin/Unit_Tests/test_boundary --csv
    
    echo -e "${YELLOW}Running integration tests...${NC}"
    ./bin/Integration_Tests/test_integration --csv
    
    echo -e "${YELLOW}Running robustness tests...${NC}"
    ./bin/Robustness_Tests/test_negative --scheme UOV --level 128
    ./bin/Robustness_Tests/test_stress --csv
    
    echo -e "${YELLOW}Running performance tests...${NC}"
    ./bin/Performance_Tests/test_performance --csv
    ./bin/Performance_Tests/test_bench --iterations 10 --csv
    
    cd ..
    echo -e "${GREEN}All tests completed!${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  build     Build the project only"
    echo "  test      Run tests only (requires build)"
    echo "  all       Build and run tests (default)"
    echo "  clean     Clean build directory"
    echo "  deps      Check dependencies only"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                # Build and test everything"
    echo "  $0 build          # Build only"
    echo "  $0 test           # Test only"
    echo "  $0 clean          # Clean build"
    echo ""
}

# Clean build directory
clean_build() {
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf build
    echo -e "${GREEN}Clean completed!${NC}"
}

# Main function
main() {
    echo -e "${BLUE}Multivariate Witness Hiding Adaptor Signatures${NC}"
    echo -e "${BLUE}==============================================${NC}"
    echo ""
    
    # Detect platform
    detect_platform
    
    # Parse command line arguments
    case "${1:-all}" in
        "build")
            check_dependencies
            build_liboqs
            build_project
            ;;
        "test")
            if [ ! -d "build" ]; then
                echo -e "${RED}Build directory not found. Run '$0 build' first.${NC}"
                exit 1
            fi
            run_tests
            ;;
        "all")
            check_dependencies
            build_liboqs
            build_project
            run_tests
            ;;
        "clean")
            clean_build
            ;;
        "deps")
            check_dependencies
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Done!${NC}"
}

# Run main function with all arguments
main "$@"
