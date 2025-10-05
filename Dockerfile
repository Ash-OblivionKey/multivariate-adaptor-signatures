# Multivariate Witness Hiding Adaptor Signatures - Universal Docker Container
# Supports: Linux, macOS, Windows (with Docker Desktop)
# Fully portable and reproducible across all platforms

FROM ubuntu:22.04

# Set environment variables for reproducibility
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libc6-dev \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set universal environment variables for reproducibility
ENV CC=gcc
ENV CXX=g++
ENV CFLAGS="-O2 -DNDEBUG -fPIC"
ENV CXXFLAGS="-O2 -DNDEBUG -fPIC"

# Set working directory
WORKDIR /workspace

# Copy project files
COPY . .

# Build liboqs
RUN cd liboqs && \
    mkdir -p build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DOQS_USE_OPENSSL=ON \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_DIST_BUILD=ON \
          .. && \
    make -j$(nproc)

# Build the project
RUN mkdir -p build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Create results directory
RUN mkdir -p build/results

# Set default command
CMD ["/bin/bash"]

# Labels for metadata
LABEL maintainer="Post-Quantum Cryptography Research Team"
LABEL description="Multivariate Witness Hiding Adaptor Signatures"
LABEL version="1.0.0"
LABEL platform="universal"
