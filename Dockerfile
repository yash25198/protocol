# Use the official NVIDIA CUDA base image
FROM nvidia/cuda:12.2.0-devel-ubuntu22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    RUST_VERSION=1.81.0 \
    RISCV_TOOLCHAIN_DIR=/opt/riscv

# Update system and install Ubuntu dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    autotools-dev \
    curl \
    python3 \
    python3-pip \
    libmpc-dev \
    libmpfr-dev \
    libgmp-dev \
    gawk \
    build-essential \
    bison \
    flex \
    texinfo \
    gperf \
    libtool \
    patchutils \
    bc \
    zlib1g-dev \
    libexpat-dev \
    ninja-build \
    git \
    cmake \
    libglib2.0-dev \
    libslirp-dev \
    clang-15 \
    llvm-15 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"

# Clone and build the RISC-V GNU toolchain
RUN git clone https://github.com/riscv-collab/riscv-gnu-toolchain && \
    cd riscv-gnu-toolchain && \
    git checkout 7d8e9ad50d931262cb1403cd97fce674a4086264 && \
    ./configure --prefix="${RISCV_TOOLCHAIN_DIR}" --with-arch=rv32im && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf riscv-gnu-toolchain

# Set up environment for RISC-V toolchain
ENV PATH="${RISCV_TOOLCHAIN_DIR}/bin:${PATH}"

# Default command
RUN |1 TARGETARCH=amd64 /bin/sh -c apt-get update && apt-get install -y --no-install-recommends     ${NV_CUDNN_PACKAGE}     ${NV_CUDNN_PACKAGE_DEV}     && apt-mark hold ${NV_CUDNN_PACKAGE_NAME}     && rm -rf /var/lib/apt/lists/* # buildkit
