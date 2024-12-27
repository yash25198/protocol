#!/bin/bash

# Helper script to compile contract artifacts and move them to artifacts/ dir 

# Compile contracts
(forge build)

# Clean and create artifacts directory
mkdir -p artifacts
rm -rf artifacts/*

# Copy compiled artifacts
cp out/RiftExchange.sol/RiftExchange.json artifacts/
cp out/MockToken.sol/MockToken.json artifacts/