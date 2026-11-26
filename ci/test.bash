#!/usr/bin/env bash
# Run the Rust tests for one target, retrying transient cross-build failures.
set -e

source ci/common.bash

# $1 {path} = Path to cross/cargo executable
CROSS=$1
# $2 {string} = <Target Triple>
TARGET_TRIPLE=$2

required_arg "$CROSS" 'CROSS'
required_arg "$TARGET_TRIPLE" '<Target Triple>'

max_attempts=3
count=1
while [ "$count" -le "$max_attempts" ]; do
    if "$CROSS" test --target "$TARGET_TRIPLE"; then
        echo "Test passed"
        exit 0
    fi
    echo "Test failed, attempt $count/$max_attempts"
    count=$((count + 1))
done

echo "Test failed after $max_attempts attempts"
exit 1
