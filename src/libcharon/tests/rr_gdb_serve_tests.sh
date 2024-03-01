#!/bin/bash

# Define the root of the project directory
PROJECT_ROOT="/home/xad/code/strongswan"

# Define the path to the exchange_tests binary
EXCHANGE_TESTS_BINARY="$PROJECT_ROOT/build/src/libcharon/tests/.libs/exchange_tests"

# Check if the exchange_tests binary exists
if [ ! -f "$EXCHANGE_TESTS_BINARY" ]; then
    echo "Test Suites target is not built yet, try invoke 'make -j$(nproc)'"
    # Optionally, you can uncomment the following line to build it automatically
    # cd "$PROJECT_ROOT" && make -j"$(nproc)"
    exit 1
fi

TESTS_SUITES="ike rekey"
TESTS_CASES="regular"
#TESTS_VERBOSITY="4"  # todo> fix this

# Call the rr record command
sudo sh -c "TESTS_SUITES='$TESTS_SUITES' TESTS_CASES='$TESTS_CASES' TESTS_VERBOSITY=4 rr record -n $EXCHANGE_TESTS_BINARY"
