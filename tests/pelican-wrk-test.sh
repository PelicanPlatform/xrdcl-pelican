#!/bin/sh

TEST_NAME=$1

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$BINARY_DIR" ]; then
  echo "$BINARY_DIR is not a directory; cannot run test"
  exit 1
fi

echo "Running $TEST_NAME - concurrent downloads"

echo > "$BINARY_DIR/tests/$TEST_NAME/client.log"

if [ ! -f "$BINARY_DIR/tests/$TEST_NAME/setup.sh" ]; then
  echo "Test environment file $BINARY_DIR/tests/$TEST_NAME/setup.sh does not exist - cannot run test"
  exit 1
fi
source "$BINARY_DIR/tests/$TEST_NAME/setup.sh"

set -x
"$WRK_BIN" -c 10 -d 10 -no-vr "$CACHE_URL/test-public/hello_world.txt"
"$WRK_BIN" -c 200 -d 10 -no-vr -T 10000 -f "$PLAYBACK_FILE"
"$WRK_BIN" -c 200 -d 10 -no-vr -T 10000 -f "$PLAYBACK_FILE"
"$WRK_BIN" -c 200 -d 10 -no-vr -T 10000 -f "$ORIGIN_PLAYBACK_FILE"

#"$WRK_BIN" -c 10 -d 10 -no-vr "$CACHE_URL/test-public/hello_world-1.txt"

#"$WRK_BIN" -c 200 -d 10 -no-vr "$CACHE_URL/test-public/hello_world-2.txt"
#"$WRK_BIN" -c 200 -d 10 -no-vr "$CACHE_URL/test-public/hello_world.txt"

