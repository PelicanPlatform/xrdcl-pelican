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

echo "Tearing down $TEST_NAME"

if [ ! -f "$BINARY_DIR/tests/$TEST_NAME/setup.sh" ]; then
  echo "Test environment file $BINARY_DIR/tests/$TEST_NAME/setup.sh does not exist - cannot run test"
  exit 1
fi
source "$BINARY_DIR/tests/$TEST_NAME/setup.sh"


if [ -z "$PELICAN_PID" ]; then
  echo "\$PELICAN_PID environment variable is not set; cannot tear down process"
  exit 1
fi

kill "$PELICAN_PID"

SHUTDOWN_MSG=$(grep -a "Pelican is safely exited" "$BINARY_DIR/tests/$TEST_NAME/pelican.log")
IDX=0
while [ -z "$SHUTDOWN_MSG" ]; do
  sleep 1
  SHUTDOWN_MSG=$(grep -a "Pelican is safely exited" "$BINARY_DIR/tests/$TEST_NAME/pelican.log")
  IDX=$(($IDX+1))
  if [ $IDX -gt 1 ]; then
    echo "Waiting for pelican at PID $PELICAN_PID to shut down ($IDX seconds so far)..."
    echo $SHUTDOWN_MSG
  fi
  if [ $IDX -eq 10 ]; then
    echo "Shutdown of pelican at PID $PELICAN_PID failed."
    exit 1
  fi
done