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

PUBLIC_HASH=$(sha256sum "$PUBLIC_TEST_FILE" | awk '{print $1;}')
echo "Reference file content hash: $PUBLIC_HASH"

# Under valgrind, the initial metadata lookup done in parallel often times out.  Do it once to populate the federation metadata cache
curl --cacert "$X509_CA_FILE" -I -v -L --fail "$FEDERATION_URL/test-public/hello_world-1.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log" > "$BINARY_DIR/tests/$TEST_NAME/client-primer.out"

IDX=1
while [ $IDX -le 5 ]; do

  rm -f "$BINARY_DIR/tests/$TEST_NAME/client-$IDX.out"
  curl --cacert "$X509_CA_FILE" -v -L --fail "$FEDERATION_URL/test-public/hello_world-$IDX.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log" > "$BINARY_DIR/tests/$TEST_NAME/client-$IDX.out" &
  export CURL_${IDX}_PID=$!

  IDX=$(($IDX+1))
done

IDX=1
while [ $IDX -le 5 ]; do

  CURL_NAME="CURL_${IDX}_PID"
  eval CURL_NAME='\$CURL_${IDX}_PID'
  eval CURL_PID=$CURL_NAME
  wait $CURL_PID
  CURL_EXIT=$?

  if [ $CURL_EXIT -ne 0 ]; then
    echo "Download of hello-world-$IDX text failed"
    exit 1
  fi

  IDX_HASH=$(sha256sum "$BINARY_DIR/tests/$TEST_NAME/client-$IDX.out" | awk '{print $1;}')

  if [ "$IDX_HASH" != "$PUBLIC_HASH" ]; then
    echo "Downloaded hello-world text is incorrect for process $IDX: (got $IDX_HASH; expected $PUBLIC_HASH)"
    exit 1
  fi

  IDX=$(($IDX+1))
done

