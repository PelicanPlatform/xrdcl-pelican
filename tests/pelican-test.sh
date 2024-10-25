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

echo "Running $TEST_NAME - simple download"

if [ ! -f "$BINARY_DIR/tests/$TEST_NAME/setup.sh" ]; then
  echo "Test environment file $BINARY_DIR/tests/$TEST_NAME/setup.sh does not exist - cannot run test"
  exit 1
fi
source "$BINARY_DIR/tests/$TEST_NAME/setup.sh"

CONTENTS=$(curl --cacert "$X509_CA_FILE" -v -L --fail -H "@$HEADER_FILE" "$FEDERATION_URL/test/hello_world.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
  echo "Download of hello-world text failed"
  exit 1
fi

if [ "$CONTENTS" != "Hello, World" ]; then
  echo "Downloaded hello-world text is incorrect: $CONTENTS"
  exit 1
fi

echo "Running $TEST_NAME - missing authz"

HTTP_CODE=$(curl --output /dev/null --cacert "$X509_CA_FILE" -v -L --write-out '%{http_code}' -H "Authorization: Bearer missing" "$FEDERATION_URL/test/hello_world.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 403 ]; then
  echo "Expected HTTP code is 403; actual was $HTTP_CODE"
  exit 1
fi

echo "Running $TEST_NAME - missing object"

HTTP_CODE=$(curl --output /dev/null --cacert "$X509_CA_FILE" -v -L --write-out '%{http_code}' -H "@$HEADER_FILE" "$FEDERATION_URL/test/missin.txt" 2>> "$BINARY_DIR/tests/$TEST_NAME/client.log")
if [ "$HTTP_CODE" -ne 404 ]; then
  echo "Expected HTTP code is 404; actual was $HTTP_CODE"
  exit 1
fi

