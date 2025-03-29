#!/bin/sh

TEST_NAME=$1

VALGRIND=0
if [ "$2" = "valgrind" ]; then
  VALGRIND=1
fi

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$BINARY_DIR" ]; then
  echo "$BINARY_DIR is not a directory; cannot run test"
  exit 1
fi
if [ -z "$SOURCE_DIR" ]; then
  echo "\$SOURCE_DIR environment variable is not set; cannot run test"
  exit 1
fi
if [ ! -d "$SOURCE_DIR" ]; then
  echo "\$SOURCE_DIR environment variable is not set; cannot run test"
  exit 1
fi

echo "Setting up Pelican federation for $TEST_NAME test"

if [ -z "$PELICAN_BIN" ]; then
  echo "pelican binary not found; cannot run unit test"
  exit 1
fi

mkdir -p "$BINARY_DIR/tests/$TEST_NAME"
RUNDIR=$(mktemp -d -p "$BINARY_DIR/tests/$TEST_NAME" test_run.XXXXXXXX)
chmod 0755 $RUNDIR

if [ ! -d "$RUNDIR" ]; then
  echo "Failed to create test run directory; cannot run pelican test"
  exit 1
fi

# We create a link to the `client.plugins.d` directory at a fixed, known
# location because it must be provided to the gtest executable via an
# environment variable specified in the CMakeLists.txt (which is not
# dynamically generated).
if [ -L "$BINARY_DIR/tests/$TEST_NAME/client.plugins.d" ]; then
  rm "$BINARY_DIR/tests/$TEST_NAME/client.plugins.d" || exit 1
fi

if ! ln -sf "$RUNDIR/client.plugins.d" "$BINARY_DIR/tests/$TEST_NAME/client.plugins.d"; then
  echo "Failed to create client plugins link; cannot run test"
  exit 1
fi

echo "Using $RUNDIR as the test run's home directory."
cd "$RUNDIR"

# Create the plugin configuration to utilize the freshly-built plugin
export XRD_PLUGINCONFDIR="$RUNDIR/client.plugins.d"
mkdir -p "$XRD_PLUGINCONFDIR"

PLUGIN_SUFFIX=so
if [ $(uname) = "Darwin" ]; then
  PLUGIN_SUFFIX=dylib
fi

cat > "$XRD_PLUGINCONFDIR/pelican-plugin.conf" <<EOF

url = pelican://*;https://*
lib = $BINARY_DIR/libXrdClPelican.$PLUGIN_SUFFIX
enable = true

EOF

# Create pelican configuration and runtime directory structure
export PELICAN_CONFIGDIR="$RUNDIR/pelican-config"
mkdir -p "$PELICAN_CONFIGDIR"
PELICAN_RUNDIR="$RUNDIR/pelican-run"
mkdir -p "$PELICAN_RUNDIR"
PELICAN_EXPORTDIR="$RUNDIR/pelican-export"
mkdir -p "$PELICAN_EXPORTDIR"
PELICAN_PUBLIC_EXPORTDIR="$RUNDIR/pelican-export"
mkdir -p "$PELICAN_PUBLIC_EXPORTDIR"

# XRootD has strict length limits on the admin path location.
# Therefore, we also create a directory in /tmp.
XROOTD_RUNDIR=$(mktemp -d -p /tmp xrootd_test.XXXXXXXX)
chmod 0755 "$XROOTD_RUNDIR"

export PELICAN_CONFIG="$PELICAN_CONFIGDIR/pelican.yaml"
cat > "$PELICAN_CONFIG" <<EOF

Logging:
  Cache:
    Pss: debug
    Pfc: debug
    Scitokens: debug
    Http: debug
    Xrd: trace
    Xrootd: trace
  Origin:
    Http: debug

Origin:
  Exports:
  - StoragePrefix: $PELICAN_EXPORTDIR
    FederationPrefix: /test
    Capabilities: ["Reads", "Writes", "Listings"]
  - StoragePrefix: $PELICAN_PUBLIC_EXPORTDIR
    FederationPrefix: /test-public
    Capabilities: ["Reads", "Writes", "Listings", "PublicReads"]
  RunLocation: $XROOTD_RUNDIR/xrootd/origin
  DbLocation: $PELICAN_RUNDIR/origin.sqlite
  GeoIpLocation: $PELICAN_RUNDIR/maxmind/GeoLite2-City.mmdb
  EnableVoms: false
  SelfTest: false
  DirectorTest: false
  Port: 0

Cache:
  RunLocation: $XROOTD_RUNDIR/xrootd/cache
  DataLocations: ["$PELICAN_RUNDIR/cache/data"]
  MetaLocations: ["$PELICAN_RUNDIR/cache/meta"]
  LocalRoot: $PELICAN_RUNDIR/cache
  SelfTest: false
  Port: 0

Director:
  EnableStat: false

Registry:
  DbLocation: $PELICAN_RUNDIR/registry.sqlite

Lotman:
  DbLocation: $PELICAN_RUNDIR/lotman

Monitoring:
  DataLocation: $PELICAN_RUNDIR/monitoring

Xrootd:
  SummaryMonitoringHost: ""
  DetailedMonitoringHost: ""
  MaxStartupWait: 30s
  ConfigFile: $PELICAN_RUNDIR/xrootd-extra.conf

Server:
  EnableUI: false
  WebPort: 0

EOF

cat > "$PELICAN_RUNDIR/xrootd-extra.conf" << EOF

http.exthandler xrdtpc libXrdHttpTPC.so

EOF

# Can be fake values but must be non-empty for startup.
echo "test-client" > "$PELICAN_CONFIGDIR/oidc-client-id"
echo "test-secret" > "$PELICAN_CONFIGDIR/oidc-client-secret"


# Export some data through the origin
echo "Hello, World" > "$PELICAN_EXPORTDIR/hello_world.txt"
echo "Hello, World" > "$PELICAN_PUBLIC_EXPORTDIR/hello_world.txt"

mkdir "$PELICAN_PUBLIC_EXPORTDIR/subdir"
touch "$PELICAN_PUBLIC_EXPORTDIR/subdir/test1"
echo 'Hello, world!' > "$PELICAN_PUBLIC_EXPORTDIR/subdir/test2"
mkdir "$PELICAN_PUBLIC_EXPORTDIR/subdir/test3"

dd if=/dev/urandom of="$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt" count=$((4 * 1024)) bs=1024
IDX=0
while [ $IDX -ne 100 ]; do
  IDX=$(($IDX+1))
  ln -s "$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt" "$PELICAN_PUBLIC_EXPORTDIR/hello_world-$IDX.txt"
done

####################################################
# Configure xrootd wrapper to have custom env vars #
####################################################
# Until Pelican has been updated to use XRD_PELICANCACHETOKENLOCATION, we inject
# it via a wrapper script
cat > "$RUNDIR/cache_token" << EOF
# This is a token file
# We set the token to 'REDACTED' to allow comparison before and after xrootd learns
# how to redact the 'access_token' parameter

  REDACTED  

EOF

XROOTD_BIN="$XROOTD_BINDIR/xrootd"
if [ "$VALGRIND" -eq 1 ]; then
  # Note we escape the quotes here -- when the contents of the
  # variable are written to the generated shell script, we want the
  # non-valgrind case to result in an empty string in the file
  VALGRIND_BIN=\"$(command -v valgrind)\"
fi

BINDIR="$RUNDIR/bin"
mkdir -p -- "$BINDIR"
cat > "$BINDIR/xrootd" << EOF
#!/bin/sh
export XRD_PELICANCACHETOKENLOCATION="$RUNDIR/cache_token"
export LD_LIBRARY_PATH="${XROOTD_LIBDIR}:$LD_LIBRARY_PATH"
set -x
exec $VALGRIND_BIN "$XROOTD_BIN" "\$@"
EOF
chmod +x "$BINDIR/xrootd"
export PATH="$BINDIR:$PATH"

##################################################
# Launch pelican & accompanying XRootD services. #
##################################################
"$PELICAN_BIN" --config "$PELICAN_CONFIG" serve -d --module origin,registry,director,cache 0<&- >"$BINARY_DIR/tests/$TEST_NAME/pelican.log" 2>&1 &
PELICAN_PID=$!
echo "Pelican PID: $PELICAN_PID"

echo "Pelican logs are available at $BINARY_DIR/tests/$TEST_NAME/pelican.log"

# Build environment file for remainder of tests
CACHE_URL=$(grep -a "Resetting Cache.Url to" "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
IDX=0
while [ -z "$CACHE_URL" ]; do
  sleep 1
  CACHE_URL=$(grep -a "Resetting Cache.Url to" "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
  IDX=$(($IDX+1))
  if [ $IDX -gt 1 ]; then
    echo "Waiting for cache to start ($IDX seconds so far) ..."
  fi
  if ! kill -0 "$PELICAN_PID" 2>/dev/null; then
    echo "Pelican process crashed - failing"
    exit 1
  fi
  if [ $IDX -eq 50 ]; then
    cat "$BINARY_DIR/tests/$TEST_NAME/pelican.log"
    echo "Cache failed to start - failing"
    exit 1
  fi
done
echo "Cache started at $CACHE_URL"

ORIGIN_URL=$(grep -a "Resetting Origin.Url to" "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
IDX=0
while [ -z "$ORIGIN_URL" ]; do
  sleep 1
  ORIGIN_URL=$(grep -a "Resetting Origin.Url to" "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
  IDX=$(($IDX+1))
  if [ $IDX -gt 1 ]; then
    echo "Waiting for cache to start ($IDX seconds so far) ..."
  fi
  if [ $IDX -eq 50 ]; then
    echo "Origin failed to start - failing"
    exit 1
  fi
done
echo "Origin started at $ORIGIN_URL"

WEB_URL=$(grep -a 'updated external web URL to' "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
IDX=0
while [ -z "$WEB_URL" ]; do
  sleep 1
  WEB_URL=$(grep -a 'updated external web URL to' "$BINARY_DIR/tests/$TEST_NAME/pelican.log" | awk '{print $NF}' | tr -d '"')
  IDX=$(($IDX+1))
  if [ $IDX -ge 1 ]; then
    echo "Waiting for web URL to start ($IDX seconds so far) ..."
  fi
  if [ $IDX -eq 10 ]; then
    echo "Web server failed to start - failing"
    exit 1
  fi
done
echo "Web URL available at $WEB_URL"

touch "$RUNDIR/url_playback_list.txt"
IDX=0
while [ $IDX -ne 100 ]; do
  IDX=$(($IDX+1))
  echo "$CACHE_URL/test-public/hello_world-$IDX.txt" >> "$RUNDIR/url_playback_list.txt"
done

touch "$RUNDIR/origin_playback_list.txt"
IDX=0
while [ $IDX -ne 100 ]; do
  IDX=$(($IDX+1))
  echo "$ORIGIN_URL/test-public/hello_world-$IDX.txt" >> "$RUNDIR/origin_playback_list.txt"
done

if ! "$PELICAN_BIN" origin token create --issuer "$WEB_URL" --audience https://wlcg.cern.ch/jwt/v1/any --subject test --profile wlcg --scope storage.read:/ > "$RUNDIR/token"; then
  echo "Failed to generate read token"
  exit 1
fi
echo "Sample read token available at $RUNDIR/token"

if ! "$PELICAN_BIN" origin token create --issuer "$WEB_URL" --audience "https://wlcg.cern.ch/jwt/v1/any" --subject test --profile wlcg --scope storage.modify:/ > "$RUNDIR/write.token"; then
  echo "Failed to generate write token"
  exit 1
fi
echo "Sample write token available at $RUNDIR/write.token"

printf "%s" "Authorization: Bearer " > "$RUNDIR/authz_header"
cat "$RUNDIR/token" >> "$RUNDIR/authz_header"

cat > "$BINARY_DIR/tests/$TEST_NAME/setup.sh" <<EOF
PELICAN_BIN=$PELICAN_BIN
PELICAN_PID=$PELICAN_PID
ORIGIN_URL=$ORIGIN_URL
CACHE_URL=$CACHE_URL
FEDERATION_URL=$WEB_URL
BEARER_TOKEN_FILE=$RUNDIR/token
HEADER_FILE=$RUNDIR/authz_header
X509_CA_FILE=$RUNDIR/pelican-config/certificates/tlsca.pem
PUBLIC_TEST_FILE=$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt
PLAYBACK_FILE=$RUNDIR/url_playback_list.txt
ORIGIN_PLAYBACK_FILE=$RUNDIR/origin_playback_list.txt
WRITE_TOKEN=$RUNDIR/write.token
READ_TOKEN=$RUNDIR/token
EOF

echo "Test environment written to $BINARY_DIR/tests/$TEST_NAME/setup.sh"
