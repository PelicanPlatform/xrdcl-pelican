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

PELICAN_BIN="$(command -v pelican)"

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

url = pelican://*
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

if [ "$VALGRIND" -eq 1 ]; then
  XROOTD_BIN=$(command -v xrootd)
  mkdir -p "$RUNDIR/xrootd-wrapper"
  cat > "$RUNDIR/xrootd-wrapper/xrootd" <<EOF
#!/bin/sh
exec valgrind "$XROOTD_BIN" "\$@"
EOF
  chmod +x "$RUNDIR/xrootd-wrapper/xrootd"
  export PATH=$RUNDIR/xrootd-wrapper:$PATH
fi

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

Server:
  EnableUI: false
  WebPort: 0

EOF

# Can be fake values but must be non-empty for startup.
echo "test-client" > "$PELICAN_CONFIGDIR/oidc-client-id"
echo "test-secret" > "$PELICAN_CONFIGDIR/oidc-client-secret"


# Export some data through the origin
echo "Hello, World" > "$PELICAN_EXPORTDIR/hello_world.txt"
echo "Hello, World" > "$PELICAN_PUBLIC_EXPORTDIR/hello_world.txt"

dd if=/dev/urandom of="$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt" count=$((4 * 1024)) bs=1024
IDX=0
while [ $IDX -ne 100 ]; do
  IDX=$(($IDX+1))
  ln -s "$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt" "$PELICAN_PUBLIC_EXPORTDIR/hello_world-$IDX.txt"
done

# Launch pelican & accompanying XRootD services.
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
  if [ $IDX -eq 50 ]; then
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

"$PELICAN_BIN" origin token create --issuer $WEB_URL --audience https://wlcg.cern.ch/jwt/v1/any --subject test --profile wlcg --scope storage.read:/ > "$RUNDIR/token"
echo "Sample token available at $RUNDIR/token"

printf "%s" "Authorization: Bearer " > "$RUNDIR/authz_header"
cat "$RUNDIR/token" >> "$RUNDIR/authz_header"

cat > "$BINARY_DIR/tests/$TEST_NAME/setup.sh" <<EOF
PELICAN_BIN=$PELICAN_BIN
PELICAN_PID=$PELICAN_PID
CACHE_URL=$CACHE_URL
FEDERATION_URL=$WEB_URL
BEARER_TOKEN_FILE=$RUNDIR/token
HEADER_FILE=$RUNDIR/authz_header
X509_CA_FILE=$RUNDIR/pelican-config/certificates/tlsca.pem
PUBLIC_TEST_FILE=$PELICAN_PUBLIC_EXPORTDIR/hello_world-1mb.txt
PLAYBACK_FILE=$RUNDIR/url_playback_list.txt
ORIGIN_PLAYBACK_FILE=$RUNDIR/origin_playback_list.txt
EOF

echo "Test environment written to $BINARY_DIR/tests/$TEST_NAME/setup.sh"
