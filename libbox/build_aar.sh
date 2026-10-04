#!/bin/sh
# Build libbox.aar with gomobile. Run in CI (or locally with Go + Android SDK).
# Output: ../app/libs/libbox.aar
set -e
cd "$(dirname "$0")"

if ! command -v gomobile >/dev/null 2>&1; then
  echo "installing gomobile..."
  go install golang.org/x/mobile/cmd/gomobile@latest
  export PATH="$PATH:$(go env GOPATH)/bin"
fi

gomobile init 2>/dev/null || true

mkdir -p ../app/libs
gomobile bind \
  -o ../app/libs/libbox.aar \
  -target android/arm64,android/armv7 \
  -javapkg box \
  .

echo "built ../app/libs/libbox.aar"
