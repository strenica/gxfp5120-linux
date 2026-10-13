#!/bin/sh
# Integrate the gxfp5120 driver into a libfprint source tree, idempotently.
# usage: apply.sh /path/to/libfprint
set -eu

TREE=${1:?usage: apply.sh /path/to/libfprint}
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/gxfp5120
DEST=$TREE/libfprint/drivers/gxfp5120

test -f "$TREE/meson.build" || { echo "not a libfprint tree: $TREE" >&2; exit 1; }

mkdir -p "$DEST/fastbrief"
cp -f "$SRC"/*.c "$SRC"/*.h "$SRC"/cc90.hex "$DEST"/
cp -f "$SRC"/fastbrief/* "$DEST/fastbrief/"

python3 "$HERE/patch_meson.py" "$TREE"
echo "driver integrated into $TREE"
