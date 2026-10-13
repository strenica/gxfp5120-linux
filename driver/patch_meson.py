#!/usr/bin/env python3
"""Idempotently integrate the gxfp5120 driver into a libfprint source tree.

usage: patch_meson.py /path/to/libfprint
"""
import sys
from pathlib import Path

tree = Path(sys.argv[1])
assert (tree / "meson.build").exists(), f"not a libfprint tree: {tree}"

DRIVER_SOURCES = """    'gxfp5120' : files(
        'drivers/gxfp5120/gxfp5120.c',
        'drivers/gxfp5120/gxfp5120-ec.c',
        'drivers/gxfp5120/gxfp5120-tls.c',
        'drivers/gxfp5120/gxfp5120-image.c',
        'drivers/gxfp5120/gxfp5120-proto.c',
        'drivers/gxfp5120/goodix_sift.c',
        'drivers/gxfp5120/fastbrief/sigfm.c',
    ),

"""

DRIVERS_INFO = "    'gxfp5120': { 'spi': true, 'helper': ['udev', 'openssl'], 'optional': true },\n"

# 1. libfprint/meson.build — driver source list
p = tree / "libfprint" / "meson.build"
src = p.read_text()
if "gxfp5120" not in src:
    anchor = "driver_sources = {\n"
    assert anchor in src, "driver_sources anchor missing"
    src = src.replace(anchor, anchor + DRIVER_SOURCES, 1)
    p.write_text(src)
    print(f"patched {p}")
else:
    print(f"{p} already patched")

# 2. top-level meson.build — driver registration
p = tree / "meson.build"
src = p.read_text()
if "'gxfp5120'" not in src:
    anchor = "drivers_info = {\n"
    assert anchor in src, "drivers_info anchor missing"
    src = src.replace(anchor, anchor + DRIVERS_INFO, 1)
    p.write_text(src)
    print(f"patched {p}")
else:
    # upgrade an earlier registration in place
    want = DRIVERS_INFO.strip()
    out = []
    changed = False
    for line in src.splitlines(keepends=True):
        if "'gxfp5120'" in line and line.strip() != want:
            out.append(DRIVERS_INFO)
            changed = True
        else:
            out.append(line)
    if changed:
        p.write_text("".join(out))
        print(f"updated {p}")
    else:
        print(f"{p} already patched")

# 3. tests/meson.build — v1.94.100 dict iteration needs two loop variables
p = tree / "tests" / "meson.build"
src = p.read_text()
old = "foreach driver_test: drivers_tests"
new = "foreach driver_test, driver_test_info : drivers_tests"
if old in src:
    src = src.replace(old, new, 1)
    p.write_text(src)
    print(f"patched {p}")
else:
    print(f"{p} already patched")
