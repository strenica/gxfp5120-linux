#!/usr/bin/env python3
"""decode-cap.py — turn a cc-cap capture into PNG images.

usage: decode-cap.py /tmp/cap1

Reads <pfx>.content.bin (7680 B: 8B header + 5120x12-bit pixels) and renders
<pfx>.png (raw) and <pfx>-eq.png (histogram-equalized), 80x64 display
(disp[y*80+x] = px[x*64+y]).
"""
import struct
import sys
import zlib
from pathlib import Path

PFX = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/cap1')
content = PFX.with_suffix('.content.bin').read_bytes()
assert len(content) >= 7688, f'content too short: {len(content)}'
px_data = content[8:8 + 7680]

px = []
for i in range(0, len(px_data) - 5, 6):
    c = px_data[i:i + 6]
    px += [((c[0] & 0xf) << 8) | c[1], (c[3] << 4) | (c[0] >> 4),
           ((c[5] & 0xf) << 8) | c[2], (c[4] << 4) | (c[5] >> 4)]
px = px[:5120]
print(f'{PFX.name}: {len(px)} px, min={min(px)} max={max(px)} spread={max(px)-min(px)}')

# display 80x64 (transposed wire), drop the first 3 marker rows
disp = [px[x * 64 + y] for y in range(3, 64) for x in range(80)]
W, H = 80, 61


def write_png(path, img, w, h, scale=5):
    raw = b''
    for y in range(h):
        row = bytearray()
        for x in range(w):
            row += bytes([img[y * w + x]] * scale)
        for _ in range(scale):
            raw += b'\x00' + bytes(row)

    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    Path(path).write_bytes(b'\x89PNG\r\n\x1a\n' +
                           chunk(b'IHDR', struct.pack('>IIBBBBB', w * scale, h * scale, 8, 0, 0, 0, 0)) +
                           chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


lo, hi = min(disp), max(disp)
raw8 = [max(0, min(255, (v - lo) * 255 // max(1, hi - lo))) for v in disp]
write_png(PFX.parent / (PFX.name + '.png'), raw8, W, H)

hist = [0] * 1024
for v in disp:
    hist[min(1023, (v - lo) * 1024 // max(1, hi - lo))] += 1
cdf, acc = [], 0
for i in range(1024):
    acc += hist[i]
    cdf.append(acc)
eq = [int(255 * cdf[min(1023, (v - lo) * 1024 // max(1, hi - lo))] / acc) for v in disp]
write_png(PFX.parent / (PFX.name + '-eq.png'), eq, W, H)
print(f'wrote {PFX.name}.png and {PFX.name}-eq.png')
